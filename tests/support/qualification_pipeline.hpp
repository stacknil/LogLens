#pragma once

#include "qualification_cases.hpp"
#include "detector.hpp"
#include "parser.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace qualification {
inline void demand(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

struct Record {
    Case sample;
    int seconds;
    std::size_t line;
};

struct ExpectedFinding {
    loglens::FindingType type;
    std::string subject;
    std::size_t observed;
    std::vector<std::string> ids;
    int first;
    int last;
    std::vector<std::string> usernames;
};

inline void replace_all(std::string& value, const std::string& old, const std::string& replacement) {
    std::size_t offset = 0;
    while ((offset = value.find(old, offset)) != std::string::npos) {
        value.replace(offset, old.size(), replacement);
        offset += replacement.size();
    }
}

inline std::vector<Record> records(const std::uint8_t* data, std::size_t size) {
    static const auto families = cases();
    static constexpr int times[]{0, 1, 299, 300, 301, 599, 600, 601, 899, 900, 901, 1802};
    std::vector<Record> result;
    for (std::size_t offset = 1; offset + 3 < size && result.size() < 24; offset += 4) {
        auto sample = families[data[offset] % families.size()];
        const auto username = data[offset + 2] % 5 == 4 ? std::string("from")
            : "user-" + std::to_string(data[offset + 2] % 4);
        const auto address = data[offset + 3] % 2 == 0 ? "203.0.113.1" : "203.0.113.2";
        replace_all(sample.message, "user-a", username);
        replace_all(sample.message, "203.0.113.1", address);
        sample.username = username;
        if (!sample.address.empty()) {
            sample.address = address;
        }
        result.push_back({std::move(sample), times[data[offset + 1] % 12], result.size() + 1});
    }
    return result;
}

inline std::string render_input(const std::vector<Record>& input, bool journal) {
    std::ostringstream output;
    for (const auto& record : input) {
        const int minute = record.seconds / 60;
        const int second = record.seconds % 60;
        output << (journal ? "Tue 2026-03-10 09:" : "Mar 10 09:");
        if (minute < 10) { output << '0'; }
        output << minute << ':';
        if (second < 10) { output << '0'; }
        output << second << (journal ? " UTC " : " ") << "example-host "
               << record.sample.program << "[4200]: " << record.sample.message << '\n';
    }
    return output.str();
}

inline std::vector<ExpectedFinding> expected_findings(const std::vector<Record>& input) {
    std::vector<ExpectedFinding> expected;
    for (int rule = 0; rule < 3; ++rule) {
        const int window = rule == 0 ? 600 : rule == 1 ? 900 : 300;
        const std::size_t threshold = rule == 0 ? 5 : 3;
        const auto type = rule == 0 ? loglens::FindingType::BruteForce
            : rule == 1 ? loglens::FindingType::MultiUserProbing : loglens::FindingType::SudoBurst;
        std::map<std::string, std::vector<const Record*>> groups;
        for (const auto& record : input) {
            const auto& sample = record.sample;
            const bool eligible = rule == 0 ? sample.terminal : rule == 1 ? sample.attempt : sample.sudo;
            const auto& key = rule == 2 ? sample.username : sample.address;
            if (eligible && !key.empty()) { groups[key].push_back(&record); }
        }
        for (auto& [subject, group] : groups) {
            std::sort(group.begin(), group.end(), [](const auto* a, const auto* b) {
                return std::tie(a->seconds, a->line) < std::tie(b->seconds, b->line);
            });
            std::vector<std::vector<const Record*>> components;
            for (const auto* record : group) {
                if (components.empty() || record->seconds - components.back().back()->seconds > window) {
                    components.emplace_back();
                }
                components.back().push_back(record);
            }
            for (const auto& component : components) {
                // Enumerate all legal intervals, independently of the production sliding window.
                std::vector<const Record*> best;
                std::set<std::string> best_users;
                std::size_t best_score = 0;
                for (std::size_t end = 0; end < component.size(); ++end) {
                    for (std::size_t begin = 0; begin <= end; ++begin) {
                        if (component[end]->seconds - component[begin]->seconds > window) { continue; }
                        std::set<std::string> users;
                        for (std::size_t j = begin; j <= end; ++j) {
                            if (!component[j]->sample.username.empty()) { users.insert(component[j]->sample.username); }
                        }
                        const std::size_t count = end - begin + 1;
                        const auto score = rule == 1 ? users.size() : count;
                        if (score > best_score || (score == best_score && count > best.size())) {
                            best.assign(component.begin() + static_cast<std::ptrdiff_t>(begin),
                                        component.begin() + static_cast<std::ptrdiff_t>(end + 1));
                            best_score = score;
                            best_users = std::move(users);
                        }
                    }
                }
                if (best_score >= threshold) {
                    ExpectedFinding finding{type, subject, best_score, {}, best.front()->seconds, best.back()->seconds, {}};
                    for (const auto* record : best) { finding.ids.push_back("line:" + std::to_string(record->line)); }
                    if (rule == 1) { finding.usernames.assign(best_users.begin(), best_users.end()); }
                    expected.push_back(std::move(finding));
                }
            }
        }
    }
    return expected;
}

inline void check_findings(const std::vector<loglens::Finding>& actual,
                           const std::vector<ExpectedFinding>& expected) {
    demand(actual.size() == expected.size(), "detector finding count");
    std::set<std::string> identities;
    std::set<std::size_t> consumed;
    std::map<std::pair<loglens::FindingType, std::string>, std::size_t> episodes;
    for (const auto& finding : actual) {
        const auto match = std::find_if(expected.begin(), expected.end(), [&](const auto& item) {
            return item.type == finding.type && item.subject == finding.subject && item.ids == finding.evidence_event_ids;
        });
        demand(match != expected.end(), "detector evidence references");
        demand(consumed.insert(static_cast<std::size_t>(match - expected.begin())).second,
               "detector duplicate expected finding");
        const bool sudo_rule = finding.type == loglens::FindingType::SudoBurst;
        const auto rule = sudo_rule ? "sudo_burst"
            : finding.type == loglens::FindingType::BruteForce ? "brute_force" : "multi_user_probing";
        demand(finding.rule_id == rule && finding.threshold == (finding.type == loglens::FindingType::BruteForce ? 5U : 3U)
               && finding.subject_kind == (sudo_rule ? "username" : "source_ip")
               && finding.grouping_key == finding.subject_kind, "detector rule metadata");
        demand(finding.observed_count == match->observed && finding.event_count == match->ids.size(), "detector threshold/count");
        demand(finding.first_seen.time_since_epoch().count() == 1773133200 + match->first
               && finding.last_seen.time_since_epoch().count() == 1773133200 + match->last,
               "detector selected time window");
        demand(finding.usernames == match->usernames, "detector username set");
        demand(!finding.finding_id.empty() && identities.insert(finding.finding_id).second, "detector duplicate identity");
        demand(finding.episode_index == ++episodes[{finding.type, finding.subject}], "detector episode numbering");
    }
}

inline void check_parsed(const loglens::ParseReport& parsed, const std::vector<Record>& input) {
    demand(parsed.warnings.empty() && parsed.events.size() == input.size(), "generated supported evidence lost");
    for (std::size_t i = 0; i < input.size(); ++i) {
        const auto& event = parsed.events[i];
        const auto& record = input[i];
        demand(event.event_type == record.sample.type && event.username == record.sample.username
               && event.source_ip == record.sample.address && event.line_number == record.line
               && event.hostname == "example-host" && event.program == record.sample.program
               && event.pid == 4200 && event.message == record.sample.message
               && event.timestamp.time_since_epoch().count() == 1773133200 + record.seconds,
               "generated normalized fields");
    }
}

inline void check_pipeline(const std::uint8_t* data, std::size_t size) {
    const auto input = records(data, size);
    const bool journal = size != 0 && (data[0] & 1) != 0;
    const loglens::AuthLogParser parser({journal ? loglens::InputMode::JournalctlShortFull
                                                : loglens::InputMode::SyslogLegacy, 2026});
    std::istringstream stream(render_input(input, journal));
    const auto parsed = parser.parse_stream(stream);
    check_parsed(parsed, input);
    check_findings(loglens::Detector{}.analyze(parsed.events), expected_findings(input));
}
} // namespace qualification
