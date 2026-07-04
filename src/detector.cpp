#include "detector.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace loglens {
namespace {

using SignalGroup = std::unordered_map<std::string, std::vector<const AuthSignal*>>;

struct CountWindowSelection {
    std::size_t start = 0;
    std::size_t end = 0;
    std::size_t count = 0;
    bool matched = false;
};

struct MultiUserWindowSelection {
    std::size_t start = 0;
    std::size_t end = 0;
    std::size_t event_count = 0;
    std::size_t distinct_username_count = 0;
    std::vector<std::string> usernames;
    bool matched = false;
};

std::string finding_rule_id_for_identity(const Finding& finding) {
    if (!finding.rule_id.empty()) {
        return finding.rule_id;
    }
    return to_string(finding.type);
}

std::string finding_subject_kind_for_identity(const Finding& finding) {
    if (!finding.subject_kind.empty()) {
        return finding.subject_kind;
    }
    return finding.grouping_key;
}

bool finding_sort_less(const Finding& left, const Finding& right) {
    if (left.type != right.type) {
        return to_string(left.type) < to_string(right.type);
    }
    if (left.subject_kind != right.subject_kind) {
        return left.subject_kind < right.subject_kind;
    }
    if (left.subject != right.subject) {
        return left.subject < right.subject;
    }
    if (left.first_seen != right.first_seen) {
        return left.first_seen < right.first_seen;
    }
    if (left.last_seen != right.last_seen) {
        return left.last_seen < right.last_seen;
    }
    return left.evidence_event_ids < right.evidence_event_ids;
}

std::string finding_episode_key(const Finding& finding) {
    return finding_rule_id_for_identity(finding)
        + '\x1f' + finding_subject_kind_for_identity(finding)
        + '\x1f' + finding.subject;
}

void hash_append(std::uint64_t& hash, std::string_view value) {
    constexpr std::uint64_t fnv_prime = 1099511628211ULL;
    for (const unsigned char ch : value) {
        hash ^= ch;
        hash *= fnv_prime;
    }
    hash ^= 0xffU;
    hash *= fnv_prime;
}

std::string hex64(std::uint64_t value) {
    std::ostringstream output;
    output << std::hex << std::setfill('0') << std::setw(16) << value;
    return output.str();
}

std::vector<const AuthSignal*> sort_signals_by_time(const std::vector<const AuthSignal*>& signals) {
    auto sorted = signals;
    std::sort(sorted.begin(), sorted.end(), [](const AuthSignal* left, const AuthSignal* right) {
        if (left->timestamp != right->timestamp) {
            return left->timestamp < right->timestamp;
        }
        return left->line_number < right->line_number;
    });
    return sorted;
}

std::vector<std::pair<std::size_t, std::size_t>> activity_segments(const std::vector<const AuthSignal*>& ordered,
                                                                   std::chrono::minutes window) {
    std::vector<std::pair<std::size_t, std::size_t>> segments;
    if (ordered.empty()) {
        return segments;
    }

    std::size_t segment_start = 0;
    for (std::size_t index = 1; index < ordered.size(); ++index) {
        if (ordered[index]->timestamp - ordered[index - 1]->timestamp > window) {
            segments.emplace_back(segment_start, index - 1);
            segment_start = index;
        }
    }

    segments.emplace_back(segment_start, ordered.size() - 1);
    return segments;
}

CountWindowSelection best_count_window(const std::vector<const AuthSignal*>& ordered,
                                       std::size_t segment_start,
                                       std::size_t segment_end,
                                       std::chrono::minutes window) {
    CountWindowSelection selection;
    std::size_t start = segment_start;

    for (std::size_t end = segment_start; end <= segment_end; ++end) {
        while (start < end && ordered[end]->timestamp - ordered[start]->timestamp > window) {
            ++start;
        }

        const auto count = end - start + 1;
        if (!selection.matched || count > selection.count) {
            selection.start = start;
            selection.end = end;
            selection.count = count;
            selection.matched = true;
        }
    }

    return selection;
}

MultiUserWindowSelection best_multi_user_window(const std::vector<const AuthSignal*>& ordered,
                                                std::size_t segment_start,
                                                std::size_t segment_end,
                                                std::chrono::minutes window) {
    MultiUserWindowSelection selection;
    std::size_t start = segment_start;
    std::unordered_map<std::string, std::size_t> username_counts;

    for (std::size_t end = segment_start; end <= segment_end; ++end) {
        if (!ordered[end]->username.empty()) {
            ++username_counts[ordered[end]->username];
        }

        while (start < end && ordered[end]->timestamp - ordered[start]->timestamp > window) {
            if (!ordered[start]->username.empty()) {
                auto count_it = username_counts.find(ordered[start]->username);
                if (count_it != username_counts.end()) {
                    if (count_it->second == 1) {
                        username_counts.erase(count_it);
                    } else {
                        --count_it->second;
                    }
                }
            }
            ++start;
        }

        const auto distinct_username_count = username_counts.size();
        const auto event_count = end - start + 1;
        if (!selection.matched
            || distinct_username_count > selection.distinct_username_count
            || (distinct_username_count == selection.distinct_username_count
                && event_count > selection.event_count)) {
            selection.start = start;
            selection.end = end;
            selection.event_count = event_count;
            selection.distinct_username_count = distinct_username_count;
            selection.usernames.clear();
            selection.usernames.reserve(username_counts.size());
            for (const auto& [username, _] : username_counts) {
                selection.usernames.push_back(username);
            }
            std::sort(selection.usernames.begin(), selection.usernames.end());
            selection.matched = true;
        }
    }

    return selection;
}

std::vector<std::string> evidence_event_ids_for_window(const std::vector<const AuthSignal*>& ordered,
                                                       std::size_t start,
                                                       std::size_t end) {
    std::vector<std::string> event_ids;
    event_ids.reserve(end - start + 1);

    for (std::size_t index = start; index <= end; ++index) {
        if (!ordered[index]->event_id.empty()) {
            event_ids.push_back(ordered[index]->event_id);
        } else {
            event_ids.push_back("line:" + std::to_string(ordered[index]->line_number));
        }
    }

    return event_ids;
}

SignalGroup group_terminal_auth_failures_by_ip(const std::vector<AuthSignal>& signals) {
    SignalGroup grouped;
    for (const auto& signal : signals) {
        if (signal.source_ip.empty() || !signal.counts_as_terminal_auth_failure) {
            continue;
        }
        grouped[signal.source_ip].push_back(&signal);
    }
    return grouped;
}

SignalGroup group_attempt_evidence_by_ip(const std::vector<AuthSignal>& signals) {
    SignalGroup grouped;
    for (const auto& signal : signals) {
        if (signal.source_ip.empty() || !signal.counts_as_attempt_evidence) {
            continue;
        }
        grouped[signal.source_ip].push_back(&signal);
    }
    return grouped;
}

SignalGroup group_sudo_burst_evidence_by_user(const std::vector<AuthSignal>& signals) {
    SignalGroup grouped;
    for (const auto& signal : signals) {
        if (signal.username.empty() || !signal.counts_as_sudo_burst_evidence) {
            continue;
        }
        grouped[signal.username].push_back(&signal);
    }
    return grouped;
}

Finding make_brute_force_finding(const std::string& ip,
                                 std::size_t count,
                                 std::size_t threshold,
                                 std::chrono::sys_seconds first_seen,
                                 std::chrono::sys_seconds last_seen,
                                 std::chrono::minutes window,
                                 std::vector<std::string> evidence_event_ids) {
    Finding finding;
    finding.type = FindingType::BruteForce;
    finding.rule_id = to_string(finding.type);
    finding.subject_kind = "source_ip";
    finding.subject = ip;
    finding.grouping_key = "source_ip";
    finding.threshold = threshold;
    finding.observed_count = count;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.evidence_event_ids = std::move(evidence_event_ids);
    finding.verdict_boundary = default_verdict_boundary(finding.type);
    finding.summary = std::to_string(count) + " failed SSH attempts from " + ip
        + " within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

Finding make_multi_user_finding(const std::string& ip,
                                std::size_t count,
                                std::size_t threshold,
                                std::size_t distinct_username_count,
                                std::chrono::sys_seconds first_seen,
                                std::chrono::sys_seconds last_seen,
                                std::vector<std::string> usernames,
                                std::chrono::minutes window,
                                std::vector<std::string> evidence_event_ids) {
    Finding finding;
    finding.type = FindingType::MultiUserProbing;
    finding.rule_id = to_string(finding.type);
    finding.subject_kind = "source_ip";
    finding.subject = ip;
    finding.grouping_key = "source_ip";
    finding.threshold = threshold;
    finding.observed_count = distinct_username_count;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.evidence_event_ids = std::move(evidence_event_ids);
    finding.verdict_boundary = default_verdict_boundary(finding.type);
    finding.usernames = std::move(usernames);
    finding.summary = ip + " targeted " + std::to_string(finding.usernames.size())
        + " usernames within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

Finding make_sudo_finding(const std::string& user,
                          std::size_t count,
                          std::size_t threshold,
                          std::chrono::sys_seconds first_seen,
                          std::chrono::sys_seconds last_seen,
                          std::chrono::minutes window,
                          std::vector<std::string> evidence_event_ids) {
    Finding finding;
    finding.type = FindingType::SudoBurst;
    finding.rule_id = to_string(finding.type);
    finding.subject_kind = "username";
    finding.subject = user;
    finding.grouping_key = "username";
    finding.threshold = threshold;
    finding.observed_count = count;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.evidence_event_ids = std::move(evidence_event_ids);
    finding.verdict_boundary = default_verdict_boundary(finding.type);
    finding.summary = user + " ran " + std::to_string(count)
        + " sudo commands within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

std::vector<Finding> detect_brute_force(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_terminal_auth_failures_by_ip(signals);

    for (const auto& [ip, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        for (const auto& [segment_start, segment_end] : activity_segments(ordered, config.brute_force.window)) {
            const auto episode = best_count_window(
                ordered,
                segment_start,
                segment_end,
                config.brute_force.window);

            if (episode.matched && episode.count >= config.brute_force.threshold) {
                findings.push_back(make_brute_force_finding(
                    ip,
                    episode.count,
                    config.brute_force.threshold,
                    ordered[episode.start]->timestamp,
                    ordered[episode.end]->timestamp,
                    config.brute_force.window,
                    evidence_event_ids_for_window(ordered, episode.start, episode.end)));
            }
        }
    }

    return findings;
}

std::vector<Finding> detect_multi_user(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_attempt_evidence_by_ip(signals);

    for (const auto& [ip, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        for (const auto& [segment_start, segment_end] : activity_segments(ordered, config.multi_user_probing.window)) {
            auto episode = best_multi_user_window(
                ordered,
                segment_start,
                segment_end,
                config.multi_user_probing.window);

            if (episode.matched && episode.distinct_username_count >= config.multi_user_probing.threshold) {
                findings.push_back(make_multi_user_finding(
                    ip,
                    episode.event_count,
                    config.multi_user_probing.threshold,
                    episode.distinct_username_count,
                    ordered[episode.start]->timestamp,
                    ordered[episode.end]->timestamp,
                    std::move(episode.usernames),
                    config.multi_user_probing.window,
                    evidence_event_ids_for_window(ordered, episode.start, episode.end)));
            }
        }
    }

    return findings;
}

std::vector<Finding> detect_sudo_burst(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_sudo_burst_evidence_by_user(signals);

    for (const auto& [username, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        for (const auto& [segment_start, segment_end] : activity_segments(ordered, config.sudo_burst.window)) {
            const auto episode = best_count_window(
                ordered,
                segment_start,
                segment_end,
                config.sudo_burst.window);

            if (episode.matched && episode.count >= config.sudo_burst.threshold) {
                findings.push_back(make_sudo_finding(
                    username,
                    episode.count,
                    config.sudo_burst.threshold,
                    ordered[episode.start]->timestamp,
                    ordered[episode.end]->timestamp,
                    config.sudo_burst.window,
                    evidence_event_ids_for_window(ordered, episode.start, episode.end)));
            }
        }
    }

    return findings;
}

}  // namespace

std::string to_string(FindingType type) {
    switch (type) {
    case FindingType::BruteForce:
        return "brute_force";
    case FindingType::MultiUserProbing:
        return "multi_user_probing";
    case FindingType::SudoBurst:
    default:
        return "sudo_burst";
    }
}

std::string default_verdict_boundary(FindingType type) {
    switch (type) {
    case FindingType::BruteForce:
        return "triage_signal_not_compromise_or_attribution";
    case FindingType::MultiUserProbing:
        return "triage_signal_not_intent_or_attribution";
    case FindingType::SudoBurst:
    default:
        return "triage_signal_not_maliciousness_or_authorization";
    }
}

std::string build_finding_id(const Finding& finding) {
    constexpr std::uint64_t fnv_offset_basis = 14695981039346656037ULL;
    std::uint64_t hash = fnv_offset_basis;

    hash_append(hash, finding_rule_id_for_identity(finding));
    hash_append(hash, finding_subject_kind_for_identity(finding));
    hash_append(hash, finding.subject);
    hash_append(hash, format_timestamp(finding.first_seen));
    hash_append(hash, format_timestamp(finding.last_seen));
    hash_append(hash, std::to_string(finding.threshold));
    const auto observed_count = finding.observed_count == 0 ? finding.event_count : finding.observed_count;
    hash_append(hash, std::to_string(observed_count));
    hash_append(hash, std::to_string(finding.event_count));
    for (const auto& event_id : finding.evidence_event_ids) {
        hash_append(hash, event_id);
    }

    return "finding:" + finding_rule_id_for_identity(finding) + ":" + hex64(hash);
}

void assign_finding_episode_identity(std::vector<Finding>& findings) {
    std::unordered_map<std::string, std::size_t> episode_counts;

    for (auto& finding : findings) {
        auto& episode_count = episode_counts[finding_episode_key(finding)];
        ++episode_count;
        finding.episode_index = episode_count;
        finding.finding_id = build_finding_id(finding);
    }
}

Detector::Detector(DetectorConfig config)
    : config_(config) {}

std::vector<Finding> Detector::analyze(const std::vector<Event>& events) const {
    const auto auth_signals = build_auth_signals(events, config_.auth_signal_mappings);
    auto findings = detect_brute_force(auth_signals, config_);
    auto multi_user = detect_multi_user(auth_signals, config_);
    auto sudo = detect_sudo_burst(auth_signals, config_);

    findings.insert(findings.end(), multi_user.begin(), multi_user.end());
    findings.insert(findings.end(), sudo.begin(), sudo.end());

    std::sort(findings.begin(), findings.end(), finding_sort_less);
    assign_finding_episode_identity(findings);

    return findings;
}

const DetectorConfig& Detector::config() const {
    return config_;
}

}  // namespace loglens
