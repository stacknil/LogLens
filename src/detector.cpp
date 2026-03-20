#include "detector.hpp"

#include <algorithm>
#include <unordered_map>

namespace loglens {
namespace {

using SignalGroup = std::unordered_map<std::string, std::vector<const AuthSignal*>>;

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
                                 std::chrono::sys_seconds first_seen,
                                 std::chrono::sys_seconds last_seen,
                                 std::chrono::minutes window) {
    Finding finding;
    finding.type = FindingType::BruteForce;
    finding.subject_kind = "source_ip";
    finding.subject = ip;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.summary = std::to_string(count) + " failed SSH attempts from " + ip
        + " within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

Finding make_multi_user_finding(const std::string& ip,
                                std::size_t count,
                                std::chrono::sys_seconds first_seen,
                                std::chrono::sys_seconds last_seen,
                                std::vector<std::string> usernames,
                                std::chrono::minutes window) {
    Finding finding;
    finding.type = FindingType::MultiUserProbing;
    finding.subject_kind = "source_ip";
    finding.subject = ip;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.usernames = std::move(usernames);
    finding.summary = ip + " targeted " + std::to_string(finding.usernames.size())
        + " usernames within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

Finding make_sudo_finding(const std::string& user,
                          std::size_t count,
                          std::chrono::sys_seconds first_seen,
                          std::chrono::sys_seconds last_seen,
                          std::chrono::minutes window) {
    Finding finding;
    finding.type = FindingType::SudoBurst;
    finding.subject_kind = "username";
    finding.subject = user;
    finding.event_count = count;
    finding.first_seen = first_seen;
    finding.last_seen = last_seen;
    finding.summary = user + " ran " + std::to_string(count)
        + " sudo commands within " + std::to_string(window.count()) + " minutes.";
    return finding;
}

std::vector<Finding> detect_brute_force(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_terminal_auth_failures_by_ip(signals);

    for (const auto& [ip, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        std::size_t start = 0;
        std::size_t best_count = 0;
        std::size_t best_start = 0;
        std::size_t best_end = 0;

        for (std::size_t end = 0; end < ordered.size(); ++end) {
            while (start < end
                   && ordered[end]->timestamp - ordered[start]->timestamp > config.brute_force.window) {
                ++start;
            }

            const auto count = end - start + 1;
            if (count > best_count) {
                best_count = count;
                best_start = start;
                best_end = end;
            }
        }

        if (best_count >= config.brute_force.threshold) {
            findings.push_back(make_brute_force_finding(
                ip,
                best_count,
                ordered[best_start]->timestamp,
                ordered[best_end]->timestamp,
                config.brute_force.window));
        }
    }

    return findings;
}

std::vector<Finding> detect_multi_user(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_attempt_evidence_by_ip(signals);

    for (const auto& [ip, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        std::size_t start = 0;
        std::unordered_map<std::string, std::size_t> username_counts;
        std::size_t best_distinct = 0;
        std::size_t best_count = 0;
        std::size_t best_start = 0;
        std::size_t best_end = 0;
        std::vector<std::string> best_usernames;

        for (std::size_t end = 0; end < ordered.size(); ++end) {
            if (!ordered[end]->username.empty()) {
                ++username_counts[ordered[end]->username];
            }

            while (start < end
                   && ordered[end]->timestamp - ordered[start]->timestamp > config.multi_user_probing.window) {
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

            const auto distinct_count = username_counts.size();
            const auto event_count = end - start + 1;
            if (distinct_count > best_distinct
                || (distinct_count == best_distinct && event_count > best_count)) {
                best_distinct = distinct_count;
                best_count = event_count;
                best_start = start;
                best_end = end;
                best_usernames.clear();
                best_usernames.reserve(username_counts.size());
                for (const auto& [username, _] : username_counts) {
                    best_usernames.push_back(username);
                }
                std::sort(best_usernames.begin(), best_usernames.end());
            }
        }

        if (best_distinct >= config.multi_user_probing.threshold) {
            findings.push_back(make_multi_user_finding(
                ip,
                best_count,
                ordered[best_start]->timestamp,
                ordered[best_end]->timestamp,
                best_usernames,
                config.multi_user_probing.window));
        }
    }

    return findings;
}

std::vector<Finding> detect_sudo_burst(const std::vector<AuthSignal>& signals, const DetectorConfig& config) {
    std::vector<Finding> findings;
    const auto grouped = group_sudo_burst_evidence_by_user(signals);

    for (const auto& [username, group] : grouped) {
        const auto ordered = sort_signals_by_time(group);
        std::size_t start = 0;
        std::size_t best_count = 0;
        std::size_t best_start = 0;
        std::size_t best_end = 0;

        for (std::size_t end = 0; end < ordered.size(); ++end) {
            while (start < end
                   && ordered[end]->timestamp - ordered[start]->timestamp > config.sudo_burst.window) {
                ++start;
            }

            const auto count = end - start + 1;
            if (count > best_count) {
                best_count = count;
                best_start = start;
                best_end = end;
            }
        }

        if (best_count >= config.sudo_burst.threshold) {
            findings.push_back(make_sudo_finding(
                username,
                best_count,
                ordered[best_start]->timestamp,
                ordered[best_end]->timestamp,
                config.sudo_burst.window));
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

Detector::Detector(DetectorConfig config)
    : config_(config) {}

std::vector<Finding> Detector::analyze(const std::vector<Event>& events) const {
    const auto auth_signals = build_auth_signals(events, config_.auth_signal_mappings);
    auto findings = detect_brute_force(auth_signals, config_);
    auto multi_user = detect_multi_user(auth_signals, config_);
    auto sudo = detect_sudo_burst(auth_signals, config_);

    findings.insert(findings.end(), multi_user.begin(), multi_user.end());
    findings.insert(findings.end(), sudo.begin(), sudo.end());

    std::sort(findings.begin(), findings.end(), [](const Finding& left, const Finding& right) {
        if (left.type != right.type) {
            return to_string(left.type) < to_string(right.type);
        }
        if (left.subject != right.subject) {
            return left.subject < right.subject;
        }
        return left.first_seen < right.first_seen;
    });

    return findings;
}

const DetectorConfig& Detector::config() const {
    return config_;
}

}  // namespace loglens
