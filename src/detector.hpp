#pragma once

#include "event.hpp"
#include "signal.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace loglens {

enum class FindingType {
    BruteForce,
    MultiUserProbing,
    SudoBurst
};

struct RuleThreshold {
    std::size_t threshold = 0;
    std::chrono::minutes window{0};
};

struct DetectorConfig {
    RuleThreshold brute_force{5, std::chrono::minutes{10}};
    RuleThreshold multi_user_probing{3, std::chrono::minutes{15}};
    RuleThreshold sudo_burst{3, std::chrono::minutes{5}};
    AuthSignalConfig auth_signal_mappings{};
};

struct Finding {
    FindingType type = FindingType::BruteForce;
    std::string subject_kind;
    std::string subject;
    std::size_t event_count = 0;
    std::chrono::sys_seconds first_seen{};
    std::chrono::sys_seconds last_seen{};
    std::vector<std::string> usernames;
    std::string summary;
};

std::string to_string(FindingType type);

class Detector {
  public:
    explicit Detector(DetectorConfig config = {});

    std::vector<Finding> analyze(const std::vector<Event>& events) const;
    const DetectorConfig& config() const;

  private:
    DetectorConfig config_;
};

}  // namespace loglens
