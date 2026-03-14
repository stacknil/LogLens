#pragma once

#include "detector.hpp"
#include "parser.hpp"

#include <filesystem>
#include <optional>

namespace loglens {

struct TimestampConfig {
    std::optional<int> assume_year;
};

struct AppConfig {
    DetectorConfig detector;
    std::optional<InputMode> input_mode;
    TimestampConfig timestamp;
};

AppConfig load_app_config(const std::filesystem::path& path);
DetectorConfig load_detector_config(const std::filesystem::path& path);

}  // namespace loglens
