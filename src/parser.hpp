#pragma once

#include "event.hpp"

#include <filesystem>
#include <istream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace loglens {

enum class InputMode {
    SyslogLegacy,
    JournalctlShortFull
};

std::string to_string(InputMode mode);
std::optional<InputMode> parse_input_mode(std::string_view value);

struct ParserConfig {
    InputMode input_mode = InputMode::SyslogLegacy;
    std::optional<int> assumed_year;
};

struct ParseWarning {
    std::size_t line_number = 0;
    std::string reason;
};

struct ParseMetadata {
    InputMode input_mode = InputMode::SyslogLegacy;
    std::optional<int> assume_year;
    bool timezone_present = false;
};

struct UnknownPatternCount {
    std::string pattern;
    std::size_t count = 0;
};

struct ParserQualityMetrics {
    std::size_t total_lines = 0;
    std::size_t parsed_lines = 0;
    std::size_t unparsed_lines = 0;
    double parse_success_rate = 0.0;
    std::vector<UnknownPatternCount> top_unknown_patterns;
};

struct ParseReport {
    std::vector<Event> events;
    std::vector<ParseWarning> warnings;
    ParseMetadata metadata;
    ParserQualityMetrics quality;
};

class AuthLogParser {
  public:
    explicit AuthLogParser(ParserConfig config = {});

    std::optional<Event> parse_line(std::string_view line,
                                    std::size_t line_number,
                                    std::string* error = nullptr) const;
    ParseReport parse_stream(std::istream& input) const;
    ParseReport parse_file(const std::filesystem::path& path) const;

  private:
    ParserConfig config_;
};

}  // namespace loglens
