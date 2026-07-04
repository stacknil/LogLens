#include "parser.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/program_dispatch.hpp"
#include "parser/source_envelope_parser.hpp"
#include "parser/text_utils.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace loglens {
namespace {

void set_failure(std::string* error,
                 ParserFailureCategory* category,
                 const parser_internal::HandlerResult& result) {
    if (error != nullptr) {
        *error = result.reason;
    }
    if (category != nullptr) {
        *category = result.failure_category;
    }
}

}  // namespace

std::string to_string(InputMode mode) {
    switch (mode) {
    case InputMode::SyslogLegacy:
        return "syslog_legacy";
    case InputMode::JournalctlShortFull:
    default:
        return "journalctl_short_full";
    }
}

std::optional<InputMode> parse_input_mode(std::string_view value) {
    if (value == "syslog" || value == "syslog-legacy" || value == "syslog_legacy") {
        return InputMode::SyslogLegacy;
    }

    if (value == "journalctl"
        || value == "journalctl-short-full"
        || value == "journalctl_short_full") {
        return InputMode::JournalctlShortFull;
    }

    return std::nullopt;
}

std::string to_string(ParserFailureCategory category) {
    switch (category) {
    case ParserFailureCategory::UnknownTimestamp:
        return "unknown_timestamp";
    case ParserFailureCategory::UnknownProgram:
        return "unknown_program";
    case ParserFailureCategory::KnownProgramUnknownMessage:
        return "known_program_unknown_message";
    case ParserFailureCategory::MalformedSourceIp:
        return "malformed_source_ip";
    case ParserFailureCategory::UnsupportedPamVariant:
    default:
        return "unsupported_pam_variant";
    }
}

AuthLogParser::AuthLogParser(ParserConfig config)
    : config_(config) {}

std::optional<Event> AuthLogParser::parse_line(std::string_view line,
                                               std::size_t line_number,
                                               std::string* error,
                                               ParserFailureCategory* category) const {
    if (error != nullptr) {
        error->clear();
    }
    if (category != nullptr) {
        *category = ParserFailureCategory::KnownProgramUnknownMessage;
    }

    auto result = parser_internal::parse_source_envelope(config_, line, line_number);
    if (result.matched && result.event.has_value()) {
        if (auto source_ip_failure = parser_internal::classify_source_ip_failure(*result.event)) {
            result = std::move(*source_ip_failure);
        } else {
            result = parser_internal::dispatch_program(*result.event);
        }
    }

    if (!result.matched || !result.event.has_value()) {
        set_failure(error, category, result);
        return std::nullopt;
    }

    return std::move(result.event);
}

ParseReport AuthLogParser::parse_stream(std::istream& input) const {
    ParseReport result;
    result.metadata.input_mode = config_.input_mode;
    result.metadata.timezone_present = config_.input_mode == InputMode::JournalctlShortFull;
    if (config_.input_mode == InputMode::SyslogLegacy) {
        result.metadata.assume_year = config_.assumed_year;
    }
    std::unordered_map<std::string, std::size_t> unknown_pattern_counts;
    std::unordered_map<std::string, std::pair<ParserFailureCategory, std::size_t>> failure_category_counts;

    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        if (parser_internal::trim(line).empty()) {
            ++result.quality.skipped_blank_lines;
            continue;
        }

        ++result.quality.total_lines;

        std::string error;
        ParserFailureCategory category = ParserFailureCategory::KnownProgramUnknownMessage;
        auto event = parse_line(line, line_number, &error, &category);
        if (event.has_value()) {
            result.events.push_back(std::move(*event));
            ++result.quality.parsed_lines;
            continue;
        }

        const auto reason = error.empty() ? "unrecognized line" : error;
        result.warnings.push_back(ParseWarning{line_number, reason, category});
        ++result.quality.unparsed_lines;
        ++unknown_pattern_counts[parser_internal::extract_unknown_pattern_key(reason)];
        auto& category_count = failure_category_counts[to_string(category)];
        category_count.first = category;
        ++category_count.second;
    }

    if (result.quality.total_lines != 0) {
        result.quality.parse_success_rate =
            static_cast<double>(result.quality.parsed_lines) / static_cast<double>(result.quality.total_lines);
    }

    result.quality.top_unknown_patterns.reserve(unknown_pattern_counts.size());
    for (const auto& [pattern, count] : unknown_pattern_counts) {
        result.quality.top_unknown_patterns.push_back(UnknownPatternCount{pattern, count});
    }

    std::sort(result.quality.top_unknown_patterns.begin(),
              result.quality.top_unknown_patterns.end(),
              [](const UnknownPatternCount& left, const UnknownPatternCount& right) {
                  if (left.count != right.count) {
                      return left.count > right.count;
                  }
                  return left.pattern < right.pattern;
              });
    if (result.quality.top_unknown_patterns.size() > 5) {
        result.quality.top_unknown_patterns.resize(5);
    }

    result.quality.failure_categories.reserve(failure_category_counts.size());
    for (const auto& [_, entry] : failure_category_counts) {
        result.quality.failure_categories.push_back(ParserFailureCategoryCount{entry.first, entry.second});
    }

    std::sort(result.quality.failure_categories.begin(),
              result.quality.failure_categories.end(),
              [](const ParserFailureCategoryCount& left, const ParserFailureCategoryCount& right) {
                  if (left.count != right.count) {
                      return left.count > right.count;
                  }
                  return to_string(left.category) < to_string(right.category);
              });

    return result;
}

ParseReport AuthLogParser::parse_file(const std::filesystem::path& path) const {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to open input log: " + path.string());
    }

    return parse_stream(input);
}

}  // namespace loglens
