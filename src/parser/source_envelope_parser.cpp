#include "parser/source_envelope_parser.hpp"

#include "parser/text_utils.hpp"
#include "parser/timestamp_parser.hpp"

#include <optional>
#include <utility>

namespace loglens::parser_internal {
namespace {

void parse_program_tag(std::string_view tag, std::string& program, std::optional<int>& pid) {
    tag = trim(tag);
    const auto open_bracket = tag.find('[');
    if (open_bracket == std::string_view::npos || tag.empty() || tag.back() != ']') {
        program.assign(tag);
        pid.reset();
        return;
    }

    const auto pid_token = tag.substr(open_bracket + 1, tag.size() - open_bracket - 2);
    int parsed_pid = 0;
    if (!parse_int(pid_token, parsed_pid)) {
        program.assign(tag);
        pid.reset();
        return;
    }

    program.assign(tag.substr(0, open_bracket));
    pid = parsed_pid;
}

HandlerResult parse_program_and_message(std::string_view remaining, Event event) {
    const auto delimiter = remaining.find(": ");
    const auto fallback_delimiter = remaining.find(':');
    const auto split_position = delimiter != std::string_view::npos ? delimiter : fallback_delimiter;
    if (split_position == std::string_view::npos) {
        return failed_event(ParserFailureCategory::UnknownProgram, "missing program/message delimiter");
    }

    const auto tag = remaining.substr(0, split_position);
    const auto message_offset = split_position + (delimiter != std::string_view::npos ? 2 : 1);
    const auto message = trim_left(remaining.substr(message_offset));

    parse_program_tag(tag, event.program, event.pid);
    event.message.assign(message);
    return matched_event(std::move(event));
}

}  // namespace

HandlerResult parse_source_envelope(const ParserConfig& config,
                                    std::string_view line,
                                    std::size_t line_number) {
    if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
    }

    auto remaining = line;
    auto timestamp_result = parse_timestamp_and_hostname(config, remaining, line_number);
    if (!timestamp_result.matched || !timestamp_result.event.has_value()) {
        return timestamp_result;
    }

    return parse_program_and_message(remaining, std::move(*timestamp_result.event));
}

}  // namespace loglens::parser_internal
