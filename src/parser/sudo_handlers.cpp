#include "parser/sudo_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

std::size_t find_command_field(std::string_view details) {
    // Sudo audit fields are separated by " ; "; substrings inside values are opaque.
    std::size_t offset = 0;
    while (offset < details.size()) {
        const auto field = trim_left(details.substr(offset));
        if (field.starts_with("COMMAND=")) {
            return details.size() - field.size();
        }
        const auto separator = details.find(" ; ", offset);
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 3;
    }
    return std::string_view::npos;
}

bool parse_sudo_message(std::string_view message, Event& event) {
    auto remaining = trim_left(message);
    const auto separator = remaining.find(':');
    if (separator == std::string_view::npos) {
        return false;
    }

    const auto username = trim(remaining.substr(0, separator));
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    const auto details = trim_left(remaining.substr(separator + 1));
    const auto command_position = find_command_field(details);
    const auto metadata = details.substr(0, command_position);
    const auto attempt_marker = metadata.find(" incorrect password attempt");
    const auto attempt_count = metadata.substr(0, attempt_marker);
    if (attempt_marker != std::string_view::npos && !attempt_count.empty()
        && std::all_of(attempt_count.begin(), attempt_count.end(), [](char ch) {
               return ch >= '0' && ch <= '9';
           })) {
        event.event_type = EventType::SudoAuthFailure;
        return true;
    }

    if (metadata.starts_with("user NOT in sudoers")
        || metadata.starts_with("command not allowed")) {
        event.event_type = EventType::SudoPolicyDenied;
        return true;
    }

    if (command_position == std::string_view::npos) {
        return false;
    }

    event.event_type = EventType::SudoCommand;
    return true;
}

}  // namespace

HandlerResult handle_sudo_event(const Event& source) {
    Event event = source;
    if (parse_sudo_message(event.message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
