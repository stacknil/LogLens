#include "parser/sudo_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

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
    if (details.find("incorrect password attempt") != std::string_view::npos) {
        event.event_type = EventType::SudoAuthFailure;
        return true;
    }

    if (details.find("user NOT in sudoers") != std::string_view::npos
        || details.find("command not allowed") != std::string_view::npos) {
        event.event_type = EventType::SudoPolicyDenied;
        return true;
    }

    if (details.find("COMMAND=") == std::string_view::npos) {
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
