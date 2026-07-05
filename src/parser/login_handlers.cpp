#include "parser/login_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

bool extract_failed_username(std::string_view message, Event& event) {
    const auto for_position = message.find(" FOR ");
    if (for_position == std::string_view::npos) {
        return false;
    }

    const auto from_position = message.rfind(" FROM ", for_position);
    if (from_position == std::string_view::npos
        || trim(message.substr(from_position + std::string_view{" FROM "}.size(),
                               for_position - from_position - std::string_view{" FROM "}.size())).empty()) {
        return false;
    }

    auto username = message.substr(for_position + std::string_view{" FOR "}.size());
    const auto comma_position = username.find(',');
    if (comma_position == std::string_view::npos) {
        return false;
    }

    const auto reason = trim(username.substr(comma_position + 1));
    username = trim(username.substr(0, comma_position));
    if (username.empty() || reason.empty()) {
        return false;
    }

    if (username != "(unknown)") {
        event.username.assign(username);
    }
    return true;
}

bool parse_login_failure(std::string_view message, Event& event) {
    static constexpr std::string_view failed_prefix = "FAILED LOGIN ";
    static constexpr std::string_view failed_session_prefix = "FAILED LOGIN SESSION FROM ";
    static constexpr std::string_view too_many_prefix = "TOO MANY LOGIN TRIES (";

    bool failed_login = message.starts_with(failed_session_prefix);
    if (!failed_login && message.starts_with(failed_prefix)) {
        const auto count_end = message.find(" FROM ", failed_prefix.size());
        int failure_count = 0;
        failed_login = count_end != std::string_view::npos
            && parse_int(message.substr(failed_prefix.size(), count_end - failed_prefix.size()), failure_count)
            && failure_count > 0;
    }

    bool too_many_tries = false;
    if (message.starts_with(too_many_prefix)) {
        const auto count_end = message.find(") FROM ", too_many_prefix.size());
        int failure_count = 0;
        too_many_tries = count_end != std::string_view::npos
            && parse_int(message.substr(too_many_prefix.size(), count_end - too_many_prefix.size()), failure_count)
            && failure_count > 0;
    }

    if (!failed_login && !too_many_tries) {
        return false;
    }

    if (!extract_failed_username(message, event)) {
        return false;
    }

    event.event_type = EventType::PamAuthFailure;
    return true;
}

bool parse_login_success(std::string_view message, Event& event) {
    static constexpr std::string_view root_prefix = "ROOT LOGIN ON ";
    static constexpr std::string_view login_prefix = "LOGIN ON ";

    if (message.starts_with(root_prefix)) {
        auto terminal = message.substr(root_prefix.size());
        const auto from_position = terminal.find(" FROM ");
        if (from_position != std::string_view::npos) {
            if (trim(terminal.substr(from_position + std::string_view{" FROM "}.size())).empty()) {
                return false;
            }
            terminal = terminal.substr(0, from_position);
        }
        if (trim(terminal).empty()) {
            return false;
        }
        event.username = "root";
        event.event_type = EventType::SessionOpened;
        return true;
    }

    if (!message.starts_with(login_prefix)) {
        return false;
    }

    const auto by_position = message.find(" BY ");
    if (by_position == std::string_view::npos) {
        return false;
    }

    if (trim(message.substr(login_prefix.size(), by_position - login_prefix.size())).empty()) {
        return false;
    }

    auto username = message.substr(by_position + std::string_view{" BY "}.size());
    const auto from_position = username.find(" FROM ");
    if (from_position != std::string_view::npos) {
        if (trim(username.substr(from_position + std::string_view{" FROM "}.size())).empty()) {
            return false;
        }
        username = username.substr(0, from_position);
    }

    username = trim(username);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.event_type = EventType::SessionOpened;
    return true;
}

}  // namespace

HandlerResult handle_login_event(const Event& source) {
    Event event = source;
    const auto message = std::string_view{event.message};
    if (parse_login_failure(message, event) || parse_login_success(message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
