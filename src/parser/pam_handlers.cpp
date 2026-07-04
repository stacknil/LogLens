#include "parser/pam_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

bool parse_pam_named_user_failure_message(std::string_view message,
                                          std::string_view prefix,
                                          Event& event) {
    if (!message.starts_with(prefix)) {
        return false;
    }

    auto remaining = message.substr(prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::PamAuthFailure;
    return true;
}

bool parse_pam_auth_failure_message(std::string_view message, Event& event) {
    static constexpr std::string_view auth_failure_prefix = "authentication failure;";
    if (!message.starts_with(auth_failure_prefix)) {
        return false;
    }

    event.username = extract_kv_value(message, "user=");
    event.source_ip = extract_kv_value(message, "rhost=");
    event.event_type = EventType::PamAuthFailure;
    return true;
}

bool parse_pam_sss_received_failure_message(std::string_view message, Event& event) {
    static constexpr std::string_view received_prefix = "received for user ";
    static constexpr std::string_view failure_marker = "(Authentication failure)";

    if (!message.starts_with(received_prefix) || message.find(failure_marker) == std::string_view::npos) {
        return false;
    }

    auto remaining = message.substr(received_prefix.size());
    const auto separator = remaining.find(':');
    if (separator == std::string_view::npos) {
        return false;
    }

    const auto username = trim(remaining.substr(0, separator));
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.event_type = EventType::PamAuthFailure;
    return true;
}

bool parse_session_opened_message(std::string_view message, Event& event) {
    static constexpr std::string_view session_prefix = "session opened for user ";
    if (!message.starts_with(session_prefix)) {
        return false;
    }

    const auto by_position = message.find(" by ");
    if (by_position == std::string_view::npos) {
        return false;
    }

    auto actor = message.substr(by_position + std::string_view{" by "}.size());
    const auto actor_end = actor.find_first_of("( ");
    if (actor_end != std::string_view::npos) {
        actor = actor.substr(0, actor_end);
    }

    actor = trim(actor);
    if (actor.empty()) {
        return false;
    }

    event.username.assign(actor);
    event.event_type = EventType::SessionOpened;
    return true;
}

bool parse_pam_faillock_message(std::string_view message, Event& event) {
    return parse_pam_named_user_failure_message(
               message,
               "Consecutive login failures for user ",
               event)
        || parse_pam_named_user_failure_message(
               message,
               "Authentication failure for user ",
               event);
}

}  // namespace

HandlerResult handle_pam_unix_event(const Event& source) {
    Event event = source;
    const auto message = std::string_view{event.message};
    if (parse_pam_auth_failure_message(message, event)
        || parse_session_opened_message(message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

HandlerResult handle_pam_faillock_event(const Event& source) {
    Event event = source;
    if (parse_pam_faillock_message(event.message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

HandlerResult handle_pam_sss_event(const Event& source) {
    Event event = source;
    const auto message = std::string_view{event.message};
    if (parse_pam_auth_failure_message(message, event)
        || parse_pam_sss_received_failure_message(message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
