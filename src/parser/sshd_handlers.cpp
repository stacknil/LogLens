#include "parser/sshd_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

bool consume_invalid_or_illegal_user_prefix(std::string_view& remaining) {
    static constexpr std::string_view invalid_user_prefix = "invalid user ";
    static constexpr std::string_view illegal_user_prefix = "illegal user ";

    if (remaining.starts_with(invalid_user_prefix)) {
        remaining.remove_prefix(invalid_user_prefix.size());
        return true;
    }

    if (remaining.starts_with(illegal_user_prefix)) {
        remaining.remove_prefix(illegal_user_prefix.size());
        return true;
    }

    return false;
}

bool parse_ssh_failed_message(std::string_view message, Event& event) {
    static constexpr std::string_view failed_password_prefix = "Failed password for ";
    static constexpr std::string_view failed_none_prefix = "Failed none for ";

    bool failed_none = false;
    std::string_view remaining;
    if (message.starts_with(failed_password_prefix)) {
        remaining = message.substr(failed_password_prefix.size());
    } else if (message.starts_with(failed_none_prefix)) {
        failed_none = true;
        remaining = message.substr(failed_none_prefix.size());
    } else {
        return false;
    }

    const bool invalid_user = consume_invalid_or_illegal_user_prefix(remaining);
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    if (failed_none && !invalid_user) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = invalid_user ? EventType::SshInvalidUser : EventType::SshFailedPassword;
    return true;
}

bool parse_ssh_accepted_message(std::string_view message, Event& event) {
    static constexpr std::string_view accepted_prefix = "Accepted password for ";
    if (!message.starts_with(accepted_prefix)) {
        return false;
    }

    auto remaining = message.substr(accepted_prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshAcceptedPassword;
    return true;
}

bool parse_ssh_accepted_publickey_message(std::string_view message, Event& event) {
    static constexpr std::string_view accepted_prefix = "Accepted publickey for ";
    if (!message.starts_with(accepted_prefix)) {
        return false;
    }

    auto remaining = message.substr(accepted_prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshAcceptedPublicKey;
    return true;
}

bool parse_ssh_accepted_keyboard_interactive_message(std::string_view message, Event& event) {
    static constexpr std::string_view accepted_prefix = "Accepted keyboard-interactive/pam for ";
    if (!message.starts_with(accepted_prefix)) {
        return false;
    }

    auto remaining = message.substr(accepted_prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshAcceptedKeyboardInteractive;
    return true;
}

bool parse_ssh_failed_publickey_message(std::string_view message, Event& event) {
    static constexpr std::string_view publickey_prefix = "Failed publickey for ";
    if (!message.starts_with(publickey_prefix)) {
        return false;
    }

    auto remaining = message.substr(publickey_prefix.size());
    consume_invalid_or_illegal_user_prefix(remaining);
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshFailedPublicKey;
    return true;
}

bool parse_ssh_failed_keyboard_interactive_message(std::string_view message, Event& event) {
    static constexpr std::string_view keyboard_prefix = "Failed keyboard-interactive/pam for ";
    if (!message.starts_with(keyboard_prefix)) {
        return false;
    }

    auto remaining = message.substr(keyboard_prefix.size());
    const bool invalid_user = consume_invalid_or_illegal_user_prefix(remaining);
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = invalid_user ? EventType::SshInvalidUser : EventType::SshFailedKeyboardInteractive;
    return true;
}

bool parse_ssh_max_auth_tries_message(std::string_view message, Event& event) {
    static constexpr std::string_view max_auth_prefix = "maximum authentication attempts exceeded for ";
    static constexpr std::string_view error_prefix = "error: ";
    if (message.starts_with(error_prefix)) {
        message.remove_prefix(error_prefix.size());
    }

    if (!message.starts_with(max_auth_prefix)) {
        return false;
    }

    auto remaining = message.substr(max_auth_prefix.size());
    const bool invalid_user = consume_invalid_or_illegal_user_prefix(remaining);
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = invalid_user ? EventType::SshInvalidUser : EventType::SshMaxAuthTries;
    return true;
}

bool parse_ssh_pam_auth_failure_message(std::string_view message, Event& event) {
    static constexpr std::string_view error_prefix = "error: ";
    static constexpr std::string_view pam_auth_prefix = "PAM: Authentication failure for ";

    if (message.starts_with(error_prefix)) {
        message.remove_prefix(error_prefix.size());
    }
    if (!message.starts_with(pam_auth_prefix)) {
        return false;
    }

    auto remaining = message.substr(pam_auth_prefix.size());
    const bool invalid_user = consume_invalid_or_illegal_user_prefix(remaining);
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = invalid_user ? EventType::SshInvalidUser : EventType::PamAuthFailure;
    return true;
}

bool parse_ssh_input_userauth_request_message(std::string_view message, Event& event) {
    static constexpr std::string_view input_userauth_prefix = "input_userauth_request: ";
    if (!message.starts_with(input_userauth_prefix)) {
        return false;
    }

    auto remaining = message.substr(input_userauth_prefix.size());
    if (!consume_invalid_or_illegal_user_prefix(remaining)) {
        return false;
    }

    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.event_type = EventType::SshInvalidUser;
    return true;
}

bool parse_ssh_invalid_user_message(std::string_view message, Event& event) {
    static constexpr std::string_view invalid_user_prefix = "Invalid user ";
    static constexpr std::string_view illegal_user_prefix = "Illegal user ";
    if (!message.starts_with(invalid_user_prefix) && !message.starts_with(illegal_user_prefix)) {
        return false;
    }

    auto remaining = message.starts_with(invalid_user_prefix)
        ? message.substr(invalid_user_prefix.size())
        : message.substr(illegal_user_prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshInvalidUser;
    return true;
}

}  // namespace

HandlerResult handle_sshd_event(const Event& source) {
    Event event = source;
    const auto message = std::string_view{event.message};

    if (parse_ssh_failed_message(message, event)
        || parse_ssh_accepted_message(message, event)
        || parse_ssh_accepted_publickey_message(message, event)
        || parse_ssh_accepted_keyboard_interactive_message(message, event)
        || parse_ssh_failed_publickey_message(message, event)
        || parse_ssh_failed_keyboard_interactive_message(message, event)
        || parse_ssh_max_auth_tries_message(message, event)
        || parse_ssh_pam_auth_failure_message(message, event)
        || parse_ssh_input_userauth_request_message(message, event)
        || parse_ssh_invalid_user_message(message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
