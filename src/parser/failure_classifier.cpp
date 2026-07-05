#include "parser/failure_classifier.hpp"

#include "parser/text_utils.hpp"

#include <cctype>

namespace loglens::parser_internal {
namespace {

bool is_valid_ipv4_token(std::string_view token) {
    int parts = 0;
    while (!token.empty()) {
        const auto dot = token.find('.');
        const auto part = dot == std::string_view::npos ? token : token.substr(0, dot);
        if (part.empty()) {
            return false;
        }

        int value = 0;
        if (!parse_int(part, value) || value < 0 || value > 255) {
            return false;
        }

        ++parts;
        if (dot == std::string_view::npos) {
            token = {};
        } else {
            token.remove_prefix(dot + 1);
        }
    }

    return parts == 4;
}

bool is_valid_ipv6_like_token(std::string_view token) {
    if (token.find(':') == std::string_view::npos) {
        return false;
    }

    bool saw_hex = false;
    for (const char character : token) {
        if (std::isxdigit(static_cast<unsigned char>(character)) != 0) {
            saw_hex = true;
            continue;
        }
        if (character == ':' || character == '.') {
            continue;
        }
        return false;
    }

    return saw_hex;
}

bool is_valid_source_ip_token(std::string_view token) {
    return is_valid_ipv4_token(token) || is_valid_ipv6_like_token(token);
}

std::string extract_source_ip_after_from(std::string_view message) {
    const auto marker_position = message.find(" from ");
    if (marker_position == std::string_view::npos) {
        return {};
    }

    auto remaining = message.substr(marker_position + std::string_view{" from "}.size());
    const auto first = consume_token(remaining);
    if (first.empty()) {
        return {};
    }

    if (first == "authenticating") {
        const auto second = consume_token(remaining);
        if (second == "user") {
            static_cast<void>(consume_token(remaining));
            return std::string(consume_token(remaining));
        }
    }

    if (first == "invalid" || first == "illegal") {
        const auto second = consume_token(remaining);
        if (second == "user") {
            static_cast<void>(consume_token(remaining));
            return std::string(consume_token(remaining));
        }
    }

    if (first == "user") {
        static_cast<void>(consume_token(remaining));
        return std::string(consume_token(remaining));
    }

    return std::string(first);
}

std::string extract_source_ip_candidate(const Event& event) {
    auto candidate = extract_source_ip_after_from(event.message);
    if (!candidate.empty()) {
        return candidate;
    }

    candidate = extract_kv_value(event.message, "rhost=");
    if (!candidate.empty()) {
        return candidate;
    }

    if (event.program == "sshd" && event.message.starts_with("Unable to negotiate with ")) {
        candidate = extract_token_after(event.message, " with ");
    }

    return candidate;
}

std::string classify_unknown_pam_faillock_pattern(std::string_view message) {
    if (message.starts_with("Account temporarily locked for user ")) {
        return "pam_faillock_account_locked";
    }

    if (message.starts_with("User ") && message.find("successfully authenticated") != std::string_view::npos) {
        return "pam_faillock_authsucc";
    }

    return "pam_faillock_other";
}

std::string classify_unknown_pam_sss_pattern(std::string_view message) {
    if (message.find("User not known to the underlying authentication module") != std::string_view::npos) {
        return "pam_sss_unknown_user";
    }

    if (message.find("Authentication service cannot retrieve authentication info") != std::string_view::npos) {
        return "pam_sss_authinfo_unavail";
    }

    return "pam_sss_other";
}

std::string classify_unknown_auth_pattern(const Event& event) {
    const auto message = std::string_view{event.message};
    if (event.program == "sshd") {
        if ((message.starts_with("Connection closed by ")
             || message.starts_with("Connection closed by authenticating user ")
             || message.starts_with("Connection reset by "))
            && message.find("[preauth]") != std::string_view::npos) {
            return "sshd_connection_closed_preauth";
        }

        if (message.starts_with("Timeout, client not responding")
            || message.starts_with("Disconnected from ")
            || message.starts_with("Received disconnect")) {
            return "sshd_timeout_or_disconnection";
        }

        if (message.starts_with("Unable to negotiate with ")) {
            return "sshd_negotiation_failure";
        }

        return "sshd_other";
    }

    if (event.program.starts_with("pam_unix(")) {
        if (message.starts_with("session closed for user ")) {
            return "pam_unix_session_closed";
        }

        return "pam_unix_other";
    }

    if (event.program.starts_with("pam_faillock(")) {
        return classify_unknown_pam_faillock_pattern(message);
    }

    if (event.program.starts_with("pam_sss(")) {
        return classify_unknown_pam_sss_pattern(message);
    }

    if (event.program == "sudo") {
        return "sudo_other";
    }

    if (event.program == "su") {
        return "su_other";
    }

    if (event.program == "login") {
        return "login_other";
    }

    return "program_" + sanitize_pattern_label(event.program);
}

bool is_pam_program(std::string_view program) {
    return program.starts_with("pam_unix(")
        || program.starts_with("pam_faillock(")
        || program.starts_with("pam_sss(");
}

bool is_known_auth_program(std::string_view program) {
    return program == "sshd"
        || program == "sudo"
        || program == "su"
        || program == "login"
        || is_pam_program(program);
}

ParserFailureCategory failure_category_for_unrecognized_event(const Event& event) {
    if (is_pam_program(event.program)) {
        return ParserFailureCategory::UnsupportedPamVariant;
    }
    if (is_known_auth_program(event.program)) {
        return ParserFailureCategory::KnownProgramUnknownMessage;
    }
    return ParserFailureCategory::UnknownProgram;
}

}  // namespace

std::optional<HandlerResult> classify_source_ip_failure(const Event& event) {
    const auto candidate = extract_source_ip_candidate(event);
    if (candidate.empty() || is_valid_source_ip_token(candidate)) {
        return std::nullopt;
    }

    return failed_event(ParserFailureCategory::MalformedSourceIp, "malformed source IP");
}

HandlerResult classify_unrecognized_event(const Event& event) {
    return failed_event(
        failure_category_for_unrecognized_event(event),
        "unrecognized auth pattern: " + classify_unknown_auth_pattern(event));
}

std::string extract_unknown_pattern_key(std::string_view error) {
    static constexpr std::string_view unknown_prefix = "unrecognized auth pattern: ";
    if (error.starts_with(unknown_prefix)) {
        return std::string(error.substr(unknown_prefix.size()));
    }

    return sanitize_pattern_label(error);
}

}  // namespace loglens::parser_internal
