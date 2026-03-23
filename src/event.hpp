#pragma once

#include <chrono>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace loglens {

enum class EventType {
    Unknown,
    SshFailedPassword,
    SshAcceptedPassword,
    SshAcceptedPublicKey,
    SshInvalidUser,
    SshFailedPublicKey,
    PamAuthFailure,
    SessionOpened,
    SudoCommand
};

struct Event {
    std::chrono::sys_seconds timestamp{};
    std::string hostname;
    std::string program;
    std::optional<int> pid;
    std::string message;
    std::string source_ip;
    std::string username;
    EventType event_type = EventType::Unknown;
    std::size_t line_number = 0;
};

inline std::string to_string(EventType type) {
    switch (type) {
    case EventType::SshFailedPassword:
        return "ssh_failed_password";
    case EventType::SshAcceptedPassword:
        return "ssh_accepted_password";
    case EventType::SshAcceptedPublicKey:
        return "ssh_accepted_publickey";
    case EventType::SshInvalidUser:
        return "ssh_invalid_user";
    case EventType::SshFailedPublicKey:
        return "ssh_failed_publickey";
    case EventType::PamAuthFailure:
        return "pam_auth_failure";
    case EventType::SessionOpened:
        return "session_opened";
    case EventType::SudoCommand:
        return "sudo_command";
    case EventType::Unknown:
    default:
        return "unknown";
    }
}

inline std::string format_timestamp(std::chrono::sys_seconds timestamp) {
    using namespace std::chrono;

    const auto day_point = floor<days>(timestamp);
    const year_month_day ymd{day_point};
    const hh_mm_ss tod{timestamp - day_point};

    std::ostringstream output;
    output.fill('0');
    output << static_cast<int>(ymd.year()) << '-';
    output.width(2);
    output << static_cast<unsigned>(ymd.month()) << '-';
    output.width(2);
    output << static_cast<unsigned>(ymd.day()) << ' ';
    output.width(2);
    output << tod.hours().count() << ':';
    output.width(2);
    output << tod.minutes().count() << ':';
    output.width(2);
    output << tod.seconds().count();
    return output.str();
}

}  // namespace loglens
