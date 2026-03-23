#include "parser.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace loglens {
namespace {

struct ClockTime {
    int hour = 0;
    int minute = 0;
    int second = 0;
};

std::string_view trim_left(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    return value;
}

std::string_view trim(std::string_view value) {
    value = trim_left(value);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return value;
}

std::string_view consume_token(std::string_view& input) {
    input = trim_left(input);
    if (input.empty()) {
        return {};
    }

    const auto separator = input.find(' ');
    if (separator == std::string_view::npos) {
        const auto token = input;
        input = {};
        return token;
    }

    const auto token = input.substr(0, separator);
    input.remove_prefix(separator + 1);
    return token;
}

bool parse_int(std::string_view token, int& value) {
    const auto* begin = token.data();
    const auto* end = token.data() + token.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

bool parse_month(std::string_view token, unsigned& month_index) {
    static constexpr std::array<std::string_view, 12> months = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    for (std::size_t index = 0; index < months.size(); ++index) {
        if (months[index] == token) {
            month_index = static_cast<unsigned>(index + 1);
            return true;
        }
    }

    return false;
}

bool parse_clock_token(std::string_view token, ClockTime& time) {
    if (token.size() < 8 || token[2] != ':' || token[5] != ':') {
        return false;
    }

    if (!parse_int(token.substr(0, 2), time.hour)
        || !parse_int(token.substr(3, 2), time.minute)
        || !parse_int(token.substr(6, 2), time.second)) {
        return false;
    }

    if (token.size() == 8) {
        return time.hour >= 0 && time.hour <= 23
            && time.minute >= 0 && time.minute <= 59
            && time.second >= 0 && time.second <= 59;
    }

    if (token[8] != '.') {
        return false;
    }

    for (std::size_t index = 9; index < token.size(); ++index) {
        if (std::isdigit(static_cast<unsigned char>(token[index])) == 0) {
            return false;
        }
    }

    return time.hour >= 0 && time.hour <= 23
        && time.minute >= 0 && time.minute <= 59
        && time.second >= 0 && time.second <= 59;
}

std::optional<std::chrono::sys_seconds> build_timestamp(int year_value,
                                                        unsigned month_index,
                                                        int day_value,
                                                        const ClockTime& time,
                                                        std::chrono::minutes offset = std::chrono::minutes{0}) {
    using namespace std::chrono;

    const year_month_day date{year{year_value}, month{month_index}, day{static_cast<unsigned>(day_value)}};
    if (!date.ok()) {
        return std::nullopt;
    }

    const auto timestamp = sys_days{date}
        + hours{time.hour}
        + minutes{time.minute}
        + seconds{time.second};
    return timestamp - offset;
}

bool parse_calendar_date_parts(std::string_view token, int& year_value, unsigned& month_index, int& day_value) {
    int parsed_month = 0;
    if (token.size() != 10 || token[4] != '-' || token[7] != '-') {
        return false;
    }

    return parse_int(token.substr(0, 4), year_value)
        && parse_int(token.substr(5, 2), parsed_month)
        && parse_int(token.substr(8, 2), day_value)
        && parsed_month >= 1 && parsed_month <= 12
        && (month_index = static_cast<unsigned>(parsed_month), true);
}

bool parse_timezone_token(std::string_view token, std::chrono::minutes& offset) {
    using namespace std::chrono;

    if (token == "UTC" || token == "GMT" || token == "Z") {
        offset = minutes{0};
        return true;
    }

    if (token.size() != 5 && token.size() != 6) {
        return false;
    }

    if (token.front() != '+' && token.front() != '-') {
        return false;
    }

    const bool negative = token.front() == '-';
    const auto digits = token.substr(1);
    int parsed_hours = 0;
    int minutes_value = 0;

    if (digits.size() == 4) {
        if (!parse_int(digits.substr(0, 2), parsed_hours) || !parse_int(digits.substr(2, 2), minutes_value)) {
            return false;
        }
    } else {
        if (digits[2] != ':'
            || !parse_int(digits.substr(0, 2), parsed_hours)
            || !parse_int(digits.substr(3, 2), minutes_value)) {
            return false;
        }
    }

    if (parsed_hours < 0 || parsed_hours > 23 || minutes_value < 0 || minutes_value > 59) {
        return false;
    }

    offset = std::chrono::hours{parsed_hours} + minutes{minutes_value};
    if (negative) {
        offset = -offset;
    }
    return true;
}

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

bool parse_program_and_message(std::string_view remaining, Event& event, std::string* error) {
    const auto delimiter = remaining.find(": ");
    const auto fallback_delimiter = remaining.find(':');
    const auto split_position = delimiter != std::string_view::npos ? delimiter : fallback_delimiter;
    if (split_position == std::string_view::npos) {
        if (error != nullptr) {
            *error = "missing program/message delimiter";
        }
        return false;
    }

    const auto tag = remaining.substr(0, split_position);
    const auto message_offset = split_position + (delimiter != std::string_view::npos ? 2 : 1);
    const auto message = trim_left(remaining.substr(message_offset));

    parse_program_tag(tag, event.program, event.pid);
    event.message.assign(message);
    return true;
}

std::string extract_token_after(std::string_view input, std::string_view marker) {
    const auto marker_position = input.find(marker);
    if (marker_position == std::string_view::npos) {
        return {};
    }

    auto remaining = input.substr(marker_position + marker.size());
    return std::string(consume_token(remaining));
}

std::string extract_kv_value(std::string_view input, std::string_view key) {
    std::size_t search_position = 0;
    while (search_position < input.size()) {
        const auto key_position = input.find(key, search_position);
        if (key_position == std::string_view::npos) {
            return {};
        }

        if (key_position == 0
            || std::isspace(static_cast<unsigned char>(input[key_position - 1])) != 0
            || input[key_position - 1] == ';') {
            auto remaining = input.substr(key_position + key.size());
            const auto end = remaining.find_first_of(" ;");
            if (end != std::string_view::npos) {
                remaining = remaining.substr(0, end);
            }
            return std::string(remaining);
        }

        search_position = key_position + key.size();
    }

    return {};
}

std::string sanitize_pattern_label(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());

    bool previous_was_separator = false;
    for (const char character : value) {
        if (std::isalnum(static_cast<unsigned char>(character)) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
            previous_was_separator = false;
            continue;
        }

        if (!normalized.empty() && !previous_was_separator) {
            normalized.push_back('_');
            previous_was_separator = true;
        }
    }

    while (!normalized.empty() && normalized.back() == '_') {
        normalized.pop_back();
    }

    return normalized.empty() ? "unknown_pattern" : normalized;
}

bool parse_ssh_failed_message(std::string_view message, Event& event) {
    static constexpr std::string_view failed_prefix = "Failed password for ";
    if (!message.starts_with(failed_prefix)) {
        return false;
    }

    auto remaining = message.substr(failed_prefix.size());
    bool invalid_user = false;
    if (remaining.starts_with("invalid user ")) {
        invalid_user = true;
        remaining.remove_prefix(std::string_view{"invalid user "}.size());
    }

    const auto username = consume_token(remaining);
    if (username.empty()) {
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

bool parse_ssh_failed_publickey_message(std::string_view message, Event& event) {
    static constexpr std::string_view publickey_prefix = "Failed publickey for ";
    if (!message.starts_with(publickey_prefix)) {
        return false;
    }

    auto remaining = message.substr(publickey_prefix.size());
    if (remaining.starts_with("invalid user ")) {
        remaining.remove_prefix(std::string_view{"invalid user "}.size());
    }

    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshFailedPublicKey;
    return true;
}

bool parse_ssh_invalid_user_message(std::string_view message, Event& event) {
    static constexpr std::string_view invalid_user_prefix = "Invalid user ";
    if (!message.starts_with(invalid_user_prefix)) {
        return false;
    }

    auto remaining = message.substr(invalid_user_prefix.size());
    const auto username = consume_token(remaining);
    if (username.empty()) {
        return false;
    }

    event.username.assign(username);
    event.source_ip = extract_token_after(message, " from ");
    event.event_type = EventType::SshInvalidUser;
    return true;
}

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
    event.event_type = EventType::SudoCommand;
    return true;
}

bool parse_pam_faillock_message(std::string_view message, Event& event) {
    if (parse_pam_named_user_failure_message(message, "Consecutive login failures for user ", event)) {
        return true;
    }

    if (parse_pam_named_user_failure_message(message, "Authentication failure for user ", event)) {
        return true;
    }

    return false;
}

std::string classify_unknown_pam_faillock_pattern(std::string_view message) {
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
        if ((message.starts_with("Connection closed by ") || message.starts_with("Connection closed by authenticating user "))
            && message.find("[preauth]") != std::string_view::npos) {
            return "sshd_connection_closed_preauth";
        }

        if (message.starts_with("Timeout, client not responding")
            || message.starts_with("Disconnected from ")
            || message.starts_with("Received disconnect")) {
            return "sshd_timeout_or_disconnection";
        }

        return "sshd_other";
    }

    if (event.program.starts_with("pam_unix(")) {
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

    return "program_" + sanitize_pattern_label(event.program);
}

bool classify_event(Event& event) {
    const auto message = std::string_view{event.message};
    if (event.program == "sshd") {
        if (parse_ssh_failed_message(message, event)) {
            return true;
        }
        if (parse_ssh_accepted_message(message, event)) {
            return true;
        }
        if (parse_ssh_accepted_publickey_message(message, event)) {
            return true;
        }
        if (parse_ssh_failed_publickey_message(message, event)) {
            return true;
        }
        if (parse_ssh_invalid_user_message(message, event)) {
            return true;
        }
        return false;
    }

    if (event.program.starts_with("pam_unix(")) {
        if (parse_pam_auth_failure_message(message, event)) {
            return true;
        }
        if (parse_session_opened_message(message, event)) {
            return true;
        }
        return false;
    }

    if (event.program.starts_with("pam_faillock(")) {
        return parse_pam_faillock_message(message, event);
    }

    if (event.program.starts_with("pam_sss(")) {
        if (parse_pam_auth_failure_message(message, event)) {
            return true;
        }
        if (parse_pam_sss_received_failure_message(message, event)) {
            return true;
        }
        return false;
    }

    if (event.program == "sudo") {
        return parse_sudo_message(message, event);
    }

    return false;
}

std::string extract_unknown_pattern_key(std::string_view error) {
    static constexpr std::string_view unknown_prefix = "unrecognized auth pattern: ";
    if (error.starts_with(unknown_prefix)) {
        return std::string(error.substr(unknown_prefix.size()));
    }

    return sanitize_pattern_label(error);
}

std::optional<Event> parse_syslog_legacy_line(const ParserConfig& config,
                                              std::string_view line,
                                              std::size_t line_number,
                                              std::string* error) {
    if (!config.assumed_year.has_value()) {
        if (error != nullptr) {
            *error = "syslog_legacy mode requires assume_year";
        }
        return std::nullopt;
    }

    auto remaining = line;
    const auto month_token = consume_token(remaining);
    const auto day_token = consume_token(remaining);
    const auto time_token = consume_token(remaining);
    const auto hostname_token = consume_token(remaining);

    if (month_token.empty() || day_token.empty() || time_token.empty() || hostname_token.empty()) {
        if (error != nullptr) {
            *error = "missing syslog header fields";
        }
        return std::nullopt;
    }

    unsigned month_index = 0;
    int day_value = 0;
    ClockTime time;

    if (!parse_month(month_token, month_index)) {
        if (error != nullptr) {
            *error = "invalid month token";
        }
        return std::nullopt;
    }

    if (!parse_int(day_token, day_value)) {
        if (error != nullptr) {
            *error = "invalid day token";
        }
        return std::nullopt;
    }

    if (!parse_clock_token(time_token, time)) {
        if (error != nullptr) {
            *error = "invalid time token";
        }
        return std::nullopt;
    }

    const auto timestamp = build_timestamp(*config.assumed_year, month_index, day_value, time);
    if (!timestamp.has_value()) {
        if (error != nullptr) {
            *error = "invalid calendar date";
        }
        return std::nullopt;
    }

    Event event;
    event.timestamp = *timestamp;
    event.hostname.assign(hostname_token);
    event.line_number = line_number;

    if (!parse_program_and_message(remaining, event, error)) {
        return std::nullopt;
    }

    if (!classify_event(event)) {
        if (error != nullptr) {
            *error = "unrecognized auth pattern: " + classify_unknown_auth_pattern(event);
        }
        return std::nullopt;
    }

    return event;
}

std::optional<Event> parse_journalctl_short_full_line(std::string_view line,
                                                      std::size_t line_number,
                                                      std::string* error) {
    auto remaining = line;
    const auto weekday_token = consume_token(remaining);
    const auto date_token = consume_token(remaining);
    const auto time_token = consume_token(remaining);
    const auto timezone_token = consume_token(remaining);
    const auto hostname_token = consume_token(remaining);

    if (weekday_token.empty() || date_token.empty() || time_token.empty()
        || timezone_token.empty() || hostname_token.empty()) {
        if (error != nullptr) {
            *error = "missing journalctl short-full header fields";
        }
        return std::nullopt;
    }

    int year_value = 0;
    unsigned month_index = 0;
    int day_value = 0;
    ClockTime time;
    std::chrono::minutes timezone_offset{0};

    if (!parse_calendar_date_parts(date_token, year_value, month_index, day_value)) {
        if (error != nullptr) {
            *error = "invalid journalctl date token";
        }
        return std::nullopt;
    }

    if (!parse_clock_token(time_token, time)) {
        if (error != nullptr) {
            *error = "invalid time token";
        }
        return std::nullopt;
    }

    if (!parse_timezone_token(timezone_token, timezone_offset)) {
        if (error != nullptr) {
            *error = "invalid timezone token";
        }
        return std::nullopt;
    }

    const auto timestamp = build_timestamp(year_value, month_index, day_value, time, timezone_offset);
    if (!timestamp.has_value()) {
        if (error != nullptr) {
            *error = "invalid calendar date";
        }
        return std::nullopt;
    }

    Event event;
    event.timestamp = *timestamp;
    event.hostname.assign(hostname_token);
    event.line_number = line_number;

    if (!parse_program_and_message(remaining, event, error)) {
        return std::nullopt;
    }

    if (!classify_event(event)) {
        if (error != nullptr) {
            *error = "unrecognized auth pattern: " + classify_unknown_auth_pattern(event);
        }
        return std::nullopt;
    }

    return event;
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
    if (value == "syslog" || value == "syslog_legacy") {
        return InputMode::SyslogLegacy;
    }

    if (value == "journalctl-short-full" || value == "journalctl_short_full") {
        return InputMode::JournalctlShortFull;
    }

    return std::nullopt;
}

AuthLogParser::AuthLogParser(ParserConfig config)
    : config_(config) {}

std::optional<Event> AuthLogParser::parse_line(std::string_view line,
                                               std::size_t line_number,
                                               std::string* error) const {
    if (error != nullptr) {
        error->clear();
    }

    switch (config_.input_mode) {
    case InputMode::SyslogLegacy:
        return parse_syslog_legacy_line(config_, line, line_number, error);
    case InputMode::JournalctlShortFull:
        return parse_journalctl_short_full_line(line, line_number, error);
    default:
        if (error != nullptr) {
            *error = "unsupported input mode";
        }
        return std::nullopt;
    }
}

ParseReport AuthLogParser::parse_stream(std::istream& input) const {
    ParseReport result;
    result.metadata.input_mode = config_.input_mode;
    result.metadata.timezone_present = config_.input_mode == InputMode::JournalctlShortFull;
    if (config_.input_mode == InputMode::SyslogLegacy) {
        result.metadata.assume_year = config_.assumed_year;
    }
    std::unordered_map<std::string, std::size_t> unknown_pattern_counts;

    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        if (trim(line).empty()) {
            continue;
        }

        ++result.quality.total_lines;

        std::string error;
        auto event = parse_line(line, line_number, &error);
        if (event.has_value()) {
            result.events.push_back(std::move(*event));
            ++result.quality.parsed_lines;
            continue;
        }

        result.warnings.push_back(ParseWarning{line_number, error.empty() ? "unrecognized line" : error});
        ++result.quality.unparsed_lines;
        ++unknown_pattern_counts[extract_unknown_pattern_key(error.empty() ? "unrecognized line" : error)];
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
