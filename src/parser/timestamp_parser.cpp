#include "parser/timestamp_parser.hpp"

#include "parser/text_utils.hpp"

#include <array>
#include <cctype>
#include <chrono>
#include <optional>
#include <utility>

namespace loglens::parser_internal {
namespace {

struct ClockTime {
    int hour = 0;
    int minute = 0;
    int second = 0;
};

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

    if (token[8] != '.' || token.size() == 9) {
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

bool parse_calendar_date_parts(std::string_view token,
                               int& year_value,
                               unsigned& month_index,
                               int& day_value) {
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
        if (!parse_int(digits.substr(0, 2), parsed_hours)
            || !parse_int(digits.substr(2, 2), minutes_value)) {
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

HandlerResult parse_syslog_timestamp(const ParserConfig& config,
                                     std::string_view& remaining,
                                     std::size_t line_number) {
    if (!config.assumed_year.has_value()) {
        return failed_event(
            ParserFailureCategory::UnknownTimestamp,
            "syslog_legacy mode requires assume_year");
    }

    const auto month_token = consume_token(remaining);
    const auto day_token = consume_token(remaining);
    const auto time_token = consume_token(remaining);
    const auto hostname_token = consume_token(remaining);

    if (month_token.empty() || day_token.empty() || time_token.empty() || hostname_token.empty()) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "missing syslog header fields");
    }

    unsigned month_index = 0;
    int day_value = 0;
    ClockTime time;

    if (!parse_month(month_token, month_index)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid month token");
    }
    if (!parse_int(day_token, day_value)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid day token");
    }
    if (!parse_clock_token(time_token, time)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid time token");
    }

    const auto timestamp = build_timestamp(*config.assumed_year, month_index, day_value, time);
    if (!timestamp.has_value()) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid calendar date");
    }

    Event event;
    event.timestamp = *timestamp;
    event.hostname.assign(hostname_token);
    event.line_number = line_number;
    return matched_event(std::move(event));
}

HandlerResult parse_journalctl_timestamp(std::string_view& remaining, std::size_t line_number) {
    const auto weekday_token = consume_token(remaining);
    const auto date_token = consume_token(remaining);
    const auto time_token = consume_token(remaining);
    const auto timezone_token = consume_token(remaining);
    const auto hostname_token = consume_token(remaining);

    if (weekday_token.empty() || date_token.empty() || time_token.empty()
        || timezone_token.empty() || hostname_token.empty()) {
        return failed_event(
            ParserFailureCategory::UnknownTimestamp,
            "missing journalctl short-full header fields");
    }

    int year_value = 0;
    unsigned month_index = 0;
    int day_value = 0;
    ClockTime time;
    std::chrono::minutes timezone_offset{0};

    if (!parse_calendar_date_parts(date_token, year_value, month_index, day_value)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid journalctl date token");
    }
    if (!parse_clock_token(time_token, time)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid time token");
    }
    if (!parse_timezone_token(timezone_token, timezone_offset)) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid timezone token");
    }

    const auto timestamp = build_timestamp(year_value, month_index, day_value, time, timezone_offset);
    if (!timestamp.has_value()) {
        return failed_event(ParserFailureCategory::UnknownTimestamp, "invalid calendar date");
    }

    Event event;
    event.timestamp = *timestamp;
    event.hostname.assign(hostname_token);
    event.line_number = line_number;
    return matched_event(std::move(event));
}

}  // namespace

HandlerResult parse_timestamp_and_hostname(const ParserConfig& config,
                                           std::string_view& remaining,
                                           std::size_t line_number) {
    switch (config.input_mode) {
    case InputMode::SyslogLegacy:
        return parse_syslog_timestamp(config, remaining, line_number);
    case InputMode::JournalctlShortFull:
        return parse_journalctl_timestamp(remaining, line_number);
    default:
        return failed_event(ParserFailureCategory::UnknownProgram, "unsupported input mode");
    }
}

}  // namespace loglens::parser_internal
