#include "parser.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string line_for(std::string_view month, std::string_view day) {
    return std::string(month) + " " + std::string(day)
        + " 08:30:00 example-host sshd[4200]: Failed password for user-a"
          " from 203.0.113.10 port 50101 ssh2";
}

std::size_t checked = 0;

void check_day(const loglens::AuthLogParser& parser, std::string_view month,
               std::string_view token, int year, unsigned month_number,
               int expected_day, std::string_view failure = "invalid calendar date") {
    std::string reason = "stale reason";
    auto category = loglens::ParserFailureCategory::MalformedSourceIp;
    const auto event = parser.parse_line(line_for(month, token), 17, &reason, &category);
    ++checked;
    // Do not construct chrono::day from the adversarial token in the oracle.
    if (expected_day == 0) {
        expect(!event, "invalid day accepted at case " + std::to_string(checked));
        expect(category == loglens::ParserFailureCategory::UnknownTimestamp,
               "invalid day must remain timestamp telemetry");
        expect(reason == failure, "unexpected timestamp failure reason");
        return;
    }
    expect(event.has_value(), "valid day rejected");
    const auto expected = std::chrono::sys_days{
        std::chrono::year{year} / std::chrono::month{month_number}
        / std::chrono::day{static_cast<unsigned>(expected_day)}}
        + std::chrono::hours{8} + std::chrono::minutes{30};
    expect(event->timestamp == expected, "valid day changed timestamp");
    expect(event->line_number == 17 && reason.empty(), "result metadata changed");
}

void test_day_domain() {
    const loglens::AuthLogParser parser({loglens::InputMode::SyslogLegacy, 2026});
    // Put the minimal positive wrap witness first for a useful baseline failure.
    check_day(parser, "Mar", "257", 2026, 3, 0);
    for (int day = -1024; day <= 1024; ++day) {
        check_day(parser, "Mar", std::to_string(day), 2026, 3,
                  day >= 1 && day <= 31 ? day : 0);
    }
    // Adding storage-width multiples must never alias a valid calendar day.
    for (const int shift : {-65536, -256, 256, 65536}) {
        for (int day = 1; day <= 31; ++day) {
            check_day(parser, "Mar", std::to_string(day + shift), 2026, 3, 0);
        }
    }
    for (const auto& token : std::array<std::string, 8>{
             "2147483647", "-2147483648", "2147483648", "-2147483649",
             "1x", std::string("1\0", 2), std::string("1\xff", 2), std::string(4096, '9')}) {
        const bool fits_int = token == "2147483647" || token == "-2147483648";
        check_day(parser, "Mar", token, 2026, 3, 0,
                  fits_int ? "invalid calendar date" : "invalid day token");
    }
    check_day(parser, "Mar", "01", 2026, 3, 1);
}

void test_calendar_controls() {
    constexpr std::array<std::string_view, 12> months{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    constexpr std::array<int, 12> lengths{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (const int year : {2024, 2026}) {
        const loglens::AuthLogParser parser({loglens::InputMode::SyslogLegacy, year});
        for (std::size_t month = 0; month < months.size(); ++month) {
            const int last = lengths[month] + (month == 1 && year == 2024 ? 1 : 0);
            for (int day = 1; day <= 31; ++day) {
                check_day(parser, months[month], std::to_string(day), year,
                          static_cast<unsigned>(month + 1), day <= last ? day : 0);
            }
        }
    }
}

void test_stream_recovery() {
    const loglens::AuthLogParser parser({loglens::InputMode::SyslogLegacy, 2026});
    std::istringstream input(line_for("Mar", "1") + '\n' + line_for("Mar", "257")
                             + '\n' + line_for("Mar", "2") + '\n');
    const auto report = parser.parse_stream(input);
    expect(report.events.size() == 2 && report.warnings.size() == 1,
           "invalid day must be a warning between two valid events");
    expect(report.events[0].line_number == 1 && report.events[1].line_number == 3
           && report.warnings[0].line_number == 2, "stream provenance changed");
    expect(report.warnings[0].category == loglens::ParserFailureCategory::UnknownTimestamp
           && report.warnings[0].reason == "invalid calendar date", "warning taxonomy changed");
    expect(report.quality.total_lines == 3 && report.quality.parsed_lines == 2
           && report.quality.unparsed_lines == 1, "stream accounting changed");
}

}  // namespace

int main() {
    try {
        test_day_domain();
        test_calendar_controls();
        test_stream_recovery();
        std::cout << checked << " day-token cases and one three-line recovery stream passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
