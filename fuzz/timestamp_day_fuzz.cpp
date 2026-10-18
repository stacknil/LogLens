#include "parser.hpp"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // The corpus mutates one token, not the surrounding source envelope.
    if (size == 0) {
        return 0;
    }
    const std::string_view token(reinterpret_cast<const char*>(data), size);
    if (token.find_first_of(" \t\r\n\f\v") != std::string_view::npos) {
        return 0;
    }
    int day = 0;
    const auto converted = std::from_chars(token.data(), token.data() + token.size(), day);
    const bool valid = converted.ec == std::errc{}
        && converted.ptr == token.data() + token.size() && day >= 1 && day <= 31;
    const std::string line = "Mar " + std::string(token)
        + " 08:30:00 example-host sshd[4200]: Failed password for user-a"
          " from 203.0.113.10 port 50101 ssh2";
    const loglens::AuthLogParser parser({loglens::InputMode::SyslogLegacy, 2026});
    std::string reason;
    auto category = loglens::ParserFailureCategory::MalformedSourceIp;
    const auto event = parser.parse_line(line, 1, &reason, &category);
    if (event.has_value() != valid) {
        std::abort();
    }
    if (!valid) {
        if (reason.empty() || category != loglens::ParserFailureCategory::UnknownTimestamp) {
            std::abort();
        }
        return 0;
    }
    // Only range-checked values reach chrono in the oracle.
    const auto expected = std::chrono::sys_days{
        std::chrono::year{2026} / std::chrono::March
        / std::chrono::day{static_cast<unsigned>(day)}}
        + std::chrono::hours{8} + std::chrono::minutes{30};
    if (event->timestamp != expected || !reason.empty()) {
        std::abort();
    }
    return 0;
}
