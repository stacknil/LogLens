#include "parser.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>

namespace {

void enforce_result_invariants(const std::optional<loglens::Event>& event,
                               const std::string& reason) {
    if (event.has_value()) {
        if (event->event_type == loglens::EventType::Unknown || event->program.empty()) {
            std::abort();
        }
        return;
    }

    if (reason.empty()) {
        std::abort();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string line(reinterpret_cast<const char*>(data), size);
    const std::array<loglens::AuthLogParser, 2> parsers{{
        loglens::AuthLogParser(loglens::ParserConfig{
            loglens::InputMode::SyslogLegacy,
            2026}),
        loglens::AuthLogParser(loglens::ParserConfig{
            loglens::InputMode::JournalctlShortFull,
            std::nullopt}),
    }};

    for (const auto& parser : parsers) {
        std::string reason;
        auto category = loglens::ParserFailureCategory::KnownProgramUnknownMessage;
        const auto event = parser.parse_line(line, 1, &reason, &category);
        enforce_result_invariants(event, reason);
    }

    return 0;
}
