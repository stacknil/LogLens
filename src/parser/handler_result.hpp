#pragma once

#include "parser.hpp"

#include <optional>
#include <string>
#include <utility>

namespace loglens::parser_internal {

struct HandlerResult {
    bool matched = false;
    std::optional<Event> event;
    ParserFailureCategory failure_category = ParserFailureCategory::KnownProgramUnknownMessage;
    std::string reason;
};

inline HandlerResult matched_event(Event event) {
    return HandlerResult{true, std::move(event), ParserFailureCategory::KnownProgramUnknownMessage, {}};
}

inline HandlerResult failed_event(ParserFailureCategory category, std::string reason) {
    return HandlerResult{false, std::nullopt, category, std::move(reason)};
}

}  // namespace loglens::parser_internal
