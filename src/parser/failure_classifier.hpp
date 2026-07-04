#pragma once

#include "parser/handler_result.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace loglens::parser_internal {

std::optional<HandlerResult> classify_source_ip_failure(const Event& event);
HandlerResult classify_unrecognized_event(const Event& event);
std::string extract_unknown_pattern_key(std::string_view error);

}  // namespace loglens::parser_internal
