#pragma once

#include "parser/handler_result.hpp"

#include <cstddef>
#include <string_view>

namespace loglens::parser_internal {

HandlerResult parse_source_envelope(const ParserConfig& config,
                                    std::string_view line,
                                    std::size_t line_number);

}  // namespace loglens::parser_internal
