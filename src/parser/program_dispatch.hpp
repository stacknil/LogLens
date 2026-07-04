#pragma once

#include "parser/handler_result.hpp"

namespace loglens::parser_internal {

HandlerResult dispatch_program(const Event& source);

}  // namespace loglens::parser_internal
