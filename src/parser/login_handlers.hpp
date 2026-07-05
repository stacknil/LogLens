#pragma once

#include "parser/handler_result.hpp"

namespace loglens::parser_internal {

HandlerResult handle_login_event(const Event& source);

}  // namespace loglens::parser_internal
