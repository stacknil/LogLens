#pragma once

#include "parser/handler_result.hpp"

namespace loglens::parser_internal {

HandlerResult handle_sudo_event(const Event& source);

}  // namespace loglens::parser_internal
