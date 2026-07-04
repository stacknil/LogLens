#pragma once

#include "parser/handler_result.hpp"

namespace loglens::parser_internal {

HandlerResult handle_pam_unix_event(const Event& source);
HandlerResult handle_pam_faillock_event(const Event& source);
HandlerResult handle_pam_sss_event(const Event& source);

}  // namespace loglens::parser_internal
