#pragma once

#include "parser/handler_result.hpp"

#include <span>
#include <string_view>

namespace loglens::parser_internal {

using ProgramMatcher = bool (*)(std::string_view program);
using ProgramHandler = HandlerResult (*)(const Event& source);

struct ProgramHandlerRegistration {
    ProgramMatcher matches;
    ProgramHandler handle;
};

std::span<const ProgramHandlerRegistration> program_handler_registry();
HandlerResult dispatch_program(const Event& source);
HandlerResult dispatch_program(const Event& source,
                               std::span<const ProgramHandlerRegistration> registry);

}  // namespace loglens::parser_internal
