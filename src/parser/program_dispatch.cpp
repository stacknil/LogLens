#include "parser/program_dispatch.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/pam_handlers.hpp"
#include "parser/sshd_handlers.hpp"
#include "parser/su_handlers.hpp"
#include "parser/sudo_handlers.hpp"

#include <array>
#include <string_view>

namespace loglens::parser_internal {
namespace {

using ProgramMatcher = bool (*)(std::string_view program);
using ProgramHandler = HandlerResult (*)(const Event& source);

struct HandlerRegistration {
    ProgramMatcher matches;
    ProgramHandler handle;
};

bool is_sshd(std::string_view program) {
    return program == "sshd";
}

bool is_pam_unix(std::string_view program) {
    return program.starts_with("pam_unix(");
}

bool is_pam_faillock(std::string_view program) {
    return program.starts_with("pam_faillock(");
}

bool is_pam_sss(std::string_view program) {
    return program.starts_with("pam_sss(");
}

bool is_sudo(std::string_view program) {
    return program == "sudo";
}

bool is_su(std::string_view program) {
    return program == "su";
}

constexpr std::array<HandlerRegistration, 6> handler_registry{{
    {is_sshd, handle_sshd_event},
    {is_pam_unix, handle_pam_unix_event},
    {is_pam_faillock, handle_pam_faillock_event},
    {is_pam_sss, handle_pam_sss_event},
    {is_sudo, handle_sudo_event},
    {is_su, handle_su_event},
}};

}  // namespace

HandlerResult dispatch_program(const Event& source) {
    for (const auto& registration : handler_registry) {
        if (registration.matches(source.program)) {
            return registration.handle(source);
        }
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
