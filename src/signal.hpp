#pragma once

#include "event.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace loglens {

enum class AuthSignalKind {
    Unknown,
    SshFailedPassword,
    SshInvalidUser,
    SshFailedPublicKey,
    PamAuthFailure
};

struct AuthSignalBehavior {
    bool counts_as_attempt_evidence = false;
    bool counts_as_terminal_auth_failure = false;
};

struct AuthSignalConfig {
    AuthSignalBehavior ssh_failed_password{true, true};
    AuthSignalBehavior ssh_invalid_user{true, true};
    AuthSignalBehavior ssh_failed_publickey{true, true};
    AuthSignalBehavior pam_auth_failure{true, false};
};

struct AuthSignal {
    std::chrono::sys_seconds timestamp{};
    std::string source_ip;
    std::string username;
    AuthSignalKind signal_kind = AuthSignalKind::Unknown;
    bool counts_as_attempt_evidence = false;
    bool counts_as_terminal_auth_failure = false;
    std::size_t line_number = 0;
};

std::vector<AuthSignal> build_auth_signals(const std::vector<Event>& events, const AuthSignalConfig& config);

}  // namespace loglens
