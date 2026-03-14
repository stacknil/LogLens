#include "signal.hpp"

namespace loglens {
namespace {

AuthSignalKind signal_kind_for_event_type(EventType type) {
    switch (type) {
    case EventType::SshFailedPassword:
        return AuthSignalKind::SshFailedPassword;
    case EventType::SshInvalidUser:
        return AuthSignalKind::SshInvalidUser;
    case EventType::SshFailedPublicKey:
        return AuthSignalKind::SshFailedPublicKey;
    case EventType::PamAuthFailure:
        return AuthSignalKind::PamAuthFailure;
    case EventType::Unknown:
    case EventType::SshAcceptedPassword:
    case EventType::SessionOpened:
    case EventType::SudoCommand:
    default:
        return AuthSignalKind::Unknown;
    }
}

const AuthSignalBehavior* behavior_for_event_type(EventType type, const AuthSignalConfig& config) {
    switch (type) {
    case EventType::SshFailedPassword:
        return &config.ssh_failed_password;
    case EventType::SshInvalidUser:
        return &config.ssh_invalid_user;
    case EventType::SshFailedPublicKey:
        return &config.ssh_failed_publickey;
    case EventType::PamAuthFailure:
        return &config.pam_auth_failure;
    case EventType::Unknown:
    case EventType::SshAcceptedPassword:
    case EventType::SessionOpened:
    case EventType::SudoCommand:
    default:
        return nullptr;
    }
}

}  // namespace

std::vector<AuthSignal> build_auth_signals(const std::vector<Event>& events, const AuthSignalConfig& config) {
    std::vector<AuthSignal> signals;
    signals.reserve(events.size());

    for (const auto& event : events) {
        const auto* behavior = behavior_for_event_type(event.event_type, config);
        if (behavior == nullptr) {
            continue;
        }

        signals.push_back(AuthSignal{
            event.timestamp,
            event.source_ip,
            event.username,
            signal_kind_for_event_type(event.event_type),
            behavior->counts_as_attempt_evidence,
            behavior->counts_as_terminal_auth_failure,
            event.line_number});
    }

    return signals;
}

}  // namespace loglens
