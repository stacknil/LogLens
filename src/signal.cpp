#include "signal.hpp"

#include <optional>

namespace loglens {
namespace {

struct SignalMapping {
    AuthSignalKind signal_kind = AuthSignalKind::Unknown;
    bool counts_as_attempt_evidence = false;
    bool counts_as_terminal_auth_failure = false;
    bool counts_as_sudo_burst_evidence = false;
};

std::optional<SignalMapping> signal_mapping_for_event(const Event& event, const AuthSignalConfig& config) {
    switch (event.event_type) {
    case EventType::SshFailedPassword:
        return SignalMapping{
            AuthSignalKind::SshFailedPassword,
            config.ssh_failed_password.counts_as_attempt_evidence,
            config.ssh_failed_password.counts_as_terminal_auth_failure,
            false};
    case EventType::SshInvalidUser:
        return SignalMapping{
            AuthSignalKind::SshInvalidUser,
            config.ssh_invalid_user.counts_as_attempt_evidence,
            config.ssh_invalid_user.counts_as_terminal_auth_failure,
            false};
    case EventType::SshFailedPublicKey:
        return SignalMapping{
            AuthSignalKind::SshFailedPublicKey,
            config.ssh_failed_publickey.counts_as_attempt_evidence,
            config.ssh_failed_publickey.counts_as_terminal_auth_failure,
            false};
    case EventType::PamAuthFailure:
        return SignalMapping{
            AuthSignalKind::PamAuthFailure,
            config.pam_auth_failure.counts_as_attempt_evidence,
            config.pam_auth_failure.counts_as_terminal_auth_failure,
            false};
    case EventType::SudoCommand:
        return SignalMapping{
            AuthSignalKind::SudoCommand,
            false,
            false,
            true};
    case EventType::SessionOpened:
        if (event.program == "pam_unix(sudo:session)") {
            return SignalMapping{
                AuthSignalKind::SudoSessionOpened,
                false,
                false,
                false};
        }
        return std::nullopt;
    case EventType::Unknown:
    case EventType::SshAcceptedPassword:
    default:
        return std::nullopt;
    }
}

}  // namespace

std::vector<AuthSignal> build_auth_signals(const std::vector<Event>& events, const AuthSignalConfig& config) {
    std::vector<AuthSignal> signals;
    signals.reserve(events.size());

    for (const auto& event : events) {
        const auto mapping = signal_mapping_for_event(event, config);
        if (!mapping.has_value()) {
            continue;
        }

        signals.push_back(AuthSignal{
            event.timestamp,
            event.source_ip,
            event.username,
            mapping->signal_kind,
            mapping->counts_as_attempt_evidence,
            mapping->counts_as_terminal_auth_failure,
            mapping->counts_as_sudo_burst_evidence,
            event.line_number});
    }

    return signals;
}

}  // namespace loglens
