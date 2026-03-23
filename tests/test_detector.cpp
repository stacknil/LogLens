#include "config.hpp"
#include "detector.hpp"
#include "parser.hpp"
#include "signal.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

const loglens::Finding* find_finding(const std::vector<loglens::Finding>& findings,
                                     loglens::FindingType type,
                                     const std::string& subject) {
    const auto it = std::find_if(findings.begin(), findings.end(), [&](const loglens::Finding& finding) {
        return finding.type == type && finding.subject == subject;
    });
    return it == findings.end() ? nullptr : &(*it);
}

const loglens::AuthSignal* find_signal(const std::vector<loglens::AuthSignal>& signals,
                                       loglens::AuthSignalKind signal_kind) {
    const auto it = std::find_if(signals.begin(), signals.end(), [&](const loglens::AuthSignal& signal) {
        return signal.signal_kind == signal_kind;
    });
    return it == signals.end() ? nullptr : &(*it);
}

std::size_t count_signals(const std::vector<loglens::AuthSignal>& signals,
                          loglens::AuthSignalKind signal_kind) {
    return static_cast<std::size_t>(std::count_if(signals.begin(), signals.end(), [&](const loglens::AuthSignal& signal) {
        return signal.signal_kind == signal_kind;
    }));
}

std::vector<loglens::Event> parse_events(loglens::ParserConfig config, std::string_view input_text) {
    const loglens::AuthLogParser parser(config);
    std::istringstream input(std::string{input_text});
    return parser.parse_stream(input).events;
}

loglens::ParserConfig make_syslog_config() {
    return loglens::ParserConfig{
        loglens::InputMode::SyslogLegacy,
        2026};
}

loglens::ParserConfig make_journalctl_config() {
    return loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt};
}

std::vector<loglens::Event> build_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed password for invalid user deploy from 203.0.113.10 port 51060 ssh2\n"
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:22:10 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -xe\n"
        "Mar 10 08:24:15 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/ssh/sshd_config\n");
}

std::vector<loglens::Event> build_publickey_bruteforce_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for root from 203.0.113.10 port 51060 ssh2\n");
}

std::vector<loglens::Event> build_publickey_success_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Accepted publickey for alice from 203.0.113.10 port 51060 ssh2: ED25519 SHA256:SANITIZEDKEY\n");
}

std::vector<loglens::Event> build_pam_bruteforce_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=root\n");
}

std::vector<loglens::Event> build_sudo_signal_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:21:05 example-host pam_unix(sudo:session): session opened for user root by alice(uid=0)\n"
        "Mar 10 08:21:10 example-host pam_unix(sshd:session): session closed for user alice\n");
}

std::vector<loglens::Event> build_sudo_burst_preservation_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:21:05 example-host pam_unix(sudo:session): session opened for user root by alice(uid=0)\n"
        "Mar 10 08:22:10 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -xe\n"
        "Mar 10 08:24:15 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/ssh/sshd_config\n");
}

void test_default_thresholds() {
    const auto events = build_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    expect(findings.size() == 3, "expected three findings");

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force != nullptr, "expected brute force finding");
    expect(brute_force->event_count == 5, "expected brute force count");

    const auto* multi_user = find_finding(findings, loglens::FindingType::MultiUserProbing, "203.0.113.10");
    expect(multi_user != nullptr, "expected multi-user finding");
    expect(multi_user->usernames.size() == 5, "expected five usernames");

    const auto* sudo = find_finding(findings, loglens::FindingType::SudoBurst, "alice");
    expect(sudo != nullptr, "expected sudo finding");
    expect(sudo->event_count == 3, "expected sudo count");
}

void test_custom_thresholds() {
    const auto events = build_events();
    loglens::DetectorConfig config;
    config.brute_force.threshold = 6;
    config.multi_user_probing.threshold = 6;
    config.sudo_burst.threshold = 4;

    const loglens::Detector detector(config);
    const auto findings = detector.analyze(events);
    expect(findings.empty(), "expected custom thresholds to suppress findings");
}

void test_auth_signal_defaults() {
    const auto events = parse_events(
        make_syslog_config(),
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for root from 203.0.113.10 port 51060 ssh2\n"
        "Mar 10 08:18:06 example-host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.11  user=alice\n");

    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);
    expect(signals.size() == 2, "expected two auth signals");

    const auto* publickey = find_signal(signals, loglens::AuthSignalKind::SshFailedPublicKey);
    expect(publickey != nullptr, "expected publickey signal");
    expect(publickey->counts_as_attempt_evidence, "expected publickey to count as attempt evidence");
    expect(publickey->counts_as_terminal_auth_failure, "expected publickey to count as terminal auth failure");

    const auto* pam = find_signal(signals, loglens::AuthSignalKind::PamAuthFailure);
    expect(pam != nullptr, "expected pam auth signal");
    expect(pam->counts_as_attempt_evidence, "expected pam auth failure to count as attempt evidence");
    expect(!pam->counts_as_terminal_auth_failure, "expected pam auth failure to stay non-terminal by default");
}

void test_failed_publickey_contributes_to_bruteforce_by_default() {
    const auto events = build_publickey_bruteforce_candidate_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force != nullptr, "expected publickey evidence to contribute to brute force");
    expect(brute_force->event_count == 5, "expected publickey evidence to raise brute force count to five");
}

void test_accepted_publickey_success_stays_out_of_failure_signals() {
    const auto events = build_publickey_success_candidate_events();
    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);

    expect(signals.size() == 4, "expected accepted publickey success to stay out of the signal layer");

    const loglens::Detector detector;
    const auto findings = detector.analyze(events);
    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force == nullptr,
           "expected accepted publickey success to stay out of brute-force counting");
}

void test_sudo_signals_include_command_and_session_opened() {
    const auto events = build_sudo_signal_candidate_events();
    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);

    expect(signals.size() == 2, "expected sudo command and supported sudo session-opened signals only");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoCommand) == 1,
           "expected one sudo command signal");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoSessionOpened) == 1,
           "expected one sudo session-opened signal");

    const auto* sudo_command = find_signal(signals, loglens::AuthSignalKind::SudoCommand);
    expect(sudo_command != nullptr, "expected sudo command signal");
    expect(sudo_command->counts_as_sudo_burst_evidence,
           "expected sudo command signal to count toward sudo burst evidence");
    expect(!sudo_command->counts_as_attempt_evidence, "did not expect sudo command to count as auth attempt evidence");
    expect(!sudo_command->counts_as_terminal_auth_failure,
           "did not expect sudo command to count as terminal auth failure");

    const auto* sudo_session = find_signal(signals, loglens::AuthSignalKind::SudoSessionOpened);
    expect(sudo_session != nullptr, "expected sudo session-opened signal");
    expect(!sudo_session->counts_as_sudo_burst_evidence,
           "expected sudo session-opened signal to stay out of sudo burst counting by default");
    expect(!sudo_session->counts_as_attempt_evidence,
           "did not expect sudo session-opened to count as auth attempt evidence");
    expect(!sudo_session->counts_as_terminal_auth_failure,
           "did not expect sudo session-opened to count as terminal auth failure");
}

void test_sudo_burst_behavior_is_preserved_with_signal_layer() {
    const auto events = build_sudo_burst_preservation_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* sudo = find_finding(findings, loglens::FindingType::SudoBurst, "alice");
    expect(sudo != nullptr, "expected sudo burst finding");
    expect(sudo->event_count == 3,
           "expected sudo burst count to remain based on command events rather than session-opened lines");
}

void test_unsupported_pam_session_close_remains_telemetry_only() {
    const loglens::AuthLogParser parser(make_syslog_config());
    std::istringstream input(
        "Mar 10 09:06:10 example-host pam_unix(sudo:session): session closed for user alice\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.empty(), "expected unsupported session-close line to stay out of parsed events");
    expect(result.warnings.size() == 1, "expected unsupported session-close line to produce one warning");
    expect(result.quality.top_unknown_patterns.size() == 1, "expected one unknown pattern bucket");
    expect(result.quality.top_unknown_patterns.front().pattern == "pam_unix_other",
           "expected unsupported session-close line to remain in pam_unix_other telemetry");

    const auto signals = loglens::build_auth_signals(result.events, loglens::DetectorConfig{}.auth_signal_mappings);
    expect(signals.empty(), "expected unsupported session-close line to stay out of the signal layer");
}

void test_pam_auth_failure_does_not_trigger_bruteforce_by_default() {
    const auto events = build_pam_bruteforce_candidate_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force == nullptr, "expected pam auth failure to stay out of brute force by default");
}

void test_equivalent_attack_scenario_yields_same_finding_count_across_modes() {
    const auto syslog_events = parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for invalid user deploy from 203.0.113.10 port 51060 ssh2\n");

    const auto journalctl_events = parse_events(
        make_journalctl_config(),
        "Tue 2026-03-10 08:11:22 UTC example-host sshd[2234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Tue 2026-03-10 08:12:05 UTC example-host sshd[2235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Tue 2026-03-10 08:13:10 UTC example-host sshd[2236]: Failed password for test from 203.0.113.10 port 51040 ssh\n"
        "Tue 2026-03-10 08:14:44 UTC example-host sshd[2237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Tue 2026-03-10 08:18:05 UTC example-host sshd[2238]: Failed publickey for invalid user deploy from 203.0.113.10 port 51060 ssh2\n");

    const loglens::Detector detector;
    const auto syslog_findings = detector.analyze(syslog_events);
    const auto journalctl_findings = detector.analyze(journalctl_events);

    expect(syslog_findings.size() == journalctl_findings.size(),
           "expected equivalent scenarios to yield the same finding count across modes");
    expect(find_finding(syslog_findings, loglens::FindingType::BruteForce, "203.0.113.10") != nullptr,
           "expected syslog brute force finding");
    expect(find_finding(journalctl_findings, loglens::FindingType::BruteForce, "203.0.113.10") != nullptr,
           "expected journalctl brute force finding");
}

void test_load_valid_config() {
    const auto temp_path = std::filesystem::current_path() / "valid_config_test.json";
    {
        std::ofstream output(temp_path);
        output << "{\n"
               << "  \"input_mode\": \"syslog_legacy\",\n"
               << "  \"timestamp\": { \"assume_year\": 2026 },\n"
               << "  \"brute_force\": { \"threshold\": 5, \"window_minutes\": 10 },\n"
               << "  \"multi_user_probing\": { \"threshold\": 3, \"window_minutes\": 15 },\n"
               << "  \"sudo_burst\": { \"threshold\": 3, \"window_minutes\": 5 },\n"
               << "  \"auth_signal_mappings\": {\n"
               << "    \"ssh_failed_password\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_invalid_user\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_failed_publickey\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"pam_auth_failure\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": false }\n"
               << "  }\n"
               << "}\n";
    }

    const auto config = loglens::load_app_config(temp_path);
    std::filesystem::remove(temp_path);

    expect(config.input_mode == loglens::InputMode::SyslogLegacy, "expected input mode from config");
    expect(config.timestamp.assume_year == 2026, "expected assume_year from config");
    expect(config.detector.brute_force.threshold == 5, "expected brute force threshold from config");
    expect(config.detector.auth_signal_mappings.ssh_failed_publickey.counts_as_terminal_auth_failure,
           "expected publickey mapping from config");
    expect(!config.detector.auth_signal_mappings.pam_auth_failure.counts_as_terminal_auth_failure,
           "expected pam auth mapping from config");

    const auto events = build_events();
    const loglens::Detector detector(config.detector);
    const auto findings = detector.analyze(events);
    expect(findings.size() == 3, "expected loaded config to preserve default findings");
}

void test_reject_invalid_config() {
    const auto temp_path = std::filesystem::current_path() / "invalid_config_test.json";
    {
        std::ofstream output(temp_path);
        output << "{\n"
               << "  \"input_mode\": \"syslog_legacy\",\n"
               << "  \"timestamp\": { \"assume_year\": \"bad\" },\n"
               << "  \"brute_force\": { \"threshold\": 5, \"window_minutes\": 10 },\n"
               << "  \"multi_user_probing\": { \"threshold\": 3, \"window_minutes\": 15 },\n"
               << "  \"sudo_burst\": { \"threshold\": 3, \"window_minutes\": 5 },\n"
               << "  \"auth_signal_mappings\": {\n"
               << "    \"ssh_failed_password\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_invalid_user\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_failed_publickey\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"pam_auth_failure\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": false }\n"
               << "  }\n"
               << "}\n";
    }

    bool threw = false;
    std::string message;
    try {
        static_cast<void>(loglens::load_app_config(temp_path));
    } catch (const std::runtime_error& error) {
        threw = true;
        message = error.what();
    }

    std::filesystem::remove(temp_path);
    expect(threw, "expected invalid config to be rejected");
    expect(message.find("assume_year") != std::string::npos,
           "expected invalid config error to mention assume_year");
}

}  // namespace

int main() {
    test_default_thresholds();
    test_custom_thresholds();
    test_auth_signal_defaults();
    test_failed_publickey_contributes_to_bruteforce_by_default();
    test_accepted_publickey_success_stays_out_of_failure_signals();
    test_sudo_signals_include_command_and_session_opened();
    test_sudo_burst_behavior_is_preserved_with_signal_layer();
    test_unsupported_pam_session_close_remains_telemetry_only();
    test_pam_auth_failure_does_not_trigger_bruteforce_by_default();
    test_equivalent_attack_scenario_yields_same_finding_count_across_modes();
    test_load_valid_config();
    test_reject_invalid_config();
    return 0;
}
