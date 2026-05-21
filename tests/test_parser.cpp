#include "parser.hpp"

#include <cmath>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

loglens::AuthLogParser make_syslog_parser() {
    return loglens::AuthLogParser(loglens::ParserConfig{
        loglens::InputMode::SyslogLegacy,
        2026});
}

loglens::AuthLogParser make_journalctl_parser() {
    return loglens::AuthLogParser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
}

std::filesystem::path repo_root() {
    const std::filesystem::path source_path{__FILE__};
    std::vector<std::filesystem::path> candidates;

    if (source_path.is_absolute()) {
        candidates.push_back(source_path);
    } else {
        const auto cwd = std::filesystem::current_path();
        candidates.push_back(cwd / source_path);
        candidates.push_back(cwd.parent_path() / source_path);
    }

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate.parent_path().parent_path();
        }
    }

    throw std::runtime_error("unable to resolve repository root from test source path");
}

std::filesystem::path asset_path(std::string_view filename) {
    return repo_root() / "assets" / std::string(filename);
}

void expect_close(double actual, double expected, double tolerance, const std::string& message) {
    if (std::fabs(actual - expected) > tolerance) {
        throw std::runtime_error(message);
    }
}

void test_invalid_user_failure() {
    const auto parser = make_syslog_parser();
    std::string error;
    const auto event = parser.parse_line(
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2",
        1,
        &error);

    expect(event.has_value(), "expected invalid-user failure event");
    expect(error.empty(), "expected empty parse error");
    expect(event->program == "sshd", "expected sshd program");
    expect(event->pid.has_value() && *event->pid == 1234, "expected parsed pid");
    expect(event->hostname == "example-host", "expected hostname");
    expect(event->username == "admin", "expected parsed username");
    expect(event->source_ip == "203.0.113.10", "expected parsed source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser, "expected invalid user type");
    expect(loglens::format_timestamp(event->timestamp) == "2026-03-10 08:11:22",
           "expected explicit syslog year injection");
}

void test_standard_failure() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2",
        2);

    expect(event.has_value(), "expected failed password event");
    expect(event->username == "root", "expected root username");
    expect(event->event_type == loglens::EventType::SshFailedPassword, "expected ssh failure type");
}

void test_success_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:20:10 example-host sshd[1240]: Accepted password for alice from 203.0.113.20 port 51111 ssh2",
        3);

    expect(event.has_value(), "expected accepted password event");
    expect(event->username == "alice", "expected alice username");
    expect(event->source_ip == "203.0.113.20", "expected alice source ip");
    expect(event->event_type == loglens::EventType::SshAcceptedPassword, "expected ssh success type");
}

void test_accepted_publickey_success_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 11 10:00:01 example-host sshd[2100]: Accepted publickey for alice from 203.0.113.70 port 53000 ssh2: ED25519 SHA256:SANITIZEDKEY",
        4);

    expect(event.has_value(), "expected accepted publickey event");
    expect(event->username == "alice", "expected accepted publickey username");
    expect(event->source_ip == "203.0.113.70", "expected accepted publickey source ip");
    expect(event->event_type == loglens::EventType::SshAcceptedPublicKey,
           "expected accepted publickey event type");
}

void test_accepted_keyboard_interactive_success_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 11 10:00:08 example-host sshd[2103]: Accepted keyboard-interactive/pam for dave from 203.0.113.76 port 53003 ssh2",
        4);

    expect(event.has_value(), "expected accepted keyboard-interactive event");
    expect(event->username == "dave", "expected accepted keyboard-interactive username");
    expect(event->source_ip == "203.0.113.76", "expected accepted keyboard-interactive source ip");
    expect(event->event_type == loglens::EventType::SshAcceptedKeyboardInteractive,
           "expected accepted keyboard-interactive event type");
}

void test_sudo_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh",
        4);

    expect(event.has_value(), "expected sudo event");
    expect(event->program == "sudo", "expected sudo program");
    expect(event->username == "alice", "expected sudo username");
    expect(event->event_type == loglens::EventType::SudoCommand, "expected sudo event type");
}

void test_sudo_auth_failure_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:21:40 example-host sudo[1241]:    alice : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        4);

    expect(event.has_value(), "expected sudo auth failure event");
    expect(event->program == "sudo", "expected sudo failure program");
    expect(event->pid.has_value() && *event->pid == 1241, "expected sudo failure pid");
    expect(event->username == "alice", "expected sudo failure actor username");
    expect(event->event_type == loglens::EventType::SudoAuthFailure, "expected sudo auth failure type");
}

void test_sudo_policy_denied_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:21:55 example-host sudo[1242]:    bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id",
        4);

    expect(event.has_value(), "expected sudo policy denied event");
    expect(event->program == "sudo", "expected sudo policy program");
    expect(event->username == "bob", "expected sudo policy actor username");
    expect(event->event_type == loglens::EventType::SudoPolicyDenied, "expected sudo policy denied type");
}

void test_su_auth_failure_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:23:01 example-host su[1243]: FAILED SU (to root) carol on pts/1",
        4);

    expect(event.has_value(), "expected su auth failure event");
    expect(event->program == "su", "expected su failure program");
    expect(event->username == "carol", "expected su failure actor username");
    expect(event->event_type == loglens::EventType::SuAuthFailure, "expected su auth failure type");
}

void test_su_success_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:23:25 example-host su[1244]: Successful su for root by dave",
        4);

    expect(event.has_value(), "expected su success event");
    expect(event->program == "su", "expected su success program");
    expect(event->username == "dave", "expected su success actor username");
    expect(event->event_type == loglens::EventType::SessionOpened, "expected su success session-opened type");
}

void test_failed_publickey_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:10 example-host sshd[1243]: Failed publickey for invalid user svc-backup from 203.0.113.40 port 51240 ssh2",
        5);

    expect(event.has_value(), "expected failed publickey event");
    expect(event->username == "svc-backup", "expected parsed publickey username");
    expect(event->source_ip == "203.0.113.40", "expected parsed publickey source ip");
    expect(event->event_type == loglens::EventType::SshFailedPublicKey, "expected ssh publickey type");
}

void test_failed_keyboard_interactive_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:18 example-host sshd[1244]: Failed keyboard-interactive/pam for eve from 203.0.113.77 port 51241 ssh2",
        5);

    expect(event.has_value(), "expected failed keyboard-interactive event");
    expect(event->username == "eve", "expected parsed keyboard-interactive username");
    expect(event->source_ip == "203.0.113.77", "expected parsed keyboard-interactive source ip");
    expect(event->event_type == loglens::EventType::SshFailedKeyboardInteractive,
           "expected ssh keyboard-interactive failure type");
}

void test_max_auth_tries_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:25 example-host sshd[1245]: maximum authentication attempts exceeded for frank from 203.0.113.78 port 51242 ssh2 [preauth]",
        5);

    expect(event.has_value(), "expected max-auth-tries event");
    expect(event->username == "frank", "expected parsed max-auth-tries username");
    expect(event->source_ip == "203.0.113.78", "expected parsed max-auth-tries source ip");
    expect(event->event_type == loglens::EventType::SshMaxAuthTries,
           "expected ssh max-auth-tries failure type");
}

void test_pam_auth_failure_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:28:33 example-host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.41  user=alice",
        6);

    expect(event.has_value(), "expected pam auth failure event");
    expect(event->program == "pam_unix(sshd:auth)", "expected pam_unix auth program");
    expect(event->username == "alice", "expected pam auth username");
    expect(event->source_ip == "203.0.113.41", "expected pam auth source ip");
    expect(event->event_type == loglens::EventType::PamAuthFailure, "expected pam auth failure type");
}

void test_pam_sss_received_failure_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 11 10:02:25 example-host pam_sss(sshd:auth): received for user dave: 7 (Authentication failure)",
        7);

    expect(event.has_value(), "expected pam_sss received failure event");
    expect(event->program == "pam_sss(sshd:auth)", "expected pam_sss auth program");
    expect(event->username == "dave", "expected pam_sss username");
    expect(event->source_ip.empty(), "expected pam_sss received failure to stay source-less");
    expect(event->event_type == loglens::EventType::PamAuthFailure, "expected pam_sss failure type");
}

void test_session_opened_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:29:50 example-host pam_unix(sudo:session): session opened for user root by alice(uid=0)",
        7);

    expect(event.has_value(), "expected session opened event");
    expect(event->program == "pam_unix(sudo:session)", "expected pam_unix session program");
    expect(event->username == "alice", "expected session actor username");
    expect(event->source_ip.empty(), "expected session opened to have no source ip");
    expect(event->event_type == loglens::EventType::SessionOpened, "expected session opened type");
}

void test_journalctl_short_full_event() {
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
    const auto event = parser.parse_line(
        "Tue 2026-03-10 08:11:22 UTC example-host sshd[2234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2",
        8);

    expect(event.has_value(), "expected journalctl short-full event");
    expect(event->hostname == "example-host", "expected journalctl hostname");
    expect(event->username == "admin", "expected journalctl username");
    expect(event->event_type == loglens::EventType::SshInvalidUser, "expected journalctl event classification");
    expect(loglens::format_timestamp(event->timestamp) == "2026-03-10 08:11:22",
           "expected journalctl timestamp to preserve embedded year and timezone");
}

void test_input_mode_aliases() {
    expect(loglens::parse_input_mode("syslog") == loglens::InputMode::SyslogLegacy,
           "expected syslog mode alias");
    expect(loglens::parse_input_mode("syslog-legacy") == loglens::InputMode::SyslogLegacy,
           "expected syslog-legacy mode alias");
    expect(loglens::parse_input_mode("syslog_legacy") == loglens::InputMode::SyslogLegacy,
           "expected syslog_legacy mode alias");
    expect(loglens::parse_input_mode("journalctl") == loglens::InputMode::JournalctlShortFull,
           "expected journalctl mode alias");
    expect(loglens::parse_input_mode("journalctl-short-full") == loglens::InputMode::JournalctlShortFull,
           "expected journalctl-short-full mode alias");
    expect(loglens::parse_input_mode("journalctl_short_full") == loglens::InputMode::JournalctlShortFull,
           "expected journalctl_short_full mode alias");
    expect(!loglens::parse_input_mode("unknown").has_value(), "expected unknown mode to be rejected");
}

void test_syslog_auth_family_fixture_file() {
    const auto parser = make_syslog_parser();
    const auto result = parser.parse_file(asset_path("parser_auth_families_syslog.log"));

    expect(result.events.size() == 8, "expected eight recognized syslog auth-family events");
    expect(result.warnings.size() == 5, "expected five syslog auth-family warnings");
    expect(result.quality.total_lines == 13, "expected thirteen syslog auth-family lines");
    expect(result.quality.parsed_lines == 8, "expected eight parsed syslog auth-family lines");
    expect(result.quality.unparsed_lines == 5, "expected five unparsed syslog auth-family lines");
    expect_close(result.quality.parse_success_rate, 8.0 / 13.0, 1e-9,
                 "expected syslog auth-family parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshAcceptedPublicKey,
           "expected accepted publickey auth-family event");
    expect(result.events[0].source_ip == "203.0.113.70", "expected accepted publickey source ip");
    expect(result.events[1].event_type == loglens::EventType::SshAcceptedPassword,
           "expected accepted password auth-family event");
    expect(result.events[1].username == "bob", "expected accepted password username");
    expect(result.events[2].event_type == loglens::EventType::SshFailedPublicKey,
           "expected failed publickey auth-family event");
    expect(result.events[2].username == "svc-deploy", "expected failed publickey username");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_faillock preauth auth-family event");
    expect(result.events[3].username == "alice", "expected pam_faillock preauth username");
    expect(result.events[3].source_ip == "203.0.113.71", "expected pam_faillock preauth source ip");
    expect(result.events[4].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_faillock authfail auth-family event");
    expect(result.events[4].username == "bob", "expected pam_faillock authfail username");
    expect(result.events[4].source_ip == "203.0.113.72", "expected pam_faillock authfail source ip");
    expect(result.events[5].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_unix auth-family event");
    expect(result.events[5].username == "carol", "expected pam_unix auth-family username");
    expect(result.events[5].source_ip == "203.0.113.75", "expected pam_unix auth-family source ip");
    expect(result.events[6].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_sss failure auth-family event");
    expect(result.events[6].username == "dave", "expected pam_sss failure username");
    expect(result.events[6].source_ip.empty(), "expected pam_sss failure fixture to stay source-less");
    expect(result.events[7].event_type == loglens::EventType::SessionOpened,
           "expected pam_unix session-opened auth-family event");
    expect(result.events[7].username == "erin", "expected pam_unix session-opened username");

    expect(result.quality.top_unknown_patterns.size() == 5, "expected five syslog auth-family buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "pam_faillock_authsucc",
           "expected pam_faillock authsucc telemetry bucket");
    expect(result.quality.top_unknown_patterns[0].count == 1, "expected one pam_faillock authsucc line");
    expect(result.quality.top_unknown_patterns[1].pattern == "pam_faillock_other",
           "expected pam_faillock other telemetry bucket");
    expect(result.quality.top_unknown_patterns[1].count == 1, "expected one pam_faillock other line");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_sss_authinfo_unavail",
           "expected pam_sss authinfo-unavail telemetry bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one pam_sss authinfo-unavail line");
    expect(result.quality.top_unknown_patterns[3].pattern == "pam_sss_unknown_user",
           "expected pam_sss unknown-user telemetry bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one pam_sss unknown-user line");
    expect(result.quality.top_unknown_patterns[4].pattern == "pam_unix_other",
           "expected pam_unix other telemetry bucket");
    expect(result.quality.top_unknown_patterns[4].count == 1, "expected one pam_unix other line");
}

void test_journalctl_auth_family_fixture_file() {
    const auto parser = make_journalctl_parser();
    const auto result = parser.parse_file(asset_path("parser_auth_families_journalctl_short_full.log"));

    expect(result.events.size() == 8, "expected eight recognized journalctl auth-family events");
    expect(result.warnings.size() == 5, "expected five journalctl auth-family warnings");
    expect(result.quality.total_lines == 13, "expected thirteen journalctl auth-family lines");
    expect(result.quality.parsed_lines == 8, "expected eight parsed journalctl auth-family lines");
    expect(result.quality.unparsed_lines == 5, "expected five unparsed journalctl auth-family lines");
    expect_close(result.quality.parse_success_rate, 8.0 / 13.0, 1e-9,
                 "expected journalctl auth-family parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshAcceptedPublicKey,
           "expected journalctl accepted publickey auth-family event");
    expect(result.events[0].source_ip == "203.0.113.70", "expected journalctl accepted publickey source ip");
    expect(result.events[1].event_type == loglens::EventType::SshAcceptedPassword,
           "expected journalctl accepted password auth-family event");
    expect(result.events[2].event_type == loglens::EventType::SshFailedPublicKey,
           "expected journalctl failed publickey auth-family event");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_faillock preauth auth-family event");
    expect(result.events[4].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_faillock authfail auth-family event");
    expect(result.events[5].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_unix auth-family event");
    expect(result.events[6].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_sss failure auth-family event");
    expect(result.events[6].source_ip.empty(), "expected journalctl pam_sss failure fixture to stay source-less");
    expect(result.events[7].event_type == loglens::EventType::SessionOpened,
           "expected journalctl pam_unix session-opened auth-family event");

    expect(result.quality.top_unknown_patterns.size() == 5, "expected five journalctl auth-family buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "pam_faillock_authsucc",
           "expected journalctl pam_faillock authsucc telemetry bucket");
    expect(result.quality.top_unknown_patterns[0].count == 1, "expected one journalctl pam_faillock authsucc line");
    expect(result.quality.top_unknown_patterns[1].pattern == "pam_faillock_other",
           "expected journalctl pam_faillock other telemetry bucket");
    expect(result.quality.top_unknown_patterns[1].count == 1, "expected one journalctl pam_faillock other line");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_sss_authinfo_unavail",
           "expected journalctl pam_sss authinfo-unavail telemetry bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one journalctl pam_sss authinfo-unavail line");
    expect(result.quality.top_unknown_patterns[3].pattern == "pam_sss_unknown_user",
           "expected journalctl pam_sss unknown-user telemetry bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one journalctl pam_sss unknown-user line");
    expect(result.quality.top_unknown_patterns[4].pattern == "pam_unix_other",
           "expected journalctl pam_unix other telemetry bucket");
    expect(result.quality.top_unknown_patterns[4].count == 1, "expected one journalctl pam_unix other line");
}

void test_malformed_line() {
    const auto parser = make_syslog_parser();
    std::string error;
    const auto event = parser.parse_line("malformed log line without syslog header", 9, &error);

    expect(!event.has_value(), "expected malformed line to fail");
    expect(!error.empty(), "expected parse error for malformed line");
}

void test_unknown_auth_patterns_are_warnings_only() {
    const auto parser = make_syslog_parser();
    std::istringstream input(
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed publickey for invalid user svc-backup from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Connection closed by authenticating user alice 203.0.113.50 port 51290 [preauth]\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Timeout, client not responding from 203.0.113.51 port 51291\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.size() == 2, "expected only recognized lines to become events");
    expect(result.warnings.size() == 2, "expected unknown auth patterns to become warnings");
    expect(result.quality.total_lines == 4, "expected total analyzed line count");
    expect(result.quality.parsed_lines == 2, "expected parsed line count");
    expect(result.quality.unparsed_lines == 2, "expected unparsed line count");
    expect(result.quality.parse_success_rate == 0.5, "expected parse success rate");
    expect(result.quality.top_unknown_patterns.size() == 2, "expected two unknown pattern buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection close pattern");
    expect(result.quality.top_unknown_patterns[0].count == 1, "expected preauth connection close count");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection pattern");
    expect(result.quality.top_unknown_patterns[1].count == 1, "expected timeout/disconnection count");
}

void test_stream_warnings_and_metadata() {
    const auto parser = make_syslog_parser();
    std::istringstream input(
        "Mar 10 08:20:10 example-host sshd[1240]: Accepted password for alice from 203.0.113.20 port 51111 ssh2\n"
        "bad-line\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.size() == 1, "expected one parsed event");
    expect(result.warnings.size() == 1, "expected one warning");
    expect(result.warnings.front().line_number == 2, "expected warning line number");
    expect(result.metadata.input_mode == loglens::InputMode::SyslogLegacy, "expected syslog metadata mode");
    expect(result.metadata.assume_year == 2026, "expected syslog metadata year");
    expect(!result.metadata.timezone_present, "expected syslog metadata timezone flag");
    expect(result.quality.total_lines == 2, "expected total line count");
    expect(result.quality.parsed_lines == 1, "expected parsed line count");
    expect(result.quality.unparsed_lines == 1, "expected unparsed line count");
    expect(result.quality.parse_success_rate == 0.5, "expected parse success rate");
    expect(result.quality.top_unknown_patterns.size() == 1, "expected one unknown pattern");
    expect(result.quality.top_unknown_patterns.front().pattern == "missing_syslog_header_fields",
           "expected normalized structural parse failure pattern");
}

void test_stream_tracks_skipped_blank_lines() {
    const auto parser = make_syslog_parser();
    std::istringstream input(
        "\n"
        "   \t\n"
        "Mar 10 08:20:10 example-host sshd[1240]: Accepted password for alice from 203.0.113.20 port 51111 ssh2\n");

    const auto result = parser.parse_stream(input);

    expect(result.events.size() == 1, "expected one parsed event after blank lines");
    expect(result.warnings.empty(), "did not expect warnings for skipped blank lines");
    expect(result.quality.skipped_blank_lines == 2, "expected two skipped blank lines");
    expect(result.quality.total_lines == 1, "expected total_lines to keep counting analyzed nonblank lines");
    expect(result.quality.parsed_lines == 1, "expected parsed line count to ignore blank lines");
    expect(result.quality.unparsed_lines == 0, "expected unparsed line count to ignore blank lines");
    expect(result.quality.parse_success_rate == 1.0, "expected parse success rate to ignore blank lines");
}

void test_journalctl_metadata() {
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
    std::istringstream input(
        "Tue 2026-03-10 08:20:10 UTC example-host sshd[2240]: Accepted password for alice from 203.0.113.20 port 51111 ssh2\n"
        "bad-line\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.size() == 1, "expected one parsed journalctl event");
    expect(result.warnings.size() == 1, "expected one journalctl warning");
    expect(result.metadata.input_mode == loglens::InputMode::JournalctlShortFull, "expected journalctl metadata mode");
    expect(!result.metadata.assume_year.has_value(), "expected no assumed year for journalctl");
    expect(result.metadata.timezone_present, "expected journalctl timezone metadata");
    expect(result.quality.total_lines == 2, "expected journalctl total line count");
    expect(result.quality.parsed_lines == 1, "expected journalctl parsed line count");
    expect(result.quality.unparsed_lines == 1, "expected journalctl unparsed line count");
    expect(result.quality.parse_success_rate == 0.5, "expected journalctl parse success rate");
    expect(result.quality.top_unknown_patterns.size() == 1, "expected one journalctl unknown pattern");
    expect(result.quality.top_unknown_patterns.front().pattern == "missing_journalctl_short_full_header_fields",
           "expected normalized journalctl failure pattern");
}

void test_journalctl_rejects_empty_fractional_seconds() {
    const auto parser = make_journalctl_parser();
    std::string error;
    const auto event = parser.parse_line(
        "Tue 2026-03-10 08:11:22. UTC example-host sshd[2234]: Failed password for root from 203.0.113.10 port 51022 ssh2",
        10,
        &error);

    expect(!event.has_value(), "expected empty fractional seconds to be rejected");
    expect(error == "invalid time token", "expected invalid time token error");
}

void test_syslog_fixture_matrix_file() {
    const auto parser = make_syslog_parser();
    const auto result = parser.parse_file(asset_path("parser_fixture_matrix_syslog.log"));

    expect(result.events.size() == 15, "expected fifteen recognized syslog fixture events");
    expect(result.warnings.size() == 8, "expected eight syslog fixture warnings");
    expect(result.quality.total_lines == 23, "expected twenty-three syslog fixture lines");
    expect(result.quality.parsed_lines == 15, "expected fifteen parsed syslog fixture lines");
    expect(result.quality.unparsed_lines == 8, "expected eight unparsed syslog fixture lines");
    expect_close(result.quality.parse_success_rate, 15.0 / 23.0, 1e-9, "expected syslog fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure, "expected pam auth failure variant");
    expect(result.events[4].event_type == loglens::EventType::SessionOpened, "expected sudo session-opened variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected su-l session-opened variant");
    expect(result.events[6].event_type == loglens::EventType::SshAcceptedPassword, "expected accepted password variant");
    expect(result.events[7].event_type == loglens::EventType::SshAcceptedPublicKey, "expected accepted publickey variant");
    expect(result.events[4].username == "alice", "expected sudo session actor username");
    expect(result.events[5].username == "bob", "expected su-l session actor username");
    expect(result.events[6].username == "alice", "expected accepted password username");
    expect(result.events[7].username == "carol", "expected accepted publickey username");
    expect(result.events[8].event_type == loglens::EventType::SshAcceptedKeyboardInteractive,
           "expected accepted keyboard-interactive variant");
    expect(result.events[8].username == "dave", "expected accepted keyboard-interactive username");
    expect(result.events[9].event_type == loglens::EventType::SudoAuthFailure,
           "expected sudo auth failure variant");
    expect(result.events[9].username == "alice", "expected sudo auth failure username");
    expect(result.events[10].event_type == loglens::EventType::SudoPolicyDenied,
           "expected sudo policy denied variant");
    expect(result.events[10].username == "bob", "expected sudo policy denied username");
    expect(result.events[11].event_type == loglens::EventType::SuAuthFailure,
           "expected su auth failure variant");
    expect(result.events[11].username == "carol", "expected su auth failure username");
    expect(result.events[12].event_type == loglens::EventType::SessionOpened,
           "expected su success session-opened variant");
    expect(result.events[12].username == "dave", "expected su success actor username");
    expect(result.events[13].event_type == loglens::EventType::SshFailedKeyboardInteractive,
           "expected failed keyboard-interactive variant");
    expect(result.events[13].username == "eve", "expected failed keyboard-interactive username");
    expect(result.events[14].event_type == loglens::EventType::SshMaxAuthTries,
           "expected max-auth-tries variant");
    expect(result.events[14].username == "frank", "expected max-auth-tries username");

    expect(result.quality.top_unknown_patterns.size() == 4, "expected four unknown syslog buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close syslog bucket");
    expect(result.quality.top_unknown_patterns[0].count == 3, "expected three preauth connection-close syslog lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection syslog bucket");
    expect(result.quality.top_unknown_patterns[1].count == 3, "expected three timeout/disconnection syslog lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_other",
           "expected unsupported pam_unix syslog bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one unsupported pam_unix syslog line");
    expect(result.quality.top_unknown_patterns[3].pattern == "sshd_other",
           "expected unsupported sshd syslog bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one unsupported sshd syslog line");
}

void test_journalctl_fixture_matrix_file() {
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
    const auto result = parser.parse_file(asset_path("parser_fixture_matrix_journalctl_short_full.log"));

    expect(result.events.size() == 15, "expected fifteen recognized journalctl fixture events");
    expect(result.warnings.size() == 8, "expected eight journalctl fixture warnings");
    expect(result.quality.total_lines == 23, "expected twenty-three journalctl fixture lines");
    expect(result.quality.parsed_lines == 15, "expected fifteen parsed journalctl fixture lines");
    expect(result.quality.unparsed_lines == 8, "expected eight unparsed journalctl fixture lines");
    expect_close(result.quality.parse_success_rate, 15.0 / 23.0, 1e-9, "expected journalctl fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected journalctl failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure, "expected journalctl pam auth failure variant");
    expect(result.events[4].event_type == loglens::EventType::SessionOpened, "expected journalctl sudo session-opened variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected journalctl su-l session-opened variant");
    expect(result.events[6].event_type == loglens::EventType::SshAcceptedPassword, "expected journalctl accepted password variant");
    expect(result.events[7].event_type == loglens::EventType::SshAcceptedPublicKey, "expected journalctl accepted publickey variant");
    expect(result.events[8].event_type == loglens::EventType::SshAcceptedKeyboardInteractive,
           "expected journalctl accepted keyboard-interactive variant");
    expect(result.events[9].event_type == loglens::EventType::SudoAuthFailure,
           "expected journalctl sudo auth failure variant");
    expect(result.events[10].event_type == loglens::EventType::SudoPolicyDenied,
           "expected journalctl sudo policy denied variant");
    expect(result.events[11].event_type == loglens::EventType::SuAuthFailure,
           "expected journalctl su auth failure variant");
    expect(result.events[12].event_type == loglens::EventType::SessionOpened,
           "expected journalctl su success session-opened variant");
    expect(result.events[13].event_type == loglens::EventType::SshFailedKeyboardInteractive,
           "expected journalctl failed keyboard-interactive variant");
    expect(result.events[14].event_type == loglens::EventType::SshMaxAuthTries,
           "expected journalctl max-auth-tries variant");

    expect(result.quality.top_unknown_patterns.size() == 4, "expected four unknown journalctl buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close journalctl bucket");
    expect(result.quality.top_unknown_patterns[0].count == 3, "expected three preauth connection-close journalctl lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection journalctl bucket");
    expect(result.quality.top_unknown_patterns[1].count == 3, "expected three timeout/disconnection journalctl lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_other",
           "expected unsupported pam_unix journalctl bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one unsupported pam_unix journalctl line");
    expect(result.quality.top_unknown_patterns[3].pattern == "sshd_other",
           "expected unsupported sshd journalctl bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one unsupported sshd journalctl line");
}

}  // namespace

int main() {
    test_invalid_user_failure();
    test_standard_failure();
    test_success_event();
    test_accepted_publickey_success_event();
    test_accepted_keyboard_interactive_success_event();
    test_sudo_event();
    test_sudo_auth_failure_event();
    test_sudo_policy_denied_event();
    test_su_auth_failure_event();
    test_su_success_event();
    test_failed_publickey_event();
    test_failed_keyboard_interactive_event();
    test_max_auth_tries_event();
    test_pam_auth_failure_event();
    test_pam_sss_received_failure_event();
    test_session_opened_event();
    test_journalctl_short_full_event();
    test_input_mode_aliases();
    test_syslog_auth_family_fixture_file();
    test_journalctl_auth_family_fixture_file();
    test_malformed_line();
    test_unknown_auth_patterns_are_warnings_only();
    test_stream_warnings_and_metadata();
    test_stream_tracks_skipped_blank_lines();
    test_journalctl_metadata();
    test_journalctl_rejects_empty_fractional_seconds();
    test_syslog_fixture_matrix_file();
    test_journalctl_fixture_matrix_file();
    return 0;
}
