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

void test_syslog_fixture_matrix_file() {
    const auto parser = make_syslog_parser();
    const auto result = parser.parse_file(asset_path("parser_fixture_matrix_syslog.log"));

    expect(result.events.size() == 6, "expected six recognized syslog fixture events");
    expect(result.warnings.size() == 6, "expected six syslog fixture warnings");
    expect(result.quality.total_lines == 12, "expected twelve syslog fixture lines");
    expect(result.quality.parsed_lines == 6, "expected six parsed syslog fixture lines");
    expect(result.quality.unparsed_lines == 6, "expected six unparsed syslog fixture lines");
    expect_close(result.quality.parse_success_rate, 0.5, 1e-9, "expected syslog fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure, "expected pam auth failure variant");
    expect(result.events[4].event_type == loglens::EventType::SessionOpened, "expected sudo session-opened variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected su-l session-opened variant");
    expect(result.events[4].username == "alice", "expected sudo session actor username");
    expect(result.events[5].username == "bob", "expected su-l session actor username");

    expect(result.quality.top_unknown_patterns.size() == 3, "expected three unknown syslog buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close syslog bucket");
    expect(result.quality.top_unknown_patterns[0].count == 3, "expected three preauth connection-close syslog lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection syslog bucket");
    expect(result.quality.top_unknown_patterns[1].count == 2, "expected two timeout/disconnection syslog lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_other",
           "expected unsupported pam_unix syslog bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one unsupported pam_unix syslog line");
}

void test_journalctl_fixture_matrix_file() {
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
    const auto result = parser.parse_file(asset_path("parser_fixture_matrix_journalctl_short_full.log"));

    expect(result.events.size() == 6, "expected six recognized journalctl fixture events");
    expect(result.warnings.size() == 6, "expected six journalctl fixture warnings");
    expect(result.quality.total_lines == 12, "expected twelve journalctl fixture lines");
    expect(result.quality.parsed_lines == 6, "expected six parsed journalctl fixture lines");
    expect(result.quality.unparsed_lines == 6, "expected six unparsed journalctl fixture lines");
    expect_close(result.quality.parse_success_rate, 0.5, 1e-9, "expected journalctl fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected journalctl failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure, "expected journalctl pam auth failure variant");
    expect(result.events[4].event_type == loglens::EventType::SessionOpened, "expected journalctl sudo session-opened variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected journalctl su-l session-opened variant");

    expect(result.quality.top_unknown_patterns.size() == 3, "expected three unknown journalctl buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close journalctl bucket");
    expect(result.quality.top_unknown_patterns[0].count == 3, "expected three preauth connection-close journalctl lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection journalctl bucket");
    expect(result.quality.top_unknown_patterns[1].count == 2, "expected two timeout/disconnection journalctl lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_other",
           "expected unsupported pam_unix journalctl bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one unsupported pam_unix journalctl line");
}

}  // namespace

int main() {
    test_invalid_user_failure();
    test_standard_failure();
    test_success_event();
    test_sudo_event();
    test_failed_publickey_event();
    test_pam_auth_failure_event();
    test_session_opened_event();
    test_journalctl_short_full_event();
    test_malformed_line();
    test_unknown_auth_patterns_are_warnings_only();
    test_stream_warnings_and_metadata();
    test_journalctl_metadata();
    test_syslog_fixture_matrix_file();
    test_journalctl_fixture_matrix_file();
    return 0;
}
