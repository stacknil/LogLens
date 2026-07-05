#include "parser.hpp"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
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

std::filesystem::path parser_matrix_fixture_path(std::string_view filename) {
    return repo_root() / "tests" / "fixtures" / "parser_matrix" / std::string(filename);
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to read file: " + path.string());
    }

    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

void expect_close(double actual, double expected, double tolerance, const std::string& message) {
    if (std::fabs(actual - expected) > tolerance) {
        throw std::runtime_error(message);
    }
}

std::size_t total_input_lines(const loglens::ParseReport& result) {
    return result.quality.total_lines + result.quality.skipped_blank_lines;
}

std::size_t event_count(const std::vector<loglens::Event>& events, loglens::EventType type) {
    return static_cast<std::size_t>(
        std::count_if(events.begin(), events.end(), [type](const loglens::Event& event) {
            return event.event_type == type;
        }));
}

std::size_t unknown_pattern_count(const loglens::ParserQualityMetrics& quality, std::string_view pattern) {
    const auto it = std::find_if(
        quality.top_unknown_patterns.begin(),
        quality.top_unknown_patterns.end(),
        [pattern](const loglens::UnknownPatternCount& entry) {
            return entry.pattern == pattern;
        });
    return it == quality.top_unknown_patterns.end() ? 0 : it->count;
}

std::size_t failure_category_count(const loglens::ParserQualityMetrics& quality,
                                   loglens::ParserFailureCategory category) {
    const auto it = std::find_if(
        quality.failure_categories.begin(),
        quality.failure_categories.end(),
        [category](const loglens::ParserFailureCategoryCount& entry) {
            return entry.category == category;
        });
    return it == quality.failure_categories.end() ? 0 : it->count;
}

std::vector<std::pair<loglens::EventType, std::size_t>> parser_event_type_counts(
    const std::vector<loglens::Event>& events) {
    std::vector<std::pair<loglens::EventType, std::size_t>> counts{
        {loglens::EventType::SshFailedPassword, 0},
        {loglens::EventType::SshAcceptedPassword, 0},
        {loglens::EventType::SshAcceptedPublicKey, 0},
        {loglens::EventType::SshAcceptedKeyboardInteractive, 0},
        {loglens::EventType::SshInvalidUser, 0},
        {loglens::EventType::SshFailedPublicKey, 0},
        {loglens::EventType::SshFailedKeyboardInteractive, 0},
        {loglens::EventType::SshMaxAuthTries, 0},
        {loglens::EventType::PamAuthFailure, 0},
        {loglens::EventType::SessionOpened, 0},
        {loglens::EventType::SudoCommand, 0},
        {loglens::EventType::SudoAuthFailure, 0},
        {loglens::EventType::SudoPolicyDenied, 0},
        {loglens::EventType::SuAuthFailure, 0}};

    for (const auto& event : events) {
        for (auto& [type, count] : counts) {
            if (type == event.event_type) {
                ++count;
                break;
            }
        }
    }

    counts.erase(
        std::remove_if(counts.begin(), counts.end(), [](const auto& entry) {
            return entry.second == 0;
        }),
        counts.end());

    return counts;
}

std::string noisy_auth_coverage_json(const loglens::ParseReport& result) {
    std::ostringstream output;
    output << "{\n"
           << "  \"fixture\": \"assets/noisy_auth_sample.log\",\n"
           << "  \"input_mode\": \"" << loglens::to_string(result.metadata.input_mode) << "\",\n"
           << "  \"assume_year\": " << *result.metadata.assume_year << ",\n"
           << "  \"total_input_lines\": " << total_input_lines(result) << ",\n"
           << "  \"total_lines\": " << result.quality.total_lines << ",\n"
           << "  \"skipped_blank_lines\": " << result.quality.skipped_blank_lines << ",\n"
           << "  \"parsed_lines\": " << result.quality.parsed_lines << ",\n"
           << "  \"unparsed_lines\": " << result.quality.unparsed_lines << ",\n"
           << "  \"parse_success_rate\": " << std::fixed << std::setprecision(10)
           << result.quality.parse_success_rate << ",\n"
           << "  \"parsed_event_count\": " << result.events.size() << ",\n"
           << "  \"warning_count\": " << result.warnings.size() << ",\n"
           << "  \"top_unknown_patterns\": [\n";

    for (std::size_t index = 0; index < result.quality.top_unknown_patterns.size(); ++index) {
        const auto& entry = result.quality.top_unknown_patterns[index];
        output << "    {\"pattern\": \"" << entry.pattern << "\", \"count\": " << entry.count << "}";
        output << (index + 1 == result.quality.top_unknown_patterns.size() ? "\n" : ",\n");
    }

    output << "  ],\n"
           << "  \"failure_categories\": [\n";

    for (std::size_t index = 0; index < result.quality.failure_categories.size(); ++index) {
        const auto& entry = result.quality.failure_categories[index];
        output << "    {\"category\": \"" << loglens::to_string(entry.category)
               << "\", \"count\": " << entry.count << "}";
        output << (index + 1 == result.quality.failure_categories.size() ? "\n" : ",\n");
    }

    output << "  ],\n"
           << "  \"warnings\": [\n";

    for (std::size_t index = 0; index < result.warnings.size(); ++index) {
        const auto& warning = result.warnings[index];
        output << "    {\"line_number\": " << warning.line_number
               << ", \"category\": \"" << loglens::to_string(warning.category) << "\""
               << ", \"reason\": \"" << warning.reason << "\"}";
        output << (index + 1 == result.warnings.size() ? "\n" : ",\n");
    }

    output << "  ]\n"
           << "}\n";
    return output.str();
}

std::string mixed_auth_coverage_json(const loglens::ParseReport& result) {
    std::ostringstream output;
    const auto event_counts = parser_event_type_counts(result.events);

    output << "{\n"
           << "  \"artifact\": \"loglens.parser_coverage_sample\",\n"
           << "  \"schema_version\": 1,\n"
           << "  \"fixture\": \"assets/mixed_auth_corpus.log\",\n"
           << "  \"input_mode\": \"" << loglens::to_string(result.metadata.input_mode) << "\",\n"
           << "  \"assume_year\": " << *result.metadata.assume_year << ",\n"
           << "  \"parser_quality\": {\n"
           << "    \"total_input_lines\": " << total_input_lines(result) << ",\n"
           << "    \"total_lines\": " << result.quality.total_lines << ",\n"
           << "    \"skipped_blank_lines\": " << result.quality.skipped_blank_lines << ",\n"
           << "    \"parsed_lines\": " << result.quality.parsed_lines << ",\n"
           << "    \"unparsed_lines\": " << result.quality.unparsed_lines << ",\n"
           << "    \"parse_success_rate\": " << std::fixed << std::setprecision(10)
           << result.quality.parse_success_rate << ",\n"
           << "    \"top_unknown_patterns\": [\n";

    for (std::size_t index = 0; index < result.quality.top_unknown_patterns.size(); ++index) {
        const auto& entry = result.quality.top_unknown_patterns[index];
        output << "      {\"pattern\": \"" << entry.pattern << "\", \"count\": " << entry.count << "}";
        output << (index + 1 == result.quality.top_unknown_patterns.size() ? "\n" : ",\n");
    }

    output << "    ],\n"
           << "    \"failure_categories\": [\n";

    for (std::size_t index = 0; index < result.quality.failure_categories.size(); ++index) {
        const auto& entry = result.quality.failure_categories[index];
        output << "      {\"category\": \"" << loglens::to_string(entry.category)
               << "\", \"count\": " << entry.count << "}";
        output << (index + 1 == result.quality.failure_categories.size() ? "\n" : ",\n");
    }

    output << "    ]\n"
           << "  },\n"
           << "  \"parsed_event_count\": " << result.events.size() << ",\n"
           << "  \"warning_count\": " << result.warnings.size() << ",\n"
           << "  \"event_type_counts\": [\n";

    for (std::size_t index = 0; index < event_counts.size(); ++index) {
        const auto& [type, count] = event_counts[index];
        output << "    {\"event_type\": \"" << loglens::to_string(type) << "\", \"count\": " << count << "}";
        output << (index + 1 == event_counts.size() ? "\n" : ",\n");
    }

    output << "  ],\n"
           << "  \"warnings\": [\n";

    for (std::size_t index = 0; index < result.warnings.size(); ++index) {
        const auto& warning = result.warnings[index];
        output << "    {\"line_number\": " << warning.line_number
               << ", \"category\": \"" << loglens::to_string(warning.category) << "\""
               << ", \"reason\": \"" << warning.reason << "\"}";
        output << (index + 1 == result.warnings.size() ? "\n" : ",\n");
    }

    output << "  ]\n"
           << "}\n";
    return output.str();
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

void test_illegal_user_failure_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:23 example-host sshd[1235]: Failed password for illegal user legacy-admin from 203.0.113.11 port 51023 ssh2",
        1);

    expect(event.has_value(), "expected illegal-user failed-password event");
    expect(event->username == "legacy-admin", "expected illegal-user failed-password username");
    expect(event->source_ip == "203.0.113.11", "expected illegal-user failed-password source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected illegal-user failed-password to normalize to invalid-user type");
}

void test_failed_none_invalid_user_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:25 example-host sshd[1237]: Failed none for invalid user svc-none from 203.0.113.13 port 51025 ssh2",
        1);

    expect(event.has_value(), "expected failed-none invalid-user event");
    expect(event->username == "svc-none", "expected failed-none invalid username");
    expect(event->source_ip == "203.0.113.13", "expected failed-none invalid source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected failed-none invalid-user to normalize to invalid-user type");
}

void test_failed_none_illegal_user_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:27 example-host sshd[1239]: Failed none for illegal user legacy-none from 203.0.113.15 port 51027 ssh2",
        1);

    expect(event.has_value(), "expected failed-none illegal-user event");
    expect(event->username == "legacy-none", "expected failed-none illegal username");
    expect(event->source_ip == "203.0.113.15", "expected failed-none illegal source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected failed-none illegal-user to normalize to invalid-user type");
}

void test_failed_none_without_invalid_user_stays_unsupported() {
    const auto parser = make_syslog_parser();
    std::string error;
    const auto event = parser.parse_line(
        "Mar 10 08:11:26 example-host sshd[1238]: Failed none for root from 203.0.113.14 port 51026 ssh2",
        1,
        &error);

    expect(!event.has_value(), "expected failed-none standard user to stay unsupported");
    expect(error == "unrecognized auth pattern: sshd_other", "expected failed-none standard user telemetry bucket");
}

void test_illegal_user_message_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:24 example-host sshd[1236]: Illegal user legacy-backup from 203.0.113.12 port 51024",
        1);

    expect(event.has_value(), "expected direct illegal-user event");
    expect(event->username == "legacy-backup", "expected direct illegal-user username");
    expect(event->source_ip == "203.0.113.12", "expected direct illegal-user source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected direct illegal-user to normalize to invalid-user type");
}

void test_input_userauth_request_invalid_user_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:28 example-host sshd[1240]: input_userauth_request: invalid user svc-verbose [preauth]",
        1);

    expect(event.has_value(), "expected input_userauth_request invalid-user event");
    expect(event->username == "svc-verbose", "expected input_userauth_request invalid username");
    expect(event->source_ip.empty(), "expected input_userauth_request invalid-user line to stay source-less");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected input_userauth_request invalid-user to normalize to invalid-user type");
}

void test_input_userauth_request_illegal_user_is_normalized_as_invalid_user() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:11:29 example-host sshd[1241]: input_userauth_request: illegal user legacy-verbose [preauth]",
        1);

    expect(event.has_value(), "expected input_userauth_request illegal-user event");
    expect(event->username == "legacy-verbose", "expected input_userauth_request illegal username");
    expect(event->source_ip.empty(), "expected input_userauth_request illegal-user line to stay source-less");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected input_userauth_request illegal-user to normalize to invalid-user type");
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

void test_failed_publickey_illegal_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:11 example-host sshd[1248]: Failed publickey for illegal user svc-legacy from 203.0.113.81 port 51245 ssh2",
        5);

    expect(event.has_value(), "expected failed publickey illegal-user event");
    expect(event->username == "svc-legacy", "expected parsed illegal-user publickey username");
    expect(event->source_ip == "203.0.113.81", "expected parsed illegal-user publickey source ip");
    expect(event->event_type == loglens::EventType::SshFailedPublicKey,
           "expected illegal-user publickey to keep publickey failure type");
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

void test_failed_keyboard_interactive_invalid_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:19 example-host sshd[1246]: Failed keyboard-interactive/pam for invalid user svc-keyboard from 203.0.113.79 port 51243 ssh2",
        5);

    expect(event.has_value(), "expected failed keyboard-interactive invalid-user event");
    expect(event->username == "svc-keyboard", "expected parsed keyboard-interactive invalid username");
    expect(event->source_ip == "203.0.113.79", "expected parsed keyboard-interactive invalid source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected keyboard-interactive invalid-user type");
}

void test_failed_keyboard_interactive_illegal_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:20 example-host sshd[1249]: Failed keyboard-interactive/pam for illegal user svc-keyboard-legacy from 203.0.113.82 port 51246 ssh2",
        5);

    expect(event.has_value(), "expected failed keyboard-interactive illegal-user event");
    expect(event->username == "svc-keyboard-legacy", "expected parsed keyboard-interactive illegal username");
    expect(event->source_ip == "203.0.113.82", "expected parsed keyboard-interactive illegal source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected keyboard-interactive illegal-user type");
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

void test_max_auth_tries_error_prefix_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:25 example-host sshd[1251]: error: maximum authentication attempts exceeded for frank from 203.0.113.84 port 51248 ssh2 [preauth]",
        5);

    expect(event.has_value(), "expected error-prefixed max-auth-tries event");
    expect(event->username == "frank", "expected parsed error-prefixed max-auth-tries username");
    expect(event->source_ip == "203.0.113.84", "expected parsed error-prefixed max-auth-tries source ip");
    expect(event->event_type == loglens::EventType::SshMaxAuthTries,
           "expected error-prefixed ssh max-auth-tries failure type");
}

void test_max_auth_tries_invalid_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:26 example-host sshd[1247]: maximum authentication attempts exceeded for invalid user svc-maxauth from 203.0.113.80 port 51244 ssh2 [preauth]",
        5);

    expect(event.has_value(), "expected max-auth-tries invalid-user event");
    expect(event->username == "svc-maxauth", "expected parsed max-auth-tries invalid username");
    expect(event->source_ip == "203.0.113.80", "expected parsed max-auth-tries invalid source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected max-auth-tries invalid-user type");
}

void test_max_auth_tries_illegal_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:27:27 example-host sshd[1250]: maximum authentication attempts exceeded for illegal user svc-maxauth-legacy from 203.0.113.83 port 51247 ssh2 [preauth]",
        5);

    expect(event.has_value(), "expected max-auth-tries illegal-user event");
    expect(event->username == "svc-maxauth-legacy", "expected parsed max-auth-tries illegal username");
    expect(event->source_ip == "203.0.113.83", "expected parsed max-auth-tries illegal source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected max-auth-tries illegal-user type");
}

void test_ssh_pam_auth_failure_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:28:40 example-host sshd[1251]: PAM: Authentication failure for alice from 203.0.113.84",
        6);

    expect(event.has_value(), "expected sshd-owned pam auth failure event");
    expect(event->program == "sshd", "expected sshd program");
    expect(event->username == "alice", "expected sshd-owned pam username");
    expect(event->source_ip == "203.0.113.84", "expected sshd-owned pam source ip");
    expect(event->event_type == loglens::EventType::PamAuthFailure,
           "expected sshd-owned pam auth failure type");
}

void test_ssh_pam_auth_failure_invalid_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:28:41 example-host sshd[1252]: PAM: Authentication failure for invalid user svc-pam from 203.0.113.85",
        6);

    expect(event.has_value(), "expected sshd-owned pam invalid-user event");
    expect(event->program == "sshd", "expected sshd program for invalid-user pam line");
    expect(event->username == "svc-pam", "expected sshd-owned pam invalid username");
    expect(event->source_ip == "203.0.113.85", "expected sshd-owned pam invalid source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected sshd-owned pam invalid-user type");
}

void test_ssh_pam_auth_failure_illegal_user_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:28:42 example-host sshd[1253]: PAM: Authentication failure for illegal user svc-pam-legacy from 203.0.113.86",
        6);

    expect(event.has_value(), "expected sshd-owned pam illegal-user event");
    expect(event->program == "sshd", "expected sshd program for illegal-user pam line");
    expect(event->username == "svc-pam-legacy", "expected sshd-owned pam illegal username");
    expect(event->source_ip == "203.0.113.86", "expected sshd-owned pam illegal source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected sshd-owned pam illegal-user type");
}

void test_ssh_pam_auth_failure_error_prefix_event() {
    const auto parser = make_syslog_parser();
    const auto event = parser.parse_line(
        "Mar 10 08:28:43 example-host sshd[1254]: error: PAM: Authentication failure for invalid user svc-pam-error from 203.0.113.87",
        6);

    expect(event.has_value(), "expected error-prefixed sshd-owned pam invalid-user event");
    expect(event->program == "sshd", "expected sshd program for error-prefixed pam line");
    expect(event->username == "svc-pam-error", "expected error-prefixed sshd-owned pam invalid username");
    expect(event->source_ip == "203.0.113.87", "expected error-prefixed sshd-owned pam source ip");
    expect(event->event_type == loglens::EventType::SshInvalidUser,
           "expected error-prefixed sshd-owned pam invalid-user type");
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
    const auto parser = make_journalctl_parser();
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

void test_journalctl_numeric_timezone_offsets() {
    const auto parser = make_journalctl_parser();
    std::string error;
    const auto compact_offset_event = parser.parse_line(
        "Tue 2026-03-10 08:11:22 +0800 example-host sshd[2235]: Failed password for root from 203.0.113.13 port 51023 ssh2",
        9,
        &error);

    expect(compact_offset_event.has_value(), "expected compact numeric timezone event");
    expect(error.empty(), "expected compact numeric timezone to parse cleanly");
    expect(compact_offset_event->username == "root", "expected compact numeric timezone username");
    expect(loglens::format_timestamp(compact_offset_event->timestamp) == "2026-03-10 00:11:22",
           "expected compact numeric timezone to normalize to UTC");

    const auto colon_offset_event = parser.parse_line(
        "Tue 2026-03-10 08:11:22 -05:00 example-host sshd[2236]: Accepted password for alice from 203.0.113.14 port 51024 ssh2",
        10,
        &error);

    expect(colon_offset_event.has_value(), "expected colon numeric timezone event");
    expect(error.empty(), "expected colon numeric timezone to parse cleanly");
    expect(colon_offset_event->username == "alice", "expected colon numeric timezone username");
    expect(loglens::format_timestamp(colon_offset_event->timestamp) == "2026-03-10 13:11:22",
           "expected colon numeric timezone to normalize to UTC");
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

    expect(result.events.size() == 12, "expected twelve recognized syslog auth-family events");
    expect(result.warnings.size() == 5, "expected five syslog auth-family warnings");
    expect(result.quality.total_lines == 17, "expected seventeen syslog auth-family lines");
    expect(result.quality.parsed_lines == 12, "expected twelve parsed syslog auth-family lines");
    expect(result.quality.unparsed_lines == 5, "expected five unparsed syslog auth-family lines");
    expect_close(result.quality.parse_success_rate, 12.0 / 17.0, 1e-9,
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
           "expected sshd-owned pam auth-family event");
    expect(result.events[3].username == "alice", "expected sshd-owned pam username");
    expect(result.events[3].source_ip == "203.0.113.76", "expected sshd-owned pam source ip");
    expect(result.events[4].event_type == loglens::EventType::SshInvalidUser,
           "expected sshd-owned pam invalid-user auth-family event");
    expect(result.events[4].username == "svc-pam", "expected sshd-owned pam invalid username");
    expect(result.events[4].source_ip == "203.0.113.77", "expected sshd-owned pam invalid source ip");
    expect(result.events[5].event_type == loglens::EventType::SshInvalidUser,
           "expected sshd-owned pam illegal-user auth-family event");
    expect(result.events[5].username == "svc-pam-legacy", "expected sshd-owned pam illegal username");
    expect(result.events[5].source_ip == "203.0.113.78", "expected sshd-owned pam illegal source ip");
    expect(result.events[6].event_type == loglens::EventType::SshInvalidUser,
           "expected error-prefixed sshd-owned pam invalid-user auth-family event");
    expect(result.events[6].username == "svc-pam-error",
           "expected error-prefixed sshd-owned pam invalid username");
    expect(result.events[6].source_ip == "203.0.113.79",
           "expected error-prefixed sshd-owned pam invalid source ip");
    expect(result.events[7].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_faillock preauth auth-family event");
    expect(result.events[7].username == "alice", "expected pam_faillock preauth username");
    expect(result.events[7].source_ip == "203.0.113.71", "expected pam_faillock preauth source ip");
    expect(result.events[8].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_faillock authfail auth-family event");
    expect(result.events[8].username == "bob", "expected pam_faillock authfail username");
    expect(result.events[8].source_ip == "203.0.113.72", "expected pam_faillock authfail source ip");
    expect(result.events[9].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_unix auth-family event");
    expect(result.events[9].username == "carol", "expected pam_unix auth-family username");
    expect(result.events[9].source_ip == "203.0.113.75", "expected pam_unix auth-family source ip");
    expect(result.events[10].event_type == loglens::EventType::PamAuthFailure,
           "expected pam_sss failure auth-family event");
    expect(result.events[10].username == "dave", "expected pam_sss failure username");
    expect(result.events[10].source_ip.empty(), "expected pam_sss failure fixture to stay source-less");
    expect(result.events[11].event_type == loglens::EventType::SessionOpened,
           "expected pam_unix session-opened auth-family event");
    expect(result.events[11].username == "erin", "expected pam_unix session-opened username");

    expect(result.quality.top_unknown_patterns.size() == 5, "expected five syslog auth-family buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "pam_faillock_account_locked",
           "expected pam_faillock account-locked telemetry bucket");
    expect(result.quality.top_unknown_patterns[0].count == 1, "expected one pam_faillock account-locked line");
    expect(result.quality.top_unknown_patterns[1].pattern == "pam_faillock_authsucc",
           "expected pam_faillock authsucc telemetry bucket");
    expect(result.quality.top_unknown_patterns[1].count == 1, "expected one pam_faillock authsucc line");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_sss_authinfo_unavail",
           "expected pam_sss authinfo-unavail telemetry bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one pam_sss authinfo-unavail line");
    expect(result.quality.top_unknown_patterns[3].pattern == "pam_sss_unknown_user",
           "expected pam_sss unknown-user telemetry bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one pam_sss unknown-user line");
    expect(result.quality.top_unknown_patterns[4].pattern == "pam_unix_session_closed",
           "expected pam_unix session-closed telemetry bucket");
    expect(result.quality.top_unknown_patterns[4].count == 1, "expected one pam_unix session-closed line");
}

void test_journalctl_auth_family_fixture_file() {
    const auto parser = make_journalctl_parser();
    const auto result = parser.parse_file(asset_path("parser_auth_families_journalctl_short_full.log"));

    expect(result.events.size() == 12, "expected twelve recognized journalctl auth-family events");
    expect(result.warnings.size() == 5, "expected five journalctl auth-family warnings");
    expect(result.quality.total_lines == 17, "expected seventeen journalctl auth-family lines");
    expect(result.quality.parsed_lines == 12, "expected twelve parsed journalctl auth-family lines");
    expect(result.quality.unparsed_lines == 5, "expected five unparsed journalctl auth-family lines");
    expect_close(result.quality.parse_success_rate, 12.0 / 17.0, 1e-9,
                 "expected journalctl auth-family parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshAcceptedPublicKey,
           "expected journalctl accepted publickey auth-family event");
    expect(result.events[0].source_ip == "203.0.113.70", "expected journalctl accepted publickey source ip");
    expect(result.events[1].event_type == loglens::EventType::SshAcceptedPassword,
           "expected journalctl accepted password auth-family event");
    expect(result.events[2].event_type == loglens::EventType::SshFailedPublicKey,
           "expected journalctl failed publickey auth-family event");
    expect(result.events[3].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl sshd-owned pam auth-family event");
    expect(result.events[3].source_ip == "203.0.113.76",
           "expected journalctl sshd-owned pam source ip");
    expect(result.events[4].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl sshd-owned pam invalid-user auth-family event");
    expect(result.events[4].username == "svc-pam", "expected journalctl sshd-owned pam invalid username");
    expect(result.events[5].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl sshd-owned pam illegal-user auth-family event");
    expect(result.events[5].username == "svc-pam-legacy",
           "expected journalctl sshd-owned pam illegal username");
    expect(result.events[6].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl error-prefixed sshd-owned pam invalid-user auth-family event");
    expect(result.events[6].username == "svc-pam-error",
           "expected journalctl error-prefixed sshd-owned pam invalid username");
    expect(result.events[6].source_ip == "203.0.113.79",
           "expected journalctl error-prefixed sshd-owned pam invalid source ip");
    expect(result.events[7].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_faillock preauth auth-family event");
    expect(result.events[8].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_faillock authfail auth-family event");
    expect(result.events[9].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_unix auth-family event");
    expect(result.events[10].event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl pam_sss failure auth-family event");
    expect(result.events[10].source_ip.empty(), "expected journalctl pam_sss failure fixture to stay source-less");
    expect(result.events[11].event_type == loglens::EventType::SessionOpened,
           "expected journalctl pam_unix session-opened auth-family event");

    expect(result.quality.top_unknown_patterns.size() == 5, "expected five journalctl auth-family buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "pam_faillock_account_locked",
           "expected journalctl pam_faillock account-locked telemetry bucket");
    expect(result.quality.top_unknown_patterns[0].count == 1,
           "expected one journalctl pam_faillock account-locked line");
    expect(result.quality.top_unknown_patterns[1].pattern == "pam_faillock_authsucc",
           "expected journalctl pam_faillock authsucc telemetry bucket");
    expect(result.quality.top_unknown_patterns[1].count == 1, "expected one journalctl pam_faillock authsucc line");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_sss_authinfo_unavail",
           "expected journalctl pam_sss authinfo-unavail telemetry bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one journalctl pam_sss authinfo-unavail line");
    expect(result.quality.top_unknown_patterns[3].pattern == "pam_sss_unknown_user",
           "expected journalctl pam_sss unknown-user telemetry bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one journalctl pam_sss unknown-user line");
    expect(result.quality.top_unknown_patterns[4].pattern == "pam_unix_session_closed",
           "expected journalctl pam_unix session-closed telemetry bucket");
    expect(result.quality.top_unknown_patterns[4].count == 1, "expected one journalctl pam_unix session-closed line");
}

void test_malformed_line() {
    const auto parser = make_syslog_parser();
    std::string error;
    loglens::ParserFailureCategory category = loglens::ParserFailureCategory::KnownProgramUnknownMessage;
    const auto event = parser.parse_line("malformed log line without syslog header", 9, &error, &category);

    expect(!event.has_value(), "expected malformed line to fail");
    expect(!error.empty(), "expected parse error for malformed line");
    expect(category == loglens::ParserFailureCategory::UnknownTimestamp,
           "expected malformed header to be categorized as unknown timestamp");
}

void test_parser_failure_taxonomy() {
    const auto parser = make_syslog_parser();
    std::istringstream input(
        "rotated\n"
        "Mar 10 08:00:00 example-host CRON[2001]: (root) CMD (/usr/bin/true)\n"
        "Mar 10 08:00:10 example-host sshd[1001]: Connection closed by authenticating user root 203.0.113.10 port 50100 [preauth]\n"
        "Mar 10 08:00:20 example-host sshd[1002]: Failed password for root from not_an_ip port 50101 ssh2\n"
        "Mar 10 08:00:30 example-host pam_faillock(sshd:auth): Account temporarily locked for user root\n");

    const auto result = parser.parse_stream(input);

    expect(result.events.empty(), "expected taxonomy fixture to produce warnings only");
    expect(result.warnings.size() == 5, "expected five taxonomy warnings");
    expect(result.quality.failure_categories.size() == 5, "expected five parser failure categories");
    expect(loglens::to_string(result.warnings[0].category) == "unknown_timestamp",
           "expected first warning category");
    expect(loglens::to_string(result.warnings[1].category) == "unknown_program",
           "expected second warning category");
    expect(loglens::to_string(result.warnings[2].category) == "known_program_unknown_message",
           "expected third warning category");
    expect(loglens::to_string(result.warnings[3].category) == "malformed_source_ip",
           "expected fourth warning category");
    expect(loglens::to_string(result.warnings[4].category) == "unsupported_pam_variant",
           "expected fifth warning category");
}

void test_malformed_source_ip_token_corpus() {
    const auto parser = make_syslog_parser();
    const std::vector<std::string> malformed_tokens{
        "not_an_ip",
        "999.0.113.10",
        "203.0.113.300",
        "203.0.113.10,"};

    for (std::size_t index = 0; index < malformed_tokens.size(); ++index) {
        const auto line = "Mar 10 08:00:20 example-host sshd[1002]: Failed password for root from "
            + malformed_tokens[index] + " port 50101 ssh2";
        std::string error;
        loglens::ParserFailureCategory category = loglens::ParserFailureCategory::KnownProgramUnknownMessage;
        const auto event = parser.parse_line(line, index + 1, &error, &category);

        expect(!event.has_value(), "expected malformed source token to stay out of normalized events");
        expect(category == loglens::ParserFailureCategory::MalformedSourceIp,
               "expected malformed source token to use malformed_source_ip category");
        expect(error == "malformed source IP", "expected malformed source token reason");
    }
}

void test_unknown_auth_patterns_are_warnings_only() {
    const auto parser = make_syslog_parser();
    std::istringstream input(
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed publickey for invalid user svc-backup from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Connection closed by authenticating user alice 203.0.113.50 port 51290 [preauth]\n"
        "Mar 10 08:13:40 example-host sshd[1238]: Connection reset by invalid user deploy 203.0.113.52 port 51292 [preauth]\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Timeout, client not responding from 203.0.113.51 port 51291\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.size() == 2, "expected only recognized lines to become events");
    expect(result.warnings.size() == 3, "expected unknown auth patterns to become warnings");
    expect(result.quality.total_lines == 5, "expected total analyzed line count");
    expect(result.quality.parsed_lines == 2, "expected parsed line count");
    expect(result.quality.unparsed_lines == 3, "expected unparsed line count");
    expect(result.quality.parse_success_rate == 0.4, "expected parse success rate");
    expect(result.quality.top_unknown_patterns.size() == 2, "expected two unknown pattern buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection close/reset pattern");
    expect(result.quality.top_unknown_patterns[0].count == 2, "expected preauth connection close/reset count");
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
    expect(result.quality.failure_categories.size() == 1, "expected one parser failure category");
    expect(result.quality.failure_categories.front().category == loglens::ParserFailureCategory::UnknownTimestamp,
           "expected missing header to be categorized as unknown timestamp");
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
    expect(result.quality.failure_categories.size() == 1, "expected one journalctl parser failure category");
    expect(result.quality.failure_categories.front().category == loglens::ParserFailureCategory::UnknownTimestamp,
           "expected journalctl missing header to be categorized as unknown timestamp");
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

    expect(result.events.size() == 23, "expected twenty-three recognized syslog fixture events");
    expect(result.warnings.size() == 9, "expected nine syslog fixture warnings");
    expect(result.quality.total_lines == 32, "expected thirty-two syslog fixture lines");
    expect(result.quality.parsed_lines == 23, "expected twenty-three parsed syslog fixture lines");
    expect(result.quality.unparsed_lines == 9, "expected nine unparsed syslog fixture lines");
    expect_close(result.quality.parse_success_rate, 23.0 / 32.0, 1e-9, "expected syslog fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::SshInvalidUser,
           "expected input_userauth_request invalid-user variant");
    expect(result.events[3].username == "svc-verbose",
           "expected input_userauth_request invalid username");
    expect(result.events[3].source_ip.empty(),
           "expected input_userauth_request invalid-user fixture to stay source-less");
    expect(result.events[4].event_type == loglens::EventType::PamAuthFailure, "expected pam auth failure variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected sudo session-opened variant");
    expect(result.events[6].event_type == loglens::EventType::SessionOpened, "expected su-l session-opened variant");
    expect(result.events[7].event_type == loglens::EventType::SshAcceptedPassword, "expected accepted password variant");
    expect(result.events[8].event_type == loglens::EventType::SshAcceptedPublicKey, "expected accepted publickey variant");
    expect(result.events[5].username == "alice", "expected sudo session actor username");
    expect(result.events[6].username == "bob", "expected su-l session actor username");
    expect(result.events[7].username == "alice", "expected accepted password username");
    expect(result.events[8].username == "carol", "expected accepted publickey username");
    expect(result.events[9].event_type == loglens::EventType::SshAcceptedKeyboardInteractive,
           "expected accepted keyboard-interactive variant");
    expect(result.events[9].username == "dave", "expected accepted keyboard-interactive username");
    expect(result.events[10].event_type == loglens::EventType::SudoAuthFailure,
           "expected sudo auth failure variant");
    expect(result.events[10].username == "alice", "expected sudo auth failure username");
    expect(result.events[11].event_type == loglens::EventType::SudoPolicyDenied,
           "expected sudo policy denied variant");
    expect(result.events[11].username == "bob", "expected sudo policy denied username");
    expect(result.events[12].event_type == loglens::EventType::SuAuthFailure,
           "expected su auth failure variant");
    expect(result.events[12].username == "carol", "expected su auth failure username");
    expect(result.events[13].event_type == loglens::EventType::SessionOpened,
           "expected su success session-opened variant");
    expect(result.events[13].username == "dave", "expected su success actor username");
    expect(result.events[14].event_type == loglens::EventType::SshFailedKeyboardInteractive,
           "expected failed keyboard-interactive variant");
    expect(result.events[14].username == "eve", "expected failed keyboard-interactive username");
    expect(result.events[15].event_type == loglens::EventType::SshMaxAuthTries,
           "expected max-auth-tries variant");
    expect(result.events[15].username == "frank", "expected max-auth-tries username");
    expect(result.events[16].event_type == loglens::EventType::SshInvalidUser,
           "expected keyboard-interactive invalid-user variant");
    expect(result.events[16].username == "svc-keyboard", "expected keyboard-interactive invalid username");
    expect(result.events[17].event_type == loglens::EventType::SshInvalidUser,
           "expected max-auth-tries invalid-user variant");
    expect(result.events[17].username == "svc-maxauth", "expected max-auth-tries invalid username");
    expect(result.events[18].event_type == loglens::EventType::SshInvalidUser,
           "expected failed-password illegal-user variant");
    expect(result.events[18].username == "legacy-admin", "expected failed-password illegal username");
    expect(result.events[19].event_type == loglens::EventType::SshInvalidUser,
           "expected direct illegal-user variant");
    expect(result.events[19].username == "legacy-backup", "expected direct illegal username");
    expect(result.events[20].event_type == loglens::EventType::SshInvalidUser,
           "expected failed-none invalid-user variant");
    expect(result.events[20].username == "svc-none", "expected failed-none invalid username");
    expect(result.events[21].event_type == loglens::EventType::SshInvalidUser,
           "expected failed-none illegal-user variant");
    expect(result.events[21].username == "legacy-none", "expected failed-none illegal username");
    expect(result.events[22].event_type == loglens::EventType::SshInvalidUser,
           "expected error-prefixed max-auth-tries invalid-user variant");
    expect(result.events[22].username == "svc-error-maxauth",
           "expected error-prefixed max-auth-tries invalid username");

    expect(result.quality.top_unknown_patterns.size() == 4, "expected four unknown syslog buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close syslog bucket");
    expect(result.quality.top_unknown_patterns[0].count == 4, "expected four preauth connection-close/reset syslog lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection syslog bucket");
    expect(result.quality.top_unknown_patterns[1].count == 3, "expected three timeout/disconnection syslog lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_session_closed",
           "expected pam_unix session-closed syslog bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one pam_unix session-closed syslog line");
    expect(result.quality.top_unknown_patterns[3].pattern == "sshd_negotiation_failure",
           "expected sshd negotiation-failure syslog bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one sshd negotiation-failure syslog line");
}

void test_journalctl_fixture_matrix_file() {
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt});
    const auto result = parser.parse_file(asset_path("parser_fixture_matrix_journalctl_short_full.log"));

    expect(result.events.size() == 23, "expected twenty-three recognized journalctl fixture events");
    expect(result.warnings.size() == 9, "expected nine journalctl fixture warnings");
    expect(result.quality.total_lines == 32, "expected thirty-two journalctl fixture lines");
    expect(result.quality.parsed_lines == 23, "expected twenty-three parsed journalctl fixture lines");
    expect(result.quality.unparsed_lines == 9, "expected nine unparsed journalctl fixture lines");
    expect_close(result.quality.parse_success_rate, 23.0 / 32.0, 1e-9,
                 "expected journalctl fixture parse success rate");

    expect(result.events[0].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid-user failed password");
    expect(result.events[1].event_type == loglens::EventType::SshFailedPublicKey, "expected journalctl failed publickey variant");
    expect(result.events[2].event_type == loglens::EventType::SshInvalidUser, "expected journalctl invalid user variant");
    expect(result.events[3].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl input_userauth_request invalid-user variant");
    expect(result.events[3].username == "svc-verbose",
           "expected journalctl input_userauth_request invalid username");
    expect(result.events[3].source_ip.empty(),
           "expected journalctl input_userauth_request invalid-user fixture to stay source-less");
    expect(result.events[4].event_type == loglens::EventType::PamAuthFailure, "expected journalctl pam auth failure variant");
    expect(result.events[5].event_type == loglens::EventType::SessionOpened, "expected journalctl sudo session-opened variant");
    expect(result.events[6].event_type == loglens::EventType::SessionOpened, "expected journalctl su-l session-opened variant");
    expect(result.events[7].event_type == loglens::EventType::SshAcceptedPassword, "expected journalctl accepted password variant");
    expect(result.events[8].event_type == loglens::EventType::SshAcceptedPublicKey, "expected journalctl accepted publickey variant");
    expect(result.events[9].event_type == loglens::EventType::SshAcceptedKeyboardInteractive,
           "expected journalctl accepted keyboard-interactive variant");
    expect(result.events[10].event_type == loglens::EventType::SudoAuthFailure,
           "expected journalctl sudo auth failure variant");
    expect(result.events[11].event_type == loglens::EventType::SudoPolicyDenied,
           "expected journalctl sudo policy denied variant");
    expect(result.events[12].event_type == loglens::EventType::SuAuthFailure,
           "expected journalctl su auth failure variant");
    expect(result.events[13].event_type == loglens::EventType::SessionOpened,
           "expected journalctl su success session-opened variant");
    expect(result.events[14].event_type == loglens::EventType::SshFailedKeyboardInteractive,
           "expected journalctl failed keyboard-interactive variant");
    expect(result.events[15].event_type == loglens::EventType::SshMaxAuthTries,
           "expected journalctl max-auth-tries variant");
    expect(result.events[16].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl keyboard-interactive invalid-user variant");
    expect(result.events[16].username == "svc-keyboard",
           "expected journalctl keyboard-interactive invalid username");
    expect(result.events[17].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl max-auth-tries invalid-user variant");
    expect(result.events[17].username == "svc-maxauth", "expected journalctl max-auth-tries invalid username");
    expect(result.events[18].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl failed-password illegal-user variant");
    expect(result.events[18].username == "legacy-admin", "expected journalctl failed-password illegal username");
    expect(result.events[19].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl direct illegal-user variant");
    expect(result.events[19].username == "legacy-backup", "expected journalctl direct illegal username");
    expect(result.events[20].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl failed-none invalid-user variant");
    expect(result.events[20].username == "svc-none", "expected journalctl failed-none invalid username");
    expect(result.events[21].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl failed-none illegal-user variant");
    expect(result.events[21].username == "legacy-none", "expected journalctl failed-none illegal username");
    expect(result.events[22].event_type == loglens::EventType::SshInvalidUser,
           "expected journalctl error-prefixed max-auth-tries invalid-user variant");
    expect(result.events[22].username == "svc-error-maxauth",
           "expected journalctl error-prefixed max-auth-tries invalid username");

    expect(result.quality.top_unknown_patterns.size() == 4, "expected four unknown journalctl buckets");
    expect(result.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth",
           "expected preauth connection-close journalctl bucket");
    expect(result.quality.top_unknown_patterns[0].count == 4, "expected four preauth connection-close/reset journalctl lines");
    expect(result.quality.top_unknown_patterns[1].pattern == "sshd_timeout_or_disconnection",
           "expected timeout/disconnection journalctl bucket");
    expect(result.quality.top_unknown_patterns[1].count == 3, "expected three timeout/disconnection journalctl lines");
    expect(result.quality.top_unknown_patterns[2].pattern == "pam_unix_session_closed",
           "expected pam_unix session-closed journalctl bucket");
    expect(result.quality.top_unknown_patterns[2].count == 1, "expected one pam_unix session-closed journalctl line");
    expect(result.quality.top_unknown_patterns[3].pattern == "sshd_negotiation_failure",
           "expected sshd negotiation-failure journalctl bucket");
    expect(result.quality.top_unknown_patterns[3].count == 1, "expected one sshd negotiation-failure journalctl line");
}

void test_noisy_auth_fixture_matrix_file() {
    const auto parser = make_syslog_parser();
    const auto result = parser.parse_file(asset_path("noisy_auth_sample.log"));

    expect(result.events.size() == 8, "expected eight parsed noisy-auth events");
    expect(result.warnings.size() == 16, "expected sixteen noisy-auth warnings");
    expect(total_input_lines(result) == 27, "expected noisy-auth total input line count");
    expect(result.quality.total_lines == 24, "expected noisy-auth nonblank line count");
    expect(result.quality.skipped_blank_lines == 3, "expected noisy-auth skipped blank line count");
    expect(result.quality.parsed_lines == 8, "expected noisy-auth parsed line count");
    expect(result.quality.unparsed_lines == 16, "expected noisy-auth unparsed line count");
    expect_close(result.quality.parse_success_rate, 8.0 / 24.0, 1e-9,
                 "expected noisy-auth parse success rate");

    expect(result.events[0].hostname == "alpha-host", "expected first noisy-auth host");
    expect(result.events[0].username == "svc+deploy", "expected unusual invalid-user username");
    expect(result.events[1].hostname == "beta-host", "expected second noisy-auth host");
    expect(result.events[1].username == "ops.robot", "expected dotted accepted-password username");
    expect(result.events[2].event_type == loglens::EventType::SudoCommand,
           "expected noisy-auth sudo command event");
    expect(result.events[3].event_type == loglens::EventType::SudoPolicyDenied,
           "expected noisy-auth sudoers denial event");
    expect(result.events[4].event_type == loglens::EventType::SudoPolicyDenied,
           "expected noisy-auth command-not-allowed denial event");
    expect(result.events[5].event_type == loglens::EventType::PamAuthFailure,
           "expected partial pam_unix failure to remain parsed lower-confidence evidence");
    expect(result.events[5].username.empty(), "expected partial pam_unix failure to stay username-less");
    expect(result.events[5].source_ip.empty(), "expected partial pam_unix failure to stay source-less");
    expect(result.events[7].hostname == "delta-host", "expected noisy-auth multi-host coverage");
    expect(result.events[7].username == "weird/user", "expected slash username in input_userauth_request");

    const auto actual = noisy_auth_coverage_json(result);
    const auto expected = read_text_file(parser_matrix_fixture_path("noisy_auth_expected.json"));
    expect(actual == expected, "expected noisy auth coverage summary to match fixture");
}

void test_mixed_auth_corpus_fixture_file() {
    const auto parser = make_syslog_parser();
    const auto result = parser.parse_file(asset_path("mixed_auth_corpus.log"));

    expect(total_input_lines(result) == 160, "expected mixed auth corpus total input line count");
    expect(result.quality.total_lines == 150, "expected mixed auth corpus nonblank line count");
    expect(result.quality.skipped_blank_lines == 10, "expected mixed auth corpus skipped blank line count");
    expect(result.events.size() == 100, "expected one hundred mixed auth corpus parsed events");
    expect(result.warnings.size() == 50, "expected fifty mixed auth corpus warnings");
    expect(result.quality.parsed_lines == 100, "expected mixed auth corpus parsed line count");
    expect(result.quality.unparsed_lines == 50, "expected mixed auth corpus unparsed line count");
    expect_close(result.quality.parse_success_rate, 100.0 / 150.0, 1e-9,
                 "expected mixed auth corpus parse success rate");

    expect(event_count(result.events, loglens::EventType::SshInvalidUser) == 10,
           "expected ten mixed corpus invalid-user events");
    expect(event_count(result.events, loglens::EventType::SshFailedPublicKey) == 10,
           "expected ten mixed corpus failed-publickey events");
    expect(event_count(result.events, loglens::EventType::SshAcceptedPublicKey) == 10,
           "expected ten mixed corpus accepted-publickey events");
    expect(event_count(result.events, loglens::EventType::SudoCommand) == 10,
           "expected ten mixed corpus sudo command events");
    expect(event_count(result.events, loglens::EventType::SudoAuthFailure) == 10,
           "expected ten mixed corpus sudo auth-failure events");
    expect(event_count(result.events, loglens::EventType::PamAuthFailure) == 36,
           "expected thirty-six mixed corpus PAM auth-failure events");
    expect(event_count(result.events, loglens::EventType::SessionOpened) == 4,
           "expected four mixed corpus session-opened events");
    expect(event_count(result.events, loglens::EventType::SuAuthFailure) == 10,
           "expected ten mixed corpus su auth-failure events");

    expect(unknown_pattern_count(result.quality, "invalid_month_token") == 10,
           "expected ten invalid-month telemetry buckets");
    expect(unknown_pattern_count(result.quality, "malformed_source_ip") == 10,
           "expected ten malformed-source-IP telemetry buckets");
    expect(unknown_pattern_count(result.quality, "pam_unix_session_closed") == 10,
           "expected ten pam_unix session-closed telemetry buckets");
    expect(unknown_pattern_count(result.quality, "program_cron") == 10,
           "expected ten unsupported-program telemetry buckets");
    expect(unknown_pattern_count(result.quality, "sshd_connection_closed_preauth") == 10,
           "expected ten sshd preauth-close telemetry buckets");

    expect(failure_category_count(result.quality, loglens::ParserFailureCategory::KnownProgramUnknownMessage) == 10,
           "expected ten known-program unknown-message failures");
    expect(failure_category_count(result.quality, loglens::ParserFailureCategory::MalformedSourceIp) == 10,
           "expected ten malformed-source-IP failures");
    expect(failure_category_count(result.quality, loglens::ParserFailureCategory::UnknownProgram) == 10,
           "expected ten unknown-program failures");
    expect(failure_category_count(result.quality, loglens::ParserFailureCategory::UnknownTimestamp) == 10,
           "expected ten unknown-timestamp failures");
    expect(failure_category_count(result.quality, loglens::ParserFailureCategory::UnsupportedPamVariant) == 10,
           "expected ten unsupported-PAM-variant failures");

    const auto actual = mixed_auth_coverage_json(result);
    const auto expected = read_text_file(asset_path("mixed_auth_parser_coverage.json"));
    expect(actual == expected, "expected mixed auth parser coverage artifact to match fixture");
}

void test_login_handler_normalizes_selected_util_linux_messages() {
    struct LoginCase {
        std::string message;
        loglens::EventType event_type;
        std::string username;
    };

    const std::vector<LoginCase> cases{
        {"FAILED LOGIN 1 FROM tty1 FOR user-a, Authentication failure",
         loglens::EventType::PamAuthFailure,
         "user-a"},
        {"TOO MANY LOGIN TRIES (3) FROM tty1 FOR user-b, Authentication failure",
         loglens::EventType::PamAuthFailure,
         "user-b"},
        {"FAILED LOGIN SESSION FROM tty1 FOR user-c, Authentication failure",
         loglens::EventType::PamAuthFailure,
         "user-c"},
        {"FAILED LOGIN 1 FROM tty1 FOR (unknown), Authentication failure",
         loglens::EventType::PamAuthFailure,
         ""},
        {"LOGIN ON tty1 BY user-d", loglens::EventType::SessionOpened, "user-d"},
        {"LOGIN ON tty1 BY user-e FROM example-console", loglens::EventType::SessionOpened, "user-e"},
        {"ROOT LOGIN ON tty2", loglens::EventType::SessionOpened, "root"},
    };

    const auto parser = make_syslog_parser();
    for (std::size_t index = 0; index < cases.size(); ++index) {
        const auto line = "Mar 10 08:19:00 example-host login[4050]: " + cases[index].message;
        const auto event = parser.parse_line(line, index + 1);

        expect(event.has_value(), "expected selected util-linux login message to emit an event");
        expect(event->program == "login", "expected login program to be preserved");
        expect(event->event_type == cases[index].event_type, "expected login message event type");
        expect(event->username == cases[index].username, "expected login message username");
        expect(event->source_ip.empty(), "expected login message not to infer a network source IP");
    }
}

void test_login_handler_keeps_unsupported_message_visible() {
    const auto parser = make_syslog_parser();
    const std::vector<std::string> messages{
        "DIALUP AT ttyS0 BY user-a",
        "FAILED LOGIN many FROM tty1 FOR user-a, Authentication failure",
        "FAILED LOGIN 1 FROM  FOR user-a, Authentication failure",
        "FAILED LOGIN 1 FROM tty1 FOR user-a,",
        "LOGIN ON  BY user-a",
        "LOGIN ON tty1 BY user-a FROM ",
        "ROOT LOGIN ON  FROM example-console",
        "ROOT LOGIN ON tty1 FROM ",
    };

    for (std::size_t index = 0; index < messages.size(); ++index) {
        std::string reason;
        auto category = loglens::ParserFailureCategory::UnknownProgram;
        const auto event = parser.parse_line(
            "Mar 10 08:19:10 example-host login[4051]: " + messages[index],
            index + 1,
            &reason,
            &category);

        expect(!event.has_value(), "expected unsupported login message not to emit an event");
        expect(category == loglens::ParserFailureCategory::KnownProgramUnknownMessage,
               "expected unsupported login message to remain a known-program failure");
        expect(reason == "unrecognized auth pattern: login_other",
               "expected stable unsupported login pattern bucket");
    }
}

void test_journalctl_login_handler_variants() {
    const auto parser = make_journalctl_parser();
    const auto failure = parser.parse_line(
        "Mon 2026-03-10 08:19:20 UTC example-host login[4052]: "
        "FAILED LOGIN 1 FROM tty1 FOR user-a, Authentication failure",
        1);
    const auto success = parser.parse_line(
        "Mon 2026-03-10 08:19:21 UTC example-host login[4053]: LOGIN ON tty1 BY user-b",
        2);

    expect(failure.has_value(), "expected journalctl login failure event");
    expect(failure->event_type == loglens::EventType::PamAuthFailure,
           "expected journalctl login failure normalization");
    expect(failure->username == "user-a", "expected journalctl login failure username");
    expect(success.has_value(), "expected journalctl login success event");
    expect(success->event_type == loglens::EventType::SessionOpened,
           "expected journalctl login success normalization");
    expect(success->username == "user-b", "expected journalctl login success username");
}

void test_program_handler_registry_routes_supported_families() {
    struct RegistryCase {
        std::string line;
        std::string program;
        loglens::EventType event_type;
    };

    const std::vector<RegistryCase> cases{
        {"Mar 10 08:20:01 example-host sshd[4101]: Failed password for user-a from 203.0.113.41 port 50101 ssh2",
         "sshd",
         loglens::EventType::SshFailedPassword},
        {"Mar 10 08:20:02 example-host pam_unix(sshd:auth): authentication failure; rhost=203.0.113.42 user=user-b",
         "pam_unix(sshd:auth)",
         loglens::EventType::PamAuthFailure},
        {"Mar 10 08:20:03 example-host pam_faillock(sshd:auth): Authentication failure for user user-c from 203.0.113.43",
         "pam_faillock(sshd:auth)",
         loglens::EventType::PamAuthFailure},
        {"Mar 10 08:20:04 example-host pam_sss(sshd:auth): received for user user-d: 7 (Authentication failure)",
         "pam_sss(sshd:auth)",
         loglens::EventType::PamAuthFailure},
        {"Mar 10 08:20:05 example-host sudo[4105]:    user-e : TTY=pts/1 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id",
         "sudo",
         loglens::EventType::SudoCommand},
        {"Mar 10 08:20:06 example-host su[4106]: FAILED SU (to root) user-f on pts/2",
         "su",
         loglens::EventType::SuAuthFailure},
        {"Mar 10 08:20:07 example-host login[4107]: FAILED LOGIN 1 FROM tty1 FOR user-g, Authentication failure",
         "login",
         loglens::EventType::PamAuthFailure},
    };

    const auto parser = make_syslog_parser();
    for (std::size_t index = 0; index < cases.size(); ++index) {
        const auto event = parser.parse_line(cases[index].line, index + 1);
        expect(event.has_value(), "expected registered program handler to emit an event");
        expect(event->program == cases[index].program, "expected registry to preserve the source program");
        expect(event->event_type == cases[index].event_type, "expected registry to select the matching handler");
    }
}

void test_parse_stream_accepts_crlf_line_terminator() {
    std::istringstream input(
        "Mar 10 08:21:01 example-host pam_faillock(sshd:auth): Authentication failure for user user-a from 203.0.113.51\r\n");

    const auto parser = make_syslog_parser();
    const auto result = parser.parse_stream(input);

    expect(result.events.size() == 1, "expected CRLF input to emit one event");
    expect(result.warnings.empty(), "expected CRLF input not to emit a malformed-IP warning");
    expect(result.events.front().source_ip == "203.0.113.51", "expected CR to be excluded from source IP");
}

}  // namespace

int main() {
    test_invalid_user_failure();
    test_illegal_user_failure_is_normalized_as_invalid_user();
    test_failed_none_invalid_user_is_normalized_as_invalid_user();
    test_failed_none_illegal_user_is_normalized_as_invalid_user();
    test_failed_none_without_invalid_user_stays_unsupported();
    test_illegal_user_message_is_normalized_as_invalid_user();
    test_input_userauth_request_invalid_user_is_normalized_as_invalid_user();
    test_input_userauth_request_illegal_user_is_normalized_as_invalid_user();
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
    test_failed_publickey_illegal_user_event();
    test_failed_keyboard_interactive_event();
    test_failed_keyboard_interactive_invalid_user_event();
    test_failed_keyboard_interactive_illegal_user_event();
    test_max_auth_tries_event();
    test_max_auth_tries_error_prefix_event();
    test_max_auth_tries_invalid_user_event();
    test_max_auth_tries_illegal_user_event();
    test_ssh_pam_auth_failure_event();
    test_ssh_pam_auth_failure_invalid_user_event();
    test_ssh_pam_auth_failure_illegal_user_event();
    test_ssh_pam_auth_failure_error_prefix_event();
    test_pam_auth_failure_event();
    test_pam_sss_received_failure_event();
    test_session_opened_event();
    test_journalctl_short_full_event();
    test_journalctl_numeric_timezone_offsets();
    test_input_mode_aliases();
    test_syslog_auth_family_fixture_file();
    test_journalctl_auth_family_fixture_file();
    test_malformed_line();
    test_parser_failure_taxonomy();
    test_malformed_source_ip_token_corpus();
    test_unknown_auth_patterns_are_warnings_only();
    test_stream_warnings_and_metadata();
    test_stream_tracks_skipped_blank_lines();
    test_journalctl_metadata();
    test_journalctl_rejects_empty_fractional_seconds();
    test_syslog_fixture_matrix_file();
    test_journalctl_fixture_matrix_file();
    test_noisy_auth_fixture_matrix_file();
    test_mixed_auth_corpus_fixture_file();
    test_login_handler_normalizes_selected_util_linux_messages();
    test_login_handler_keeps_unsupported_message_visible();
    test_journalctl_login_handler_variants();
    test_program_handler_registry_routes_supported_families();
    test_parse_stream_accepts_crlf_line_terminator();
    return 0;
}
