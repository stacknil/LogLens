#include "report.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
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

std::chrono::sys_seconds timestamp_at_minute(int minute_value) {
    using namespace std::chrono;
    return sys_days{year{2026} / month{3} / day{10}} + hours{8} + minutes{minute_value};
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to read file: " + path.string());
    }

    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
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

loglens::ReportData make_report_data() {
    loglens::ReportData data;
    data.input_path = std::filesystem::path{"assets/sample_auth.log"};
    data.parse_metadata.input_mode = loglens::InputMode::SyslogLegacy;
    data.parse_metadata.assume_year = 2026;
    data.parse_metadata.timezone_present = false;
    data.parser_quality.total_lines = 1;
    data.parser_quality.unparsed_lines = 1;
    data.parser_quality.top_unknown_patterns.push_back({"bad_pattern", 1});
    return data;
}

void test_noisy_auth_report_json_keeps_unsupported_lines_visible() {
    const auto input_path = asset_path("noisy_auth_sample.log");
    const loglens::AuthLogParser parser(loglens::ParserConfig{
        loglens::InputMode::SyslogLegacy,
        2026});
    const auto parsed = parser.parse_file(input_path);

    const loglens::Detector detector;
    const auto findings = detector.analyze(parsed.events);

    loglens::ReportData data;
    data.input_path = std::filesystem::path{"assets/noisy_auth_sample.log"};
    data.parse_metadata = parsed.metadata;
    data.parser_quality = parsed.quality;
    data.events = parsed.events;
    data.findings = findings;
    data.warnings = parsed.warnings;
    data.auth_signal_mappings = detector.config().auth_signal_mappings;

    const auto json = loglens::render_json_report(data);

    expect(findings.empty(), "expected noisy unsupported lines not to create findings");
    expect(json.find("\"parse_success_rate\": 0.3333") != std::string::npos,
           "expected noisy report json parse success rate");
    expect(json.find("\"parsed_event_count\": 8") != std::string::npos,
           "expected noisy report json parsed event count");
    expect(json.find("\"warning_count\": 16") != std::string::npos,
           "expected noisy report json warning count");
    expect(json.find("\"finding_count\": 0") != std::string::npos,
           "expected noisy report json finding count");
    expect(json.find("\"pattern\": \"sshd_connection_closed_preauth\", \"count\": 2") != std::string::npos,
           "expected noisy report json stable sshd preauth bucket");
    expect(json.find("\"pattern\": \"pam_faillock_account_locked\", \"count\": 2") != std::string::npos,
           "expected noisy report json stable pam_faillock account-lock bucket");
    expect(json.find("\"line_number\": 13, \"category\": \"known_program_unknown_message\", \"reason\": \"unrecognized auth pattern: sshd_connection_closed_preauth\"")
               != std::string::npos,
           "expected noisy report json to keep unsupported sshd warning visible");
    expect(json.find("\"line_number\": 24, \"category\": \"known_program_unknown_message\", \"reason\": \"unrecognized auth pattern: sudo_other\"")
               != std::string::npos,
           "expected noisy report json to keep unsupported partial sudo warning visible");
}

void test_markdown_table_cells_escape_user_controlled_values() {
    auto data = make_report_data();

    loglens::Finding finding;
    finding.type = loglens::FindingType::SudoBurst;
    finding.subject_kind = "username";
    finding.subject = "ali|ce";
    finding.event_count = 3;
    finding.first_seen = timestamp_at_minute(21);
    finding.last_seen = timestamp_at_minute(24);
    finding.usernames = {"ali|ce", "bob<root>"};
    finding.summary = "summary | <raw> & more";
    data.findings.push_back(finding);
    data.warnings.push_back({1, "bad | value\nnext <tag> & more"});

    const auto markdown = loglens::render_markdown_report(data);

    expect(markdown.find("| sudo_burst | ali\\|ce | 3 |") != std::string::npos,
           "expected markdown finding subject to escape table pipes");
    expect(markdown.find("summary \\| &lt;raw&gt; &amp; more Usernames: ali\\|ce, bob&lt;root&gt;")
               != std::string::npos,
           "expected markdown finding notes to escape table and html-sensitive characters");
    expect(markdown.find("| 1 | known_program_unknown_message | bad \\| value<br>next &lt;tag&gt; &amp; more |")
               != std::string::npos,
           "expected markdown warning reason to escape table pipes and newlines");
}

void test_json_escapes_generic_control_characters() {
    auto data = make_report_data();

    std::string reason = "bad ";
    reason.push_back('\x01');
    reason += " \"quote\"";
    data.warnings.push_back({7, reason});

    const auto json = loglens::render_json_report(data);

    expect(json.find('\x01') == std::string::npos, "expected raw control character to be absent from json");
    expect(json.find("\"reason\": \"bad \\u0001 \\\"quote\\\"\"") != std::string::npos,
           "expected json warning reason to use valid escapes");
}

void test_json_finding_includes_explainability_fields() {
    auto data = make_report_data();

    loglens::Finding finding;
    finding.type = loglens::FindingType::SudoBurst;
    finding.rule_id = "sudo_burst";
    finding.subject_kind = "username";
    finding.subject = "alice";
    finding.grouping_key = "username";
    finding.threshold = 3;
    finding.observed_count = 4;
    finding.event_count = 4;
    finding.first_seen = timestamp_at_minute(21);
    finding.last_seen = timestamp_at_minute(24);
    finding.evidence_event_ids = {"line:6", "line:7", "line:8", "line:9"};
    finding.verdict_boundary = "triage_signal_not_maliciousness_or_authorization";
    finding.summary = "alice ran 4 sudo commands within 5 minutes.";
    data.findings.push_back(finding);

    const auto json = loglens::render_json_report(data);

    expect(json.find("\"finding_id\": \"finding:sudo_burst:") != std::string::npos,
           "expected json finding to include stable finding id");
    expect(json.find("\"rule_id\": \"sudo_burst\"") != std::string::npos,
           "expected json finding to include rule id");
    expect(json.find("\"episode_index\": 1") != std::string::npos,
           "expected json finding to include episode index");
    expect(json.find("\"grouping_key\": \"username\"") != std::string::npos,
           "expected json finding to include grouping key");
    expect(json.find("\"threshold\": 3") != std::string::npos,
           "expected json finding to include threshold");
    expect(json.find("\"observed_count\": 4") != std::string::npos,
           "expected json finding to include observed count");
    expect(json.find("\"evidence_event_ids\": [\"line:6\", \"line:7\", \"line:8\", \"line:9\"]")
               != std::string::npos,
           "expected json finding to include evidence event ids");
    expect(json.find("\"verdict_boundary\": \"triage_signal_not_maliciousness_or_authorization\"")
               != std::string::npos,
           "expected json finding to include verdict boundary");
}

void test_json_report_includes_schema_identity() {
    const auto json = loglens::render_json_report(make_report_data());

    expect(json.find("\"schema\": \"loglens.report.v3\"") != std::string::npos,
           "expected json report to include schema identifier");
    expect(json.find("\"schema_version\": 3") != std::string::npos,
           "expected json report to include schema version");
}

void test_reports_include_total_input_line_count() {
    auto data = make_report_data();
    data.parser_quality.total_lines = 3;
    data.parser_quality.skipped_blank_lines = 2;

    const auto markdown = loglens::render_markdown_report(data);
    const auto json = loglens::render_json_report(data);

    expect(markdown.find("Total input lines: 5") != std::string::npos,
           "expected markdown report to include total input line count");
    expect(json.find("\"total_input_lines\": 5") != std::string::npos,
           "expected json report to include total input line count");
}

void test_csv_neutralizes_formula_like_fields() {
    auto data = make_report_data();

    loglens::Finding finding;
    finding.type = loglens::FindingType::SudoBurst;
    finding.subject_kind = "username";
    finding.subject = "=alice";
    finding.event_count = 3;
    finding.first_seen = timestamp_at_minute(21);
    finding.last_seen = timestamp_at_minute(24);
    finding.usernames = {"+bob", "-carol", "@dave"};
    finding.summary = " @summary";
    data.findings.push_back(finding);
    data.warnings.push_back({2, "=warning"});

    const auto findings_csv = loglens::render_findings_csv(data);
    const auto warnings_csv = loglens::render_warnings_csv(data);

    expect(findings_csv.find("sudo_burst,username,'=alice,3,") != std::string::npos,
           "expected formula-like finding subject to be neutralized");
    expect(findings_csv.find(",'+bob;-carol;@dave,' @summary") != std::string::npos,
           "expected formula-like usernames and summary to be neutralized");
    expect(warnings_csv.find("parse_warning,2,known_program_unknown_message,'=warning") != std::string::npos,
           "expected formula-like warning reason to be neutralized");
}

void test_write_reports_fails_when_report_path_is_directory() {
    const auto output_directory = std::filesystem::current_path() / "report_write_failure_test";
    std::filesystem::remove_all(output_directory);
    std::filesystem::create_directories(output_directory / "report.md");

    bool threw = false;
    std::string message;
    try {
        loglens::write_reports(make_report_data(), output_directory);
    } catch (const std::runtime_error& error) {
        threw = true;
        message = error.what();
    }

    std::filesystem::remove_all(output_directory);

    expect(threw, "expected write_reports to fail when report.md cannot be opened");
    expect(message.find("report.md") != std::string::npos,
           "expected write_reports failure to mention report.md");
}

void test_write_reports_writes_default_report_files() {
    const auto output_directory = std::filesystem::current_path() / "report_success_test";
    std::filesystem::remove_all(output_directory);

    loglens::write_reports(make_report_data(), output_directory);

    const auto markdown = read_file(output_directory / "report.md");
    const auto json = read_file(output_directory / "report.json");

    expect(markdown.find("# LogLens Report") != std::string::npos,
           "expected default report run to write markdown report");
    expect(markdown.find("Total input lines: 1") != std::string::npos,
           "expected default markdown report to include total input line count");
    expect(markdown.find("Skipped blank lines: 0") != std::string::npos,
           "expected default markdown report to include skipped blank line count");
    expect(json.find("\"tool\": \"LogLens\"") != std::string::npos,
           "expected default report run to write json report");
    expect(json.find("\"total_input_lines\": 1") != std::string::npos,
           "expected default json report to include total input line count");
    expect(json.find("\"skipped_blank_lines\": 0") != std::string::npos,
           "expected default json report to include skipped blank line count");
    expect(!std::filesystem::exists(output_directory / "findings.csv"),
           "did not expect findings.csv without csv flag");
    expect(!std::filesystem::exists(output_directory / "warnings.csv"),
           "did not expect warnings.csv without csv flag");

    std::filesystem::remove_all(output_directory);
}

void test_write_reports_fails_when_output_path_is_file() {
    const auto output_path = std::filesystem::current_path() / "report_output_file_test";
    std::filesystem::remove(output_path);
    {
        std::ofstream output(output_path);
        output << "not a directory\n";
    }

    bool threw = false;
    std::string message;
    try {
        loglens::write_reports(make_report_data(), output_path);
    } catch (const std::runtime_error& error) {
        threw = true;
        message = error.what();
    }

    std::filesystem::remove(output_path);

    expect(threw, "expected write_reports to fail when output path is a file");
    expect(message.find("report_output_file_test") != std::string::npos,
           "expected output directory failure to mention the output path");
}

void test_write_reports_preserves_existing_csv_when_csv_is_disabled() {
    const auto output_directory = std::filesystem::current_path() / "report_existing_csv_preservation_test";
    std::filesystem::remove_all(output_directory);
    std::filesystem::create_directories(output_directory);

    {
        std::ofstream output(output_directory / "findings.csv");
        output << "keep-findings\n";
    }
    {
        std::ofstream output(output_directory / "warnings.csv");
        output << "keep-warnings\n";
    }

    loglens::write_reports(make_report_data(), output_directory, false);

    expect(read_file(output_directory / "findings.csv") == "keep-findings\n",
           "expected existing findings.csv to be preserved when csv is disabled");
    expect(read_file(output_directory / "warnings.csv") == "keep-warnings\n",
           "expected existing warnings.csv to be preserved when csv is disabled");

    std::filesystem::remove_all(output_directory);
}

void test_write_reports_reports_csv_write_failure() {
    const auto output_directory = std::filesystem::current_path() / "report_csv_write_failure_test";
    std::filesystem::remove_all(output_directory);
    std::filesystem::create_directories(output_directory / "findings.csv" / "nested");

    bool threw = false;
    std::string message;
    try {
        loglens::write_reports(make_report_data(), output_directory, true);
    } catch (const std::runtime_error& error) {
        threw = true;
        message = error.what();
    }

    std::filesystem::remove_all(output_directory);

    expect(threw, "expected write_reports to fail when findings.csv cannot be written");
    expect(message.find("findings.csv") != std::string::npos,
           "expected csv write failure to mention findings.csv");
}

void test_privilege_auth_events_remain_visible_without_findings() {
    const std::array<std::string, 3> types{
        "sudo_auth_failure", "sudo_policy_denied", "su_auth_failure"};
    for (const bool journal : {false, true}) {
        const std::string header = journal
            ? "Tue 2026-03-10 08:21:40 UTC example-host "
            : "Mar 10 08:21:40 example-host ";
        std::istringstream input(
            header + "sudo[4201]: user-a : 1 incorrect password attempt ; TTY=pts/0 ; "
                     "PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id\n"
            + header + "sudo[4202]: user-a : user NOT in sudoers ; TTY=pts/0 ; "
                       "PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id\n"
            + header + "su[4203]: FAILED SU (to root) user-a on pts/0\n");
        const loglens::AuthLogParser parser({
            journal ? loglens::InputMode::JournalctlShortFull : loglens::InputMode::SyslogLegacy,
            2026});
        const auto parsed = parser.parse_stream(input);
        loglens::ReportData data;
        data.input_path = "synthetic.log";
        data.parse_metadata = parsed.metadata;
        data.parser_quality = parsed.quality;
        data.events = parsed.events;
        data.warnings = parsed.warnings;
        data.findings = loglens::Detector{}.analyze(data.events);
        expect(data.events.size() == 3 && data.warnings.empty() && data.findings.empty(),
               "expected three parsed audit events without warnings or findings");
        const auto json = loglens::render_json_report(data);
        const auto markdown = loglens::render_markdown_report(data);
        expect(json.find("\"parsed_event_count\": 3") != std::string::npos,
               "expected all three audit events in report total");
        for (const auto& type : types) {
            expect(json.find("\"event_type\": \"" + type + "\", \"count\": 1") != std::string::npos,
                   "missing parsed audit event count in JSON: " + type);
            expect(markdown.find("| " + type + " | 1 |") != std::string::npos,
                   "missing parsed audit event count in Markdown: " + type);
        }
        expect(markdown.find("No configured detections matched") != std::string::npos,
               "report visibility must not promote audit events into findings");
    }
}

std::size_t reported_number(std::string_view json, std::string_view key) {
    const auto position = json.find(key);
    expect(position != std::string_view::npos, "missing report number: " + std::string(key));
    const auto value = json.substr(position + key.size());
    std::size_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
    expect(result.ec == std::errc{}, "invalid report number");
    return number;
}

void expect_event_count_total(std::string_view json, std::size_t expected) {
    const auto key = json.find("\"event_counts\": [");
    expect(key != std::string_view::npos, "missing event_counts");
    const auto end = json.find(']', key);
    expect(end != std::string_view::npos, "missing event_counts end");
    auto counts = json.substr(key, end - key);
    std::size_t total = 0;
    while (true) {
        const auto entry = counts.find("\"count\": ");
        if (entry == std::string_view::npos) {
            break;
        }
        counts.remove_prefix(entry);
        total += reported_number(counts, "\"count\": ");
        counts.remove_prefix(std::string_view{"\"count\": "}.size());
    }
    expect(total == expected, "event_counts must account for every normalized event");
    expect(reported_number(json, "\"parsed_event_count\": ") == total,
           "event_counts sum must equal parsed_event_count");
}

void test_ssh_report_counts_are_complete_globally_and_per_host() {
    const std::array<std::string, 3> messages{
        "Accepted keyboard-interactive/pam for user-a from 203.0.113.10 port 50101 ssh2",
        "Failed keyboard-interactive/pam for user-a from 203.0.113.10 port 50101 ssh2",
        "maximum authentication attempts exceeded for user-a from 203.0.113.10 port 50101 ssh2 [preauth]"};
    const std::array<loglens::EventType, 3> types{
        loglens::EventType::SshAcceptedKeyboardInteractive,
        loglens::EventType::SshFailedKeyboardInteractive,
        loglens::EventType::SshMaxAuthTries};
    for (const bool journal : {false, true}) {
        const std::string timestamp = journal
            ? "Tue 2026-03-10 08:21:40 UTC " : "Mar 10 08:21:40 ";
        const loglens::AuthLogParser parser({
            journal ? loglens::InputMode::JournalctlShortFull : loglens::InputMode::SyslogLegacy,
            2026});
        for (const bool two_hosts : {false, true}) {
            // Three SSH shapes, one repeated on host B: global 4, hosts A/B 2/2.
            std::string text;
            for (std::size_t index = 0; index < 4; ++index) {
                const auto hostname = two_hosts && index >= 2 ? "example-host-b" : "example-host-a";
                text += timestamp + hostname + " sshd[4200]: " + messages[index % 3] + '\n';
            }
            std::istringstream input(text);
            const auto parsed = parser.parse_stream(input);
            expect(parsed.events.size() == 4 && parsed.warnings.empty(),
                   "expected four normalized SSH events without warnings");
            for (std::size_t index = 0; index < parsed.events.size(); ++index) {
                expect(parsed.events[index].event_type == types[index % 3],
                       "expected the documented SSH event type before reporting");
            }
            loglens::ReportData data;
            data.input_path = "synthetic.log";
            data.parse_metadata = parsed.metadata;
            data.parser_quality = parsed.quality;
            data.events = parsed.events;
            data.findings = loglens::Detector{}.analyze(data.events);
            expect(data.findings.empty(), "fixture must remain below default detector thresholds");
            const auto json = loglens::render_json_report(data);
            const auto markdown = loglens::render_markdown_report(data);
            expect_event_count_total(json, 4);
            for (std::size_t index = 0; index < types.size(); ++index) {
                const auto type = loglens::to_string(types[index]);
                const auto count = std::to_string(index == 0 ? 2 : 1);
                expect(json.find("\"event_type\": \"" + type + "\", \"count\": " + count)
                           != std::string::npos, "missing SSH type count in JSON: " + type);
                expect(markdown.find("| " + type + " | " + count + " |") != std::string::npos,
                       "missing SSH type count in Markdown: " + type);
            }
            if (!two_hosts) {
                expect(json.find("\"host_summaries\"") == std::string::npos,
                       "single-host report shape must remain unchanged");
                continue;
            }
            const auto hosts = json.find("\"host_summaries\": [");
            expect(hosts != std::string::npos, "expected two-host summaries");
            const auto first = json.find("\"hostname\": \"example-host-a\"", hosts);
            const auto second = json.find("\"hostname\": \"example-host-b\"", hosts);
            expect(first != std::string::npos && second != std::string::npos && first < second,
                   "expected sorted summaries for both hosts");
            const std::string_view first_host{json.data() + first, second - first};
            const std::string_view second_host{json.data() + second, json.size() - second};
            expect_event_count_total(first_host, 2);
            expect_event_count_total(second_host, 2);
            expect(first_host.find("ssh_failed_keyboard_interactive") != std::string_view::npos
                   && first_host.find("ssh_max_auth_tries") == std::string_view::npos,
                   "host A counts must use only host A events");
            expect(second_host.find("ssh_max_auth_tries") != std::string_view::npos
                   && second_host.find("ssh_failed_keyboard_interactive") == std::string_view::npos,
                   "host B counts must use only host B events");
        }
    }
}

}  // namespace

int main() {
    test_ssh_report_counts_are_complete_globally_and_per_host();
    test_privilege_auth_events_remain_visible_without_findings();
    test_noisy_auth_report_json_keeps_unsupported_lines_visible();
    test_markdown_table_cells_escape_user_controlled_values();
    test_json_escapes_generic_control_characters();
    test_json_finding_includes_explainability_fields();
    test_json_report_includes_schema_identity();
    test_reports_include_total_input_line_count();
    test_csv_neutralizes_formula_like_fields();
    test_write_reports_fails_when_report_path_is_directory();
    test_write_reports_writes_default_report_files();
    test_write_reports_fails_when_output_path_is_file();
    test_write_reports_preserves_existing_csv_when_csv_is_disabled();
    test_write_reports_reports_csv_write_failure();
    return 0;
}
