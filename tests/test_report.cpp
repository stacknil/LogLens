#include "report.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

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
    expect(json.find("\"line_number\": 13, \"reason\": \"unrecognized auth pattern: sshd_connection_closed_preauth\"")
               != std::string::npos,
           "expected noisy report json to keep unsupported sshd warning visible");
    expect(json.find("\"line_number\": 24, \"reason\": \"unrecognized auth pattern: sudo_other\"")
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
    expect(markdown.find("| 1 | bad \\| value<br>next &lt;tag&gt; &amp; more |") != std::string::npos,
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
    expect(warnings_csv.find("parse_warning,2,'=warning") != std::string::npos,
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

}  // namespace

int main() {
    test_noisy_auth_report_json_keeps_unsupported_lines_visible();
    test_markdown_table_cells_escape_user_controlled_values();
    test_json_escapes_generic_control_characters();
    test_reports_include_total_input_line_count();
    test_csv_neutralizes_formula_like_fields();
    test_write_reports_fails_when_report_path_is_directory();
    test_write_reports_writes_default_report_files();
    test_write_reports_fails_when_output_path_is_file();
    test_write_reports_preserves_existing_csv_when_csv_is_disabled();
    test_write_reports_reports_csv_write_failure();
    return 0;
}
