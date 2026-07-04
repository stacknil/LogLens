#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "test_cli assertion failed: " << message << '\n';
        throw std::runtime_error(message);
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to read file: " + path.string());
    }

    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::string quote_argument(const std::filesystem::path& path) {
    return "\"" + path.string() + "\"";
}

std::string build_command(std::string invocation,
                          const std::filesystem::path* stdout_path = nullptr,
                          const std::filesystem::path* stderr_path = nullptr) {
    if (stdout_path != nullptr) {
        invocation += " 1>" + quote_argument(*stdout_path);
    }
    if (stderr_path != nullptr) {
        invocation += " 2>" + quote_argument(*stderr_path);
    }

#ifdef _WIN32
    return "cmd /c \"" + invocation + "\"";
#else
    return invocation;
#endif
}

void expect_report_core_fields(const std::string& markdown,
                               const std::string& json,
                               const std::string& input_mode,
                               bool expect_assume_year,
                               bool timezone_present) {
    expect(markdown.find("Input mode: " + input_mode) != std::string::npos, "expected markdown input mode");
    expect(markdown.find(std::string("Timezone present: ") + (timezone_present ? "true" : "false")) != std::string::npos,
           "expected markdown timezone metadata");
    if (expect_assume_year) {
        expect(markdown.find("Assume year: 2026") != std::string::npos, "expected markdown assume year");
        expect(json.find("\"assume_year\": 2026") != std::string::npos, "expected json assume_year");
    } else {
        expect(markdown.find("Assume year:") == std::string::npos, "did not expect markdown assume year");
        expect(json.find("\"assume_year\":") == std::string::npos, "did not expect json assume_year");
    }

    expect(markdown.find("Total lines: 16") != std::string::npos, "expected markdown total line count");
    expect(markdown.find("Parsed lines: 14") != std::string::npos, "expected markdown parsed line count");
    expect(markdown.find("Unparsed lines: 2") != std::string::npos, "expected markdown unparsed line count");
    expect(markdown.find("Parse success rate: 87.50%") != std::string::npos, "expected markdown parse success rate");
    expect(markdown.find("Parsed events: 14") != std::string::npos, "expected markdown parsed event count");
    expect(markdown.find("Findings: 3") != std::string::npos, "expected markdown finding count");
    expect(markdown.find("Parser warnings: 2") != std::string::npos, "expected markdown warning count");
    expect(markdown.find("| sshd_connection_closed_preauth | 1 |") != std::string::npos,
           "expected markdown unknown connection-close pattern");
    expect(markdown.find("| sshd_timeout_or_disconnection | 1 |") != std::string::npos,
           "expected markdown unknown timeout pattern");
    expect(json.find("\"total_lines\": 16") != std::string::npos, "expected json total line count");
    expect(json.find("\"parsed_lines\": 14") != std::string::npos, "expected json parsed line count");
    expect(json.find("\"unparsed_lines\": 2") != std::string::npos, "expected json unparsed line count");
    expect(json.find("\"parse_success_rate\": 0.8750") != std::string::npos, "expected json parse success rate");
    expect(json.find("\"parsed_event_count\": 14") != std::string::npos, "expected json parsed event count");
    expect(json.find("\"finding_count\": 3") != std::string::npos, "expected json finding count");
    expect(json.find("\"warning_count\": 2") != std::string::npos, "expected json warning count");
    expect(json.find("\"input_mode\": \"" + input_mode + "\"") != std::string::npos, "expected json input mode");
    expect(json.find(std::string("\"timezone_present\": ") + (timezone_present ? "true" : "false")) != std::string::npos,
           "expected json timezone metadata");
    expect(json.find("\"pattern\": \"sshd_connection_closed_preauth\"") != std::string::npos,
           "expected json unknown connection-close pattern");
    expect(json.find("\"pattern\": \"sshd_timeout_or_disconnection\"") != std::string::npos,
           "expected json unknown timeout pattern");
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 5) {
        throw std::runtime_error("expected arguments: <loglens_exe> <sample_log> <sample_config> <output_dir>");
    }

    const std::filesystem::path loglens_exe = std::filesystem::absolute(argv[1]);
    const std::filesystem::path sample_log = std::filesystem::absolute(argv[2]);
    const std::filesystem::path sample_config = std::filesystem::absolute(argv[3]);
    const std::filesystem::path output_dir = std::filesystem::absolute(argv[4]);
    const std::filesystem::path asset_dir = sample_log.parent_path();
    const std::filesystem::path journalctl_log = asset_dir / "sample_journalctl_short_full.log";

    std::filesystem::remove_all(output_dir);
    std::filesystem::create_directories(output_dir);

    const auto help_stdout = output_dir / "help_stdout.txt";
    const auto help_stderr = output_dir / "help_stderr.txt";
    const int help_exit = std::system(build_command(
        quote_argument(loglens_exe) + " --help",
        &help_stdout,
        &help_stderr)
                                          .c_str());
    const auto help_output = read_file(help_stdout);
    expect(help_exit == 0, "expected --help to succeed");
    expect(help_output.find("Usage:") != std::string::npos,
           "expected --help to print usage to stdout");
    expect(help_output.find("loglens --help") != std::string::npos,
           "expected --help usage to mention help command");
    expect(help_output.find("loglens --version") != std::string::npos,
           "expected --help usage to mention version command");
    expect(help_output.find("syslog|syslog-legacy|journalctl|journalctl-short-full") != std::string::npos,
           "expected --help usage to mention supported mode aliases");
    expect(help_output.find("[--config <config.json>]") != std::string::npos,
           "expected --help usage to mention analysis options");
    expect(help_output.find("--option=value") != std::string::npos,
           "expected --help usage to mention equals-style option syntax");
    expect(read_file(help_stderr).empty(), "expected --help to keep stderr empty");

    const auto version_stdout = output_dir / "version_stdout.txt";
    const auto version_stderr = output_dir / "version_stderr.txt";
    const int version_exit = std::system(build_command(
        quote_argument(loglens_exe) + " --version",
        &version_stdout,
        &version_stderr)
                                             .c_str());
    expect(version_exit == 0, "expected --version to succeed");
    expect(read_file(version_stdout) == "LogLens 0.5.0\n",
           "expected --version to print project version to stdout");
    expect(read_file(version_stderr).empty(), "expected --version to keep stderr empty");

    const auto syslog_cli_out = output_dir / "syslog_cli";
    std::filesystem::create_directories(syslog_cli_out);
    const int syslog_cli_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode syslog-legacy --year 2026 "
        + quote_argument(sample_log)
        + " " + quote_argument(syslog_cli_out))
                                                .c_str());
    expect(syslog_cli_exit == 0, "expected syslog CLI run with --year to succeed");

    const auto syslog_markdown = read_file(syslog_cli_out / "report.md");
    const auto syslog_json = read_file(syslog_cli_out / "report.json");
    expect_report_core_fields(syslog_markdown, syslog_json, "syslog_legacy", true, false);
    expect(!std::filesystem::exists(syslog_cli_out / "findings.csv"),
           "did not expect findings.csv without explicit csv flag");
    expect(!std::filesystem::exists(syslog_cli_out / "warnings.csv"),
           "did not expect warnings.csv without explicit csv flag");

    const auto leading_dash_log = output_dir / "-leading-dash-auth.log";
    std::filesystem::copy_file(sample_log, leading_dash_log, std::filesystem::copy_options::overwrite_existing);
    const auto leading_dash_out = output_dir / "leading_dash_input";
    std::filesystem::create_directories(leading_dash_out);
    const int leading_dash_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode syslog-legacy --year 2026 -- "
        + quote_argument(leading_dash_log)
        + " " + quote_argument(leading_dash_out))
                                                  .c_str());
    expect(leading_dash_exit == 0, "expected -- to allow input path beginning with dash");
    expect(read_file(leading_dash_out / "report.json").find("\"input_mode\": \"syslog_legacy\"")
               != std::string::npos,
           "expected leading-dash input run to produce syslog report");

    const auto csv_out = output_dir / "csv_run";
    std::filesystem::create_directories(csv_out);
    const int csv_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode=syslog-legacy --year=2026 --csv "
        + quote_argument(sample_log)
        + " " + quote_argument(csv_out))
                                         .c_str());
    expect(csv_exit == 0, "expected syslog CSV CLI run to succeed");
    const auto findings_csv = read_file(csv_out / "findings.csv");
    const auto warnings_csv = read_file(csv_out / "warnings.csv");
    expect(findings_csv.find("rule,subject_kind,subject,event_count,window_start,window_end,usernames,summary")
               == 0,
           "expected findings csv header");
    expect(findings_csv.find("brute_force,source_ip,203.0.113.10,5,2026-03-10 08:11:22,2026-03-10 08:18:05,,5 failed SSH attempts from 203.0.113.10 within 10 minutes.")
               != std::string::npos,
           "expected brute-force findings csv row");
    expect(warnings_csv.find("kind,line_number,category,message") == 0, "expected warnings csv header");
    expect(warnings_csv.find("parse_warning,15,known_program_unknown_message,unrecognized auth pattern: sshd_connection_closed_preauth")
               != std::string::npos,
           "expected warning csv row");

    const auto stale_csv_out = output_dir / "stale_csv";
    std::filesystem::create_directories(stale_csv_out);
    {
        std::ofstream output(stale_csv_out / "findings.csv");
        output << "keep-findings\n";
    }
    {
        std::ofstream output(stale_csv_out / "warnings.csv");
        output << "keep-warnings\n";
    }
    const int stale_csv_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode syslog --year 2026 "
        + quote_argument(sample_log)
        + " " + quote_argument(stale_csv_out))
                                               .c_str());
    expect(stale_csv_exit == 0, "expected non-csv run in directory with stale csv to succeed");
    expect(read_file(stale_csv_out / "findings.csv") == "keep-findings\n",
           "expected non-csv run to preserve pre-existing findings.csv");
    expect(read_file(stale_csv_out / "warnings.csv") == "keep-warnings\n",
           "expected non-csv run to preserve pre-existing warnings.csv");

    const auto config_run_out = output_dir / "config_run";
    std::filesystem::create_directories(config_run_out);
    const int config_run_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --config " + quote_argument(sample_config)
        + " " + quote_argument(sample_log)
        + " " + quote_argument(config_run_out))
                                                .c_str());
    expect(config_run_exit == 0, "expected sample config run to succeed");
    expect_report_core_fields(
        read_file(config_run_out / "report.md"),
        read_file(config_run_out / "report.json"),
        "syslog_legacy",
        true,
        false);

    const auto journalctl_out = output_dir / "journalctl_cli";
    std::filesystem::create_directories(journalctl_out);
    const int journalctl_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode journalctl "
        + quote_argument(journalctl_log)
        + " " + quote_argument(journalctl_out))
                                                .c_str());
    expect(journalctl_exit == 0, "expected journalctl short-full CLI run to succeed");

    const auto journalctl_markdown = read_file(journalctl_out / "report.md");
    const auto journalctl_json = read_file(journalctl_out / "report.json");
    expect_report_core_fields(journalctl_markdown, journalctl_json, "journalctl_short_full", false, true);
    expect(!std::filesystem::exists(journalctl_out / "findings.csv"),
           "did not expect journalctl findings.csv without explicit csv flag");
    expect(!std::filesystem::exists(journalctl_out / "warnings.csv"),
           "did not expect journalctl warnings.csv without explicit csv flag");

    const auto missing_year_out = output_dir / "missing_year";
    std::filesystem::create_directories(missing_year_out);
    const int missing_year_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode syslog "
        + quote_argument(sample_log)
        + " " + quote_argument(missing_year_out))
                                                   .c_str());
    expect(missing_year_exit != 0, "expected syslog mode without year to fail");

    const auto short_year_out = output_dir / "short_year";
    const auto short_year_stderr = output_dir / "short_year_stderr.txt";
    std::filesystem::create_directories(short_year_out);
    const int short_year_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode syslog --year 26 "
        + quote_argument(sample_log)
        + " " + quote_argument(short_year_out),
        nullptr,
        &short_year_stderr)
                                                .c_str());
    expect(short_year_exit != 0, "expected short --year value to fail");
    expect(read_file(short_year_stderr).find("invalid year value: 26") != std::string::npos,
           "expected short --year failure message");

    const auto nondigit_year_out = output_dir / "nondigit_year";
    const auto nondigit_year_stderr = output_dir / "nondigit_year_stderr.txt";
    std::filesystem::create_directories(nondigit_year_out);
    const int nondigit_year_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --mode=syslog --year=20x6 "
        + quote_argument(sample_log)
        + " " + quote_argument(nondigit_year_out),
        nullptr,
        &nondigit_year_stderr)
                                                   .c_str());
    expect(nondigit_year_exit != 0, "expected non-digit --year value to fail");
    expect(read_file(nondigit_year_stderr).find("invalid year value: 20x6") != std::string::npos,
           "expected non-digit --year failure message");

    const auto invalid_config = output_dir / "invalid_config.json";
    {
        std::ofstream output(invalid_config);
        output << "{\n"
               << "  \"input_mode\": \"syslog_legacy\",\n"
               << "  \"timestamp\": { \"assume_year\": 26 },\n"
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

    const auto invalid_out = output_dir / "invalid_config_run";
    const auto invalid_stderr = output_dir / "invalid_config_stderr.txt";
    std::filesystem::create_directories(invalid_out);
    const int invalid_exit = std::system(build_command(
        quote_argument(loglens_exe)
        + " --config " + quote_argument(invalid_config)
        + " " + quote_argument(sample_log)
        + " " + quote_argument(invalid_out),
        nullptr,
        &invalid_stderr)
                                             .c_str());
    expect(invalid_exit != 0, "expected invalid config CLI run to fail");
    expect(read_file(invalid_stderr).find("timestamp.assume_year must be a four-digit year") != std::string::npos,
           "expected invalid config year failure message");

    return 0;
}
