#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
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

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to read file: " + path.string());
    }

    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::string normalize_line_endings(std::string value) {
    value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
    return value;
}

std::vector<std::string> split_lines(const std::string& content) {
    std::vector<std::string> lines;
    std::string current;

    for (const char ch : normalize_line_endings(content)) {
        if (ch == '\n') {
            lines.push_back(current);
            current.clear();
        } else {
            current += ch;
        }
    }

    if (!current.empty()) {
        lines.push_back(current);
    }

    return lines;
}

std::string trim(std::string_view value) {
    std::size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) {
        --end;
    }

    return std::string(value.substr(start, end - start));
}

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool is_markdown_separator_row(std::string_view line) {
    return starts_with(line, "| ---");
}

std::vector<std::string> extract_markdown_contract_lines(const std::string& markdown) {
    std::vector<std::string> contract_lines;

    for (const auto& raw_line : split_lines(markdown)) {
        const auto line = trim(raw_line);
        if (line.empty() || is_markdown_separator_row(line)) {
            continue;
        }

        if (line == "# LogLens Report"
            || starts_with(line, "## ")
            || starts_with(line, "- Input: ")
            || starts_with(line, "- Input mode: ")
            || starts_with(line, "- Assume year: ")
            || starts_with(line, "- Timezone present: ")
            || starts_with(line, "- Total lines: ")
            || starts_with(line, "- Parsed lines: ")
            || starts_with(line, "- Unparsed lines: ")
            || starts_with(line, "- Parse success rate: ")
            || starts_with(line, "- Parsed events: ")
            || starts_with(line, "- Findings: ")
            || starts_with(line, "- Parser warnings: ")
            || starts_with(line, "| ")
            || starts_with(line, "No configured detections matched")
            || starts_with(line, "All analyzed lines matched")
            || starts_with(line, "No malformed lines were skipped")) {
            contract_lines.push_back(line);
        }
    }

    return contract_lines;
}

std::vector<std::string> extract_json_contract_lines(const std::string& json) {
    std::vector<std::string> contract_lines;

    for (const auto& raw_line : split_lines(json)) {
        const auto line = trim(raw_line);
        if (line.empty()) {
            continue;
        }

        if (starts_with(line, "\"tool\": ")
            || starts_with(line, "\"input\": ")
            || starts_with(line, "\"input_mode\": ")
            || starts_with(line, "\"assume_year\": ")
            || starts_with(line, "\"timezone_present\": ")
            || starts_with(line, "\"total_lines\": ")
            || starts_with(line, "\"parsed_lines\": ")
            || starts_with(line, "\"unparsed_lines\": ")
            || starts_with(line, "\"parse_success_rate\": ")
            || starts_with(line, "\"parsed_event_count\": ")
            || starts_with(line, "\"warning_count\": ")
            || starts_with(line, "\"finding_count\": ")
            || starts_with(line, "{\"pattern\": ")
            || starts_with(line, "{\"event_type\": ")
            || starts_with(line, "\"rule\": ")
            || starts_with(line, "\"subject_kind\": ")
            || starts_with(line, "\"subject\": ")
            || starts_with(line, "\"event_count\": ")
            || starts_with(line, "\"window_start\": ")
            || starts_with(line, "\"window_end\": ")
            || starts_with(line, "\"usernames\": ")
            || starts_with(line, "\"summary\": ")
            || starts_with(line, "{\"line_number\": ")) {
            contract_lines.push_back(line);
        }
    }

    return contract_lines;
}

std::string quote_argument(std::string_view value) {
    return "\"" + std::string(value) + "\"";
}

std::string build_command(const std::string& invocation) {
#ifdef _WIN32
    return "cmd /c \"" + invocation + "\"";
#else
    return invocation;
#endif
}

void expect_equal_lines(const std::vector<std::string>& actual,
                        const std::vector<std::string>& expected,
                        const std::string& message) {
    if (actual == expected) {
        return;
    }

    std::string details = message + "\nexpected:\n";
    for (const auto& line : expected) {
        details += "  " + line + '\n';
    }
    details += "actual:\n";
    for (const auto& line : actual) {
        details += "  " + line + '\n';
    }

    throw std::runtime_error(details);
}

void run_report_contract_case(const std::filesystem::path& loglens_exe,
                              const std::filesystem::path& fixture_directory,
                              const std::filesystem::path& output_root,
                              const std::string& mode_argument,
                              const std::string& extra_arguments = {}) {
    const auto repo = repo_root();
    const auto relative_input = std::filesystem::relative(fixture_directory / "input.log", repo).generic_string();
    const auto case_output = output_root / fixture_directory.filename();

    std::filesystem::remove_all(case_output);
    std::filesystem::create_directories(case_output);

    std::string invocation = quote_argument(loglens_exe.generic_string())
        + " --mode " + mode_argument;
    if (!extra_arguments.empty()) {
        invocation += " " + extra_arguments;
    }
    invocation += " " + quote_argument(relative_input)
        + " " + quote_argument(case_output.generic_string());

    const int exit_code = std::system(build_command(invocation).c_str());
    expect(exit_code == 0, "expected report contract CLI run to succeed for " + fixture_directory.filename().string());

    const auto actual_markdown = read_file(case_output / "report.md");
    const auto actual_json = read_file(case_output / "report.json");
    const auto golden_markdown = read_file(fixture_directory / "report.md");
    const auto golden_json = read_file(fixture_directory / "report.json");

    expect_equal_lines(
        extract_markdown_contract_lines(actual_markdown),
        extract_markdown_contract_lines(golden_markdown),
        "markdown contract mismatch for " + fixture_directory.filename().string());
    expect_equal_lines(
        extract_json_contract_lines(actual_json),
        extract_json_contract_lines(golden_json),
        "json contract mismatch for " + fixture_directory.filename().string());
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        throw std::runtime_error("expected arguments: <loglens_exe> <output_dir>");
    }

    const auto original_cwd = std::filesystem::current_path();
    const auto repo = repo_root();
    std::filesystem::current_path(repo);

    try {
        const std::filesystem::path loglens_exe = std::filesystem::absolute(argv[1]);
        const std::filesystem::path output_root = std::filesystem::absolute(argv[2]);
        const auto fixture_root = repo / "tests" / "fixtures" / "report_contracts";

        run_report_contract_case(
            loglens_exe,
            fixture_root / "syslog_legacy",
            output_root,
            "syslog",
            "--year 2026");
        run_report_contract_case(
            loglens_exe,
            fixture_root / "journalctl_short_full",
            output_root,
            "journalctl-short-full");
    } catch (...) {
        std::filesystem::current_path(original_cwd);
        throw;
    }

    std::filesystem::current_path(original_cwd);
    return 0;
}
