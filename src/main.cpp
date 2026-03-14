#include "config.hpp"
#include "detector.hpp"
#include "parser.hpp"
#include "report.hpp"

#include <charconv>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace {

struct CliOptions {
    std::optional<std::filesystem::path> config_path;
    std::optional<loglens::InputMode> input_mode;
    std::optional<int> assumed_year;
    std::filesystem::path input_path;
    std::filesystem::path output_directory;
};

void print_usage() {
    std::cerr << "Usage: loglens [--config <config.json>] [--mode <syslog|journalctl-short-full>] [--year <YYYY>] <input_log> [output_dir]\n";
}

int parse_year_argument(std::string_view value) {
    int parsed_year = 0;
    const auto* begin = value.data();
    const auto* end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed_year);
    if (result.ec != std::errc{} || result.ptr != end || parsed_year <= 0) {
        throw std::runtime_error("invalid year value: " + std::string(value));
    }

    return parsed_year;
}

CliOptions parse_cli_options(int argc, char* argv[]) {
    if (argc < 2) {
        throw std::runtime_error("missing required arguments");
    }

    int index = 1;
    CliOptions options;

    while (index < argc) {
        const std::string_view argument = argv[index];
        if (argument == "--config") {
            if (index + 1 >= argc) {
                throw std::runtime_error("missing path after --config");
            }

            options.config_path = std::filesystem::path{argv[index + 1]};
            index += 2;
            continue;
        }

        if (argument == "--mode") {
            if (index + 1 >= argc) {
                throw std::runtime_error("missing value after --mode");
            }

            const auto parsed_mode = loglens::parse_input_mode(argv[index + 1]);
            if (!parsed_mode.has_value()) {
                throw std::runtime_error("unsupported mode: " + std::string{argv[index + 1]});
            }

            options.input_mode = *parsed_mode;
            index += 2;
            continue;
        }

        if (argument == "--year") {
            if (index + 1 >= argc) {
                throw std::runtime_error("missing value after --year");
            }

            options.assumed_year = parse_year_argument(argv[index + 1]);
            index += 2;
            continue;
        }

        if (argument.starts_with('-')) {
            throw std::runtime_error("unknown option: " + std::string{argv[index]});
        }

        break;
    }

    const int remaining = argc - index;
    if (remaining < 1 || remaining > 2) {
        throw std::runtime_error("invalid argument count");
    }

    options.input_path = std::filesystem::path{argv[index]};
    options.output_directory = remaining == 2
        ? std::filesystem::path{argv[index + 1]}
        : std::filesystem::current_path();
    return options;
}

loglens::ParserConfig resolve_parser_config(const CliOptions& options, const loglens::AppConfig& config) {
    const auto resolved_mode = options.input_mode.has_value()
        ? options.input_mode
        : config.input_mode;
    if (!resolved_mode.has_value()) {
        throw std::runtime_error("input mode is required; use --mode or input_mode in config.json");
    }

    loglens::ParserConfig parser_config;
    parser_config.input_mode = *resolved_mode;

    if (parser_config.input_mode == loglens::InputMode::SyslogLegacy) {
        parser_config.assumed_year = options.assumed_year.has_value()
            ? options.assumed_year
            : config.timestamp.assume_year;
        if (!parser_config.assumed_year.has_value()) {
            throw std::runtime_error("syslog mode requires --year or timestamp.assume_year in config.json");
        }
    }

    return parser_config;
}

}  // namespace

int main(int argc, char* argv[]) {
    CliOptions options;
    try {
        options = parse_cli_options(argc, argv);
    } catch (const std::exception& error) {
        print_usage();
        std::cerr << "LogLens failed: " << error.what() << '\n';
        return 1;
    }

    try {
        const auto app_config = options.config_path.has_value()
            ? loglens::load_app_config(*options.config_path)
            : loglens::AppConfig{};
        const auto parser_config = resolve_parser_config(options, app_config);

        const loglens::AuthLogParser parser(parser_config);
        const auto parsed = parser.parse_file(options.input_path);

        const loglens::Detector detector(app_config.detector);
        const auto findings = detector.analyze(parsed.events);

        const loglens::ReportData report_data{
            options.input_path,
            parsed.metadata,
            parsed.quality,
            parsed.events,
            findings,
            parsed.warnings};

        loglens::write_reports(report_data, options.output_directory);

        std::cout << "Parsed events: " << parsed.events.size() << '\n';
        std::cout << "Findings: " << findings.size() << '\n';
        std::cout << "Warnings: " << parsed.warnings.size() << '\n';
        std::cout << "Markdown report: " << (options.output_directory / "report.md").string() << '\n';
        std::cout << "JSON report: " << (options.output_directory / "report.json").string() << '\n';
    } catch (const std::exception& error) {
        std::cerr << "LogLens failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
