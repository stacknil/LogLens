#include "config.hpp"
#include "detector.hpp"
#include "parser.hpp"
#include "report.hpp"

#include <charconv>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string_view>

#ifndef LOGLENS_VERSION
#define LOGLENS_VERSION "unknown"
#endif

namespace {

struct CliOptions {
    bool show_help = false;
    bool show_version = false;
    std::optional<std::filesystem::path> config_path;
    std::optional<loglens::InputMode> input_mode;
    std::optional<int> assumed_year;
    bool emit_csv = false;
    std::filesystem::path input_path;
    std::filesystem::path output_directory;
};

void print_usage(std::ostream& output) {
    output << "Usage:\n"
           << "  loglens --help\n"
           << "  loglens --version\n"
           << "  loglens [--config <config.json>] [--mode <syslog|syslog-legacy|journalctl|journalctl-short-full>] [--year <YYYY>] [--csv] <input_log> [output_dir]\n";
    output << "Options with values also support --option=value syntax.\n";
}

void print_version(std::ostream& output) {
    output << "LogLens " << LOGLENS_VERSION << '\n';
}

std::optional<std::string_view> option_value(std::string_view argument, std::string_view option_name) {
    if (!argument.starts_with(option_name) || argument.size() <= option_name.size()) {
        return std::nullopt;
    }

    if (argument[option_name.size()] != '=') {
        return std::nullopt;
    }

    return argument.substr(option_name.size() + 1);
}

int parse_year_argument(std::string_view value) {
    if (value.size() != 4) {
        throw std::runtime_error("invalid year value: " + std::string(value));
    }

    for (const char character : value) {
        if (std::isdigit(static_cast<unsigned char>(character)) == 0) {
            throw std::runtime_error("invalid year value: " + std::string(value));
        }
    }

    int parsed_year = 0;
    const auto* begin = value.data();
    const auto* end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed_year);
    if (result.ec != std::errc{} || result.ptr != end || parsed_year < 1000 || parsed_year > 9999) {
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
        if (argument == "--") {
            ++index;
            break;
        }

        if (argument == "--help" || argument == "-h") {
            if (argc != 2) {
                throw std::runtime_error("--help cannot be combined with other arguments");
            }

            options.show_help = true;
            return options;
        }

        if (argument == "--version") {
            if (argc != 2) {
                throw std::runtime_error("--version cannot be combined with other arguments");
            }

            options.show_version = true;
            return options;
        }

        if (argument == "--config") {
            if (index + 1 >= argc) {
                throw std::runtime_error("missing path after --config");
            }

            options.config_path = std::filesystem::path{argv[index + 1]};
            index += 2;
            continue;
        }

        if (const auto value = option_value(argument, "--config"); value.has_value()) {
            if (value->empty()) {
                throw std::runtime_error("missing path after --config");
            }

            options.config_path = std::filesystem::path{std::string{*value}};
            ++index;
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

        if (const auto value = option_value(argument, "--mode"); value.has_value()) {
            if (value->empty()) {
                throw std::runtime_error("missing value after --mode");
            }

            const auto parsed_mode = loglens::parse_input_mode(*value);
            if (!parsed_mode.has_value()) {
                throw std::runtime_error("unsupported mode: " + std::string{*value});
            }

            options.input_mode = *parsed_mode;
            ++index;
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

        if (const auto value = option_value(argument, "--year"); value.has_value()) {
            if (value->empty()) {
                throw std::runtime_error("missing value after --year");
            }

            options.assumed_year = parse_year_argument(*value);
            ++index;
            continue;
        }

        if (argument == "--csv") {
            options.emit_csv = true;
            ++index;
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
        print_usage(std::cerr);
        std::cerr << "LogLens failed: " << error.what() << '\n';
        return 1;
    }

    if (options.show_help) {
        print_usage(std::cout);
        return 0;
    }

    if (options.show_version) {
        print_version(std::cout);
        return 0;
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
            parsed.warnings,
            app_config.detector.auth_signal_mappings};

        loglens::write_reports(report_data, options.output_directory, options.emit_csv);

        std::cout << "Parsed events: " << parsed.events.size() << '\n';
        std::cout << "Findings: " << findings.size() << '\n';
        std::cout << "Warnings: " << parsed.warnings.size() << '\n';
        std::cout << "Markdown report: " << (options.output_directory / "report.md").string() << '\n';
        std::cout << "JSON report: " << (options.output_directory / "report.json").string() << '\n';
        if (options.emit_csv) {
            std::cout << "Findings CSV: " << (options.output_directory / "findings.csv").string() << '\n';
            std::cout << "Warnings CSV: " << (options.output_directory / "warnings.csv").string() << '\n';
        }
    } catch (const std::exception& error) {
        std::cerr << "LogLens failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
