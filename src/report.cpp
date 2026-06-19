#include "report.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace loglens {
namespace {

struct HostSummary {
    std::string hostname;
    std::size_t parsed_event_count = 0;
    std::size_t finding_count = 0;
    std::size_t warning_count = 0;
    std::vector<std::pair<EventType, std::size_t>> event_counts;
};

void append_unicode_escape(std::string& output, unsigned char value) {
    std::ostringstream escaped_code;
    escaped_code << "\\u"
                 << std::uppercase
                 << std::hex
                 << std::setfill('0')
                 << std::setw(4)
                 << static_cast<int>(value);
    output += escaped_code.str();
}

std::string escape_json(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());

    for (const char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(character) < 0x20) {
                append_unicode_escape(escaped, static_cast<unsigned char>(character));
            } else {
                escaped += character;
            }
            break;
        }
    }

    return escaped;
}

std::string escape_markdown_table_cell(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());

    for (std::size_t index = 0; index < value.size(); ++index) {
        const char character = value[index];
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '|':
            escaped += "\\|";
            break;
        case '\r':
            if (index + 1 < value.size() && value[index + 1] == '\n') {
                ++index;
            }
            escaped += "<br>";
            break;
        case '\n':
            escaped += "<br>";
            break;
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        default:
            if (static_cast<unsigned char>(character) < 0x20) {
                append_unicode_escape(escaped, static_cast<unsigned char>(character));
            } else {
                escaped += character;
            }
            break;
        }
    }

    return escaped;
}

bool starts_with_csv_formula_marker(std::string_view value) {
    std::size_t index = 0;
    while (index < value.size() && value[index] == ' ') {
        ++index;
    }

    if (index >= value.size()) {
        return false;
    }

    switch (value[index]) {
    case '=':
    case '+':
    case '-':
    case '@':
    case '\t':
    case '\r':
    case '\n':
        return true;
    default:
        return false;
    }
}

std::string neutralize_csv_formula(std::string_view value) {
    if (!starts_with_csv_formula_marker(value)) {
        return std::string(value);
    }

    std::string neutralized;
    neutralized.reserve(value.size() + 1);
    neutralized.push_back('\'');
    neutralized.append(value);
    return neutralized;
}

std::string escape_csv(std::string_view value) {
    const auto safe_value = neutralize_csv_formula(value);
    bool needs_quotes = safe_value.find_first_of(",\"\n\r") != std::string::npos;
    std::string escaped;
    escaped.reserve(safe_value.size() + 2);

    if (needs_quotes) {
        escaped.push_back('"');
    }

    for (const char character : safe_value) {
        if (character == '"') {
            escaped += "\"\"";
        } else {
            escaped.push_back(character);
        }
    }

    if (needs_quotes) {
        escaped.push_back('"');
    }

    return escaped;
}

void write_text_file(const std::filesystem::path& path, std::string_view content) {
    std::ofstream output(path);
    if (!output) {
        throw std::runtime_error("unable to open report output: " + path.string());
    }

    output << content;
    if (!output) {
        throw std::runtime_error("unable to write report output: " + path.string());
    }

    output.close();
    if (!output) {
        throw std::runtime_error("unable to finalize report output: " + path.string());
    }
}

void ensure_output_directory(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        throw std::runtime_error(
            "unable to create report output directory: " + path.string() + ": " + error.message());
    }

    if (!std::filesystem::is_directory(path, error)) {
        if (error) {
            throw std::runtime_error(
                "unable to inspect report output directory: " + path.string() + ": " + error.message());
        }
        throw std::runtime_error("report output path is not a directory: " + path.string());
    }
}

std::vector<Finding> sorted_findings(const std::vector<Finding>& findings) {
    auto ordered = findings;
    std::sort(ordered.begin(), ordered.end(), [](const Finding& left, const Finding& right) {
        if (left.type != right.type) {
            return to_string(left.type) < to_string(right.type);
        }
        if (left.subject != right.subject) {
            return left.subject < right.subject;
        }
        return left.first_seen < right.first_seen;
    });
    return ordered;
}

std::vector<ParseWarning> sorted_warnings(const std::vector<ParseWarning>& warnings) {
    auto ordered = warnings;
    std::sort(ordered.begin(), ordered.end(), [](const ParseWarning& left, const ParseWarning& right) {
        if (left.line_number != right.line_number) {
            return left.line_number < right.line_number;
        }
        return left.reason < right.reason;
    });
    return ordered;
}

std::vector<std::pair<EventType, std::size_t>> build_event_counts(const std::vector<Event>& events) {
    std::vector<std::pair<EventType, std::size_t>> counts = {
        {EventType::SshFailedPassword, 0},
        {EventType::SshAcceptedPassword, 0},
        {EventType::SshAcceptedPublicKey, 0},
        {EventType::SshInvalidUser, 0},
        {EventType::SshFailedPublicKey, 0},
        {EventType::PamAuthFailure, 0},
        {EventType::SessionOpened, 0},
        {EventType::SudoCommand, 0},
        {EventType::Unknown, 0}};

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

std::string usernames_note(const Finding& finding) {
    if (finding.usernames.empty()) {
        return finding.summary;
    }

    std::ostringstream note;
    note << finding.summary << " Usernames: ";
    for (std::size_t index = 0; index < finding.usernames.size(); ++index) {
        if (index != 0) {
            note << ", ";
        }
        note << finding.usernames[index];
    }
    return note.str();
}

std::string usernames_csv_field(const Finding& finding) {
    std::ostringstream usernames;
    for (std::size_t index = 0; index < finding.usernames.size(); ++index) {
        if (index != 0) {
            usernames << ';';
        }
        usernames << finding.usernames[index];
    }
    return usernames.str();
}

std::string finding_rule_id(const Finding& finding) {
    if (!finding.rule_id.empty()) {
        return finding.rule_id;
    }
    return to_string(finding.type);
}

std::string finding_grouping_key(const Finding& finding) {
    if (!finding.grouping_key.empty()) {
        return finding.grouping_key;
    }
    return finding.subject_kind;
}

std::size_t finding_observed_count(const Finding& finding) {
    if (finding.observed_count != 0) {
        return finding.observed_count;
    }
    return finding.event_count;
}

void write_json_string_array(std::ostream& output, const std::vector<std::string>& values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        output << '"' << escape_json(values[index]) << '"';
        if (index + 1 != values.size()) {
            output << ", ";
        }
    }
    output << ']';
}

std::string format_parse_success_rate(double rate) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(4) << rate;
    return output.str();
}

std::string format_parse_success_percent(double rate) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(2) << (rate * 100.0) << '%';
    return output.str();
}

std::size_t total_input_lines(const ParserQualityMetrics& quality) {
    return quality.total_lines + quality.skipped_blank_lines;
}

std::string_view trim_left(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    return value;
}

std::string_view consume_token(std::string_view& input) {
    input = trim_left(input);
    if (input.empty()) {
        return {};
    }

    const auto separator = input.find(' ');
    if (separator == std::string_view::npos) {
        const auto token = input;
        input = {};
        return token;
    }

    const auto token = input.substr(0, separator);
    input.remove_prefix(separator + 1);
    return token;
}

std::optional<std::string> extract_hostname_from_input_line(std::string_view line, InputMode input_mode) {
    auto remaining = line;
    switch (input_mode) {
    case InputMode::SyslogLegacy:
        if (consume_token(remaining).empty()
            || consume_token(remaining).empty()
            || consume_token(remaining).empty()) {
            return std::nullopt;
        }
        break;
    case InputMode::JournalctlShortFull:
        if (consume_token(remaining).empty()
            || consume_token(remaining).empty()
            || consume_token(remaining).empty()
            || consume_token(remaining).empty()) {
            return std::nullopt;
        }
        break;
    default:
        return std::nullopt;
    }

    const auto hostname = consume_token(remaining);
    if (hostname.empty()) {
        return std::nullopt;
    }

    return std::string(hostname);
}

std::unordered_map<std::size_t, std::string> load_hostnames_by_line(const ReportData& data) {
    std::unordered_map<std::size_t, std::string> hostnames_by_line;
    if (data.warnings.empty()) {
        return hostnames_by_line;
    }

    std::ifstream input(data.input_path);
    if (!input) {
        return hostnames_by_line;
    }

    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const auto hostname = extract_hostname_from_input_line(line, data.parse_metadata.input_mode);
        if (hostname.has_value()) {
            hostnames_by_line.emplace(line_number, *hostname);
        }
    }

    return hostnames_by_line;
}

bool is_matching_finding_signal(const Finding& finding, const AuthSignal& signal) {
    if (signal.timestamp < finding.first_seen || signal.timestamp > finding.last_seen) {
        return false;
    }

    switch (finding.type) {
    case FindingType::BruteForce:
        return signal.counts_as_terminal_auth_failure
            && signal.source_ip == finding.subject;
    case FindingType::MultiUserProbing:
        if (!signal.counts_as_attempt_evidence || signal.source_ip != finding.subject) {
            return false;
        }
        if (finding.usernames.empty()) {
            return true;
        }
        return std::find(
                   finding.usernames.begin(),
                   finding.usernames.end(),
                   signal.username)
            != finding.usernames.end();
    case FindingType::SudoBurst:
        return signal.counts_as_sudo_burst_evidence
            && signal.username == finding.subject;
    default:
        return false;
    }
}

std::vector<HostSummary> build_host_summaries(const ReportData& data) {
    std::unordered_map<std::string, HostSummary> summaries_by_host;

    for (const auto& event : data.events) {
        if (event.hostname.empty()) {
            continue;
        }

        auto& summary = summaries_by_host[event.hostname];
        summary.hostname = event.hostname;
        ++summary.parsed_event_count;
    }

    const auto hostnames_by_line = load_hostnames_by_line(data);
    for (const auto& warning : data.warnings) {
        const auto hostname_it = hostnames_by_line.find(warning.line_number);
        if (hostname_it == hostnames_by_line.end() || hostname_it->second.empty()) {
            continue;
        }

        auto& summary = summaries_by_host[hostname_it->second];
        summary.hostname = hostname_it->second;
        ++summary.warning_count;
    }

    if (summaries_by_host.size() <= 1) {
        return {};
    }

    std::unordered_map<std::size_t, std::string> hostname_by_event_line;
    hostname_by_event_line.reserve(data.events.size());
    std::unordered_map<std::string, std::vector<Event>> events_by_host;
    events_by_host.reserve(summaries_by_host.size());

    for (const auto& event : data.events) {
        hostname_by_event_line.emplace(event.line_number, event.hostname);
        events_by_host[event.hostname].push_back(event);
    }

    const auto signals = build_auth_signals(data.events, data.auth_signal_mappings);
    for (const auto& finding : data.findings) {
        std::unordered_set<std::string> matching_hosts;
        for (const auto& signal : signals) {
            if (!is_matching_finding_signal(finding, signal)) {
                continue;
            }

            const auto hostname_it = hostname_by_event_line.find(signal.line_number);
            if (hostname_it == hostname_by_event_line.end() || hostname_it->second.empty()) {
                continue;
            }
            matching_hosts.insert(hostname_it->second);
        }

        for (const auto& hostname : matching_hosts) {
            ++summaries_by_host[hostname].finding_count;
        }
    }

    std::vector<HostSummary> summaries;
    summaries.reserve(summaries_by_host.size());
    for (auto& [hostname, summary] : summaries_by_host) {
        const auto events_it = events_by_host.find(hostname);
        if (events_it != events_by_host.end()) {
            summary.event_counts = build_event_counts(events_it->second);
        }
        summaries.push_back(std::move(summary));
    }

    std::sort(summaries.begin(), summaries.end(), [](const HostSummary& left, const HostSummary& right) {
        return left.hostname < right.hostname;
    });

    return summaries;
}

}  // namespace

std::string render_markdown_report(const ReportData& data) {
    std::ostringstream output;
    const auto findings = sorted_findings(data.findings);
    const auto warnings = sorted_warnings(data.warnings);
    const auto event_counts = build_event_counts(data.events);
    const auto host_summaries = build_host_summaries(data);

    output << "# LogLens Report\n\n";
    output << "## Summary\n\n";
    output << "- Input: `" << data.input_path.generic_string() << "`\n";
    output << "- Input mode: " << to_string(data.parse_metadata.input_mode) << '\n';
    if (data.parse_metadata.assume_year.has_value()) {
        output << "- Assume year: " << *data.parse_metadata.assume_year << '\n';
    }
    output << "- Timezone present: " << (data.parse_metadata.timezone_present ? "true" : "false") << '\n';
    output << "- Total input lines: " << total_input_lines(data.parser_quality) << '\n';
    output << "- Total lines: " << data.parser_quality.total_lines << '\n';
    output << "- Skipped blank lines: " << data.parser_quality.skipped_blank_lines << '\n';
    output << "- Parsed lines: " << data.parser_quality.parsed_lines << '\n';
    output << "- Unparsed lines: " << data.parser_quality.unparsed_lines << '\n';
    output << "- Parse success rate: " << format_parse_success_percent(data.parser_quality.parse_success_rate) << '\n';
    output << "- Parsed events: " << data.events.size() << '\n';
    output << "- Findings: " << findings.size() << '\n';
    output << "- Parser warnings: " << warnings.size() << "\n\n";

    if (!host_summaries.empty()) {
        output << "## Host Summary\n\n";
        output << "| Host | Parsed Events | Findings | Warnings |\n";
        output << "| --- | ---: | ---: | ---: |\n";
        for (const auto& summary : host_summaries) {
            output << "| " << escape_markdown_table_cell(summary.hostname)
                   << " | " << summary.parsed_event_count
                   << " | " << summary.finding_count
                   << " | " << summary.warning_count << " |\n";
        }
        output << '\n';
    }

    output << "## Findings\n\n";
    if (findings.empty()) {
        output << "No configured detections matched the analyzed events.\n\n";
    } else {
        output << "| Rule | Subject | Count | Window | Notes |\n";
        output << "| --- | --- | ---: | --- | --- |\n";
        for (const auto& finding : findings) {
            output << "| " << escape_markdown_table_cell(to_string(finding.type))
                   << " | " << escape_markdown_table_cell(finding.subject)
                   << " | " << finding.event_count
                   << " | " << format_timestamp(finding.first_seen)
                   << " -> " << format_timestamp(finding.last_seen)
                   << " | " << escape_markdown_table_cell(usernames_note(finding)) << " |\n";
        }
        output << '\n';
    }

    output << "## Event Counts\n\n";
    output << "| Event Type | Count |\n";
    output << "| --- | ---: |\n";
    for (const auto& [type, count] : event_counts) {
        output << "| " << escape_markdown_table_cell(to_string(type)) << " | " << count << " |\n";
    }
    output << '\n';

    output << "## Parser Quality\n\n";
    if (data.parser_quality.top_unknown_patterns.empty()) {
        output << "All analyzed lines matched a supported pattern.\n\n";
    } else {
        output << "| Unknown Pattern | Count |\n";
        output << "| --- | ---: |\n";
        for (const auto& entry : data.parser_quality.top_unknown_patterns) {
            output << "| " << escape_markdown_table_cell(entry.pattern) << " | " << entry.count << " |\n";
        }
        output << '\n';
    }

    output << "## Parser Warnings\n\n";
    if (warnings.empty()) {
        output << "No malformed lines were skipped.\n";
    } else {
        output << "| Line | Reason |\n";
        output << "| ---: | --- |\n";
        for (const auto& warning : warnings) {
            output << "| " << warning.line_number << " | "
                   << escape_markdown_table_cell(warning.reason) << " |\n";
        }
    }

    return output.str();
}

std::string render_json_report(const ReportData& data) {
    std::ostringstream output;
    const auto findings = sorted_findings(data.findings);
    const auto warnings = sorted_warnings(data.warnings);
    const auto event_counts = build_event_counts(data.events);
    const auto host_summaries = build_host_summaries(data);

    output << "{\n";
    output << "  \"tool\": \"LogLens\",\n";
    output << "  \"input\": \"" << escape_json(data.input_path.generic_string()) << "\",\n";
    output << "  \"input_mode\": \"" << to_string(data.parse_metadata.input_mode) << "\",\n";
    if (data.parse_metadata.assume_year.has_value()) {
        output << "  \"assume_year\": " << *data.parse_metadata.assume_year << ",\n";
    }
    output << "  \"timezone_present\": " << (data.parse_metadata.timezone_present ? "true" : "false") << ",\n";
    output << "  \"parser_quality\": {\n";
    output << "    \"total_input_lines\": " << total_input_lines(data.parser_quality) << ",\n";
    output << "    \"total_lines\": " << data.parser_quality.total_lines << ",\n";
    output << "    \"skipped_blank_lines\": " << data.parser_quality.skipped_blank_lines << ",\n";
    output << "    \"parsed_lines\": " << data.parser_quality.parsed_lines << ",\n";
    output << "    \"unparsed_lines\": " << data.parser_quality.unparsed_lines << ",\n";
    output << "    \"parse_success_rate\": " << format_parse_success_rate(data.parser_quality.parse_success_rate) << ",\n";
    output << "    \"top_unknown_patterns\": [\n";
    for (std::size_t index = 0; index < data.parser_quality.top_unknown_patterns.size(); ++index) {
        const auto& entry = data.parser_quality.top_unknown_patterns[index];
        output << "      {\"pattern\": \"" << escape_json(entry.pattern) << "\", \"count\": " << entry.count << "}";
        output << (index + 1 == data.parser_quality.top_unknown_patterns.size() ? "\n" : ",\n");
    }
    output << "    ]\n";
    output << "  },\n";
    output << "  \"parsed_event_count\": " << data.events.size() << ",\n";
    output << "  \"warning_count\": " << warnings.size() << ",\n";
    output << "  \"finding_count\": " << findings.size() << ",\n";
    output << "  \"event_counts\": [\n";
    for (std::size_t index = 0; index < event_counts.size(); ++index) {
        const auto& [type, count] = event_counts[index];
        output << "    {\"event_type\": \"" << to_string(type) << "\", \"count\": " << count << "}";
        output << (index + 1 == event_counts.size() ? "\n" : ",\n");
    }
    output << "  ]";
    if (!host_summaries.empty()) {
        output << ",\n";
        output << "  \"host_summaries\": [\n";
        for (std::size_t host_index = 0; host_index < host_summaries.size(); ++host_index) {
            const auto& summary = host_summaries[host_index];
            output << "    {\n";
            output << "      \"hostname\": \"" << escape_json(summary.hostname) << "\",\n";
            output << "      \"parsed_event_count\": " << summary.parsed_event_count << ",\n";
            output << "      \"finding_count\": " << summary.finding_count << ",\n";
            output << "      \"warning_count\": " << summary.warning_count << ",\n";
            output << "      \"event_counts\": [\n";
            for (std::size_t event_index = 0; event_index < summary.event_counts.size(); ++event_index) {
                const auto& [type, count] = summary.event_counts[event_index];
                output << "        {\"event_type\": \"" << to_string(type) << "\", \"count\": " << count << "}";
                output << (event_index + 1 == summary.event_counts.size() ? "\n" : ",\n");
            }
            output << "      ]\n";
            output << "    }";
            output << (host_index + 1 == host_summaries.size() ? "\n" : ",\n");
        }
        output << "  ],\n";
    } else {
        output << ",\n";
    }
    output << "  \"findings\": [\n";
    for (std::size_t index = 0; index < findings.size(); ++index) {
        const auto& finding = findings[index];
        output << "    {\n";
        output << "      \"rule_id\": \"" << escape_json(finding_rule_id(finding)) << "\",\n";
        output << "      \"rule\": \"" << to_string(finding.type) << "\",\n";
        output << "      \"subject_kind\": \"" << escape_json(finding.subject_kind) << "\",\n";
        output << "      \"subject\": \"" << escape_json(finding.subject) << "\",\n";
        output << "      \"grouping_key\": \"" << escape_json(finding_grouping_key(finding)) << "\",\n";
        output << "      \"threshold\": " << finding.threshold << ",\n";
        output << "      \"observed_count\": " << finding_observed_count(finding) << ",\n";
        output << "      \"event_count\": " << finding.event_count << ",\n";
        output << "      \"window_start\": \"" << format_timestamp(finding.first_seen) << "\",\n";
        output << "      \"window_end\": \"" << format_timestamp(finding.last_seen) << "\",\n";
        output << "      \"evidence_event_ids\": ";
        write_json_string_array(output, finding.evidence_event_ids);
        output << ",\n";
        output << "      \"usernames\": ";
        write_json_string_array(output, finding.usernames);
        output << ",\n";
        output << "      \"summary\": \"" << escape_json(finding.summary) << "\"\n";
        output << "    }";
        output << (index + 1 == findings.size() ? "\n" : ",\n");
    }
    output << "  ],\n";
    output << "  \"warnings\": [\n";
    for (std::size_t index = 0; index < warnings.size(); ++index) {
        const auto& warning = warnings[index];
        output << "    {\"line_number\": " << warning.line_number
               << ", \"reason\": \"" << escape_json(warning.reason) << "\"}";
        output << (index + 1 == warnings.size() ? "\n" : ",\n");
    }
    output << "  ]\n";
    output << "}\n";
    return output.str();
}

std::string render_findings_csv(const ReportData& data) {
    std::ostringstream output;
    const auto findings = sorted_findings(data.findings);

    output << "rule,subject_kind,subject,event_count,window_start,window_end,usernames,summary\n";
    for (const auto& finding : findings) {
        output << escape_csv(to_string(finding.type)) << ','
               << escape_csv(finding.subject_kind) << ','
               << escape_csv(finding.subject) << ','
               << finding.event_count << ','
               << escape_csv(format_timestamp(finding.first_seen)) << ','
               << escape_csv(format_timestamp(finding.last_seen)) << ','
               << escape_csv(usernames_csv_field(finding)) << ','
               << escape_csv(finding.summary) << '\n';
    }

    return output.str();
}

std::string render_warnings_csv(const ReportData& data) {
    std::ostringstream output;
    const auto warnings = sorted_warnings(data.warnings);

    output << "kind,line_number,message\n";
    for (const auto& warning : warnings) {
        output << "parse_warning,"
               << warning.line_number << ','
               << escape_csv(warning.reason) << '\n';
    }

    return output.str();
}

void write_reports(const ReportData& data, const std::filesystem::path& output_directory, bool emit_csv) {
    ensure_output_directory(output_directory);

    write_text_file(output_directory / "report.md", render_markdown_report(data));
    write_text_file(output_directory / "report.json", render_json_report(data));

    const auto findings_csv_path = output_directory / "findings.csv";
    const auto warnings_csv_path = output_directory / "warnings.csv";
    if (!emit_csv) {
        return;
    }
    write_text_file(findings_csv_path, render_findings_csv(data));
    write_text_file(warnings_csv_path, render_warnings_csv(data));
}

}  // namespace loglens
