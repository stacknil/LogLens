#include "report.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace loglens {
namespace {

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
            escaped += character;
            break;
        }
    }

    return escaped;
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

}  // namespace

std::string render_markdown_report(const ReportData& data) {
    std::ostringstream output;
    const auto findings = sorted_findings(data.findings);
    const auto warnings = sorted_warnings(data.warnings);
    const auto event_counts = build_event_counts(data.events);

    output << "# LogLens Report\n\n";
    output << "## Summary\n\n";
    output << "- Input: `" << data.input_path.generic_string() << "`\n";
    output << "- Input mode: " << to_string(data.parse_metadata.input_mode) << '\n';
    if (data.parse_metadata.assume_year.has_value()) {
        output << "- Assume year: " << *data.parse_metadata.assume_year << '\n';
    }
    output << "- Timezone present: " << (data.parse_metadata.timezone_present ? "true" : "false") << '\n';
    output << "- Total lines: " << data.parser_quality.total_lines << '\n';
    output << "- Parsed lines: " << data.parser_quality.parsed_lines << '\n';
    output << "- Unparsed lines: " << data.parser_quality.unparsed_lines << '\n';
    output << "- Parse success rate: " << format_parse_success_percent(data.parser_quality.parse_success_rate) << '\n';
    output << "- Parsed events: " << data.events.size() << '\n';
    output << "- Findings: " << findings.size() << '\n';
    output << "- Parser warnings: " << warnings.size() << "\n\n";

    output << "## Findings\n\n";
    if (findings.empty()) {
        output << "No configured detections matched the analyzed events.\n\n";
    } else {
        output << "| Rule | Subject | Count | Window | Notes |\n";
        output << "| --- | --- | ---: | --- | --- |\n";
        for (const auto& finding : findings) {
            output << "| " << to_string(finding.type)
                   << " | " << finding.subject
                   << " | " << finding.event_count
                   << " | " << format_timestamp(finding.first_seen)
                   << " -> " << format_timestamp(finding.last_seen)
                   << " | " << usernames_note(finding) << " |\n";
        }
        output << '\n';
    }

    output << "## Event Counts\n\n";
    output << "| Event Type | Count |\n";
    output << "| --- | ---: |\n";
    for (const auto& [type, count] : event_counts) {
        output << "| " << to_string(type) << " | " << count << " |\n";
    }
    output << '\n';

    output << "## Parser Quality\n\n";
    if (data.parser_quality.top_unknown_patterns.empty()) {
        output << "All analyzed lines matched a supported pattern.\n\n";
    } else {
        output << "| Unknown Pattern | Count |\n";
        output << "| --- | ---: |\n";
        for (const auto& entry : data.parser_quality.top_unknown_patterns) {
            output << "| " << entry.pattern << " | " << entry.count << " |\n";
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
            output << "| " << warning.line_number << " | " << warning.reason << " |\n";
        }
    }

    return output.str();
}

std::string render_json_report(const ReportData& data) {
    std::ostringstream output;
    const auto findings = sorted_findings(data.findings);
    const auto warnings = sorted_warnings(data.warnings);
    const auto event_counts = build_event_counts(data.events);

    output << "{\n";
    output << "  \"tool\": \"LogLens\",\n";
    output << "  \"input\": \"" << escape_json(data.input_path.generic_string()) << "\",\n";
    output << "  \"input_mode\": \"" << to_string(data.parse_metadata.input_mode) << "\",\n";
    if (data.parse_metadata.assume_year.has_value()) {
        output << "  \"assume_year\": " << *data.parse_metadata.assume_year << ",\n";
    }
    output << "  \"timezone_present\": " << (data.parse_metadata.timezone_present ? "true" : "false") << ",\n";
    output << "  \"parser_quality\": {\n";
    output << "    \"total_lines\": " << data.parser_quality.total_lines << ",\n";
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
    output << "  ],\n";
    output << "  \"findings\": [\n";
    for (std::size_t index = 0; index < findings.size(); ++index) {
        const auto& finding = findings[index];
        output << "    {\n";
        output << "      \"rule\": \"" << to_string(finding.type) << "\",\n";
        output << "      \"subject_kind\": \"" << escape_json(finding.subject_kind) << "\",\n";
        output << "      \"subject\": \"" << escape_json(finding.subject) << "\",\n";
        output << "      \"event_count\": " << finding.event_count << ",\n";
        output << "      \"window_start\": \"" << format_timestamp(finding.first_seen) << "\",\n";
        output << "      \"window_end\": \"" << format_timestamp(finding.last_seen) << "\",\n";
        output << "      \"usernames\": [";
        for (std::size_t name_index = 0; name_index < finding.usernames.size(); ++name_index) {
            output << '"' << escape_json(finding.usernames[name_index]) << '"';
            if (name_index + 1 != finding.usernames.size()) {
                output << ", ";
            }
        }
        output << "],\n";
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

void write_reports(const ReportData& data, const std::filesystem::path& output_directory) {
    std::filesystem::create_directories(output_directory);

    std::ofstream markdown_output(output_directory / "report.md");
    markdown_output << render_markdown_report(data);

    std::ofstream json_output(output_directory / "report.json");
    json_output << render_json_report(data);
}

}  // namespace loglens
