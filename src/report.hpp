#pragma once

#include "detector.hpp"
#include "parser.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace loglens {

struct ReportData {
    std::filesystem::path input_path;
    ParseMetadata parse_metadata;
    ParserQualityMetrics parser_quality;
    std::vector<Event> events;
    std::vector<Finding> findings;
    std::vector<ParseWarning> warnings;
};

std::string render_markdown_report(const ReportData& data);
std::string render_json_report(const ReportData& data);
void write_reports(const ReportData& data, const std::filesystem::path& output_directory);

}  // namespace loglens
