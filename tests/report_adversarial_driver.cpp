#include "report.hpp"

#include <filesystem>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2 && !(argc == 3 && std::string(argv[2]) == "--extended")) {
        throw std::runtime_error("expected output directory");
    }
    const std::filesystem::path root{argv[1]};
    std::filesystem::create_directories(root);
    std::vector<std::string> fields{
        "example-user", "=1+1", " +1", "-1", "@example", "\t=1", "\r\n=1",
        "quote\",comma,pipe|slash\\<tag>&", std::string("NUL\0end", 7),
        std::string("control\x01\x1f", 9), "valid-\xc3\xa9-\xe4\xb8\xad-\xf0\x9f\x98\x80",
        "bad-\xff", "bad-\xc0\xaf", "bad-\xed\xa0\x80", "bad-\xf4\x90\x80\x80",
        "truncated-\xe2\x82", "mixed-\xe2\x82\xac-\xff-\xc3\xa9"};
    if (argc == 3) {
        // Portable fixed-state byte mutation; paths never derive from these fields.
        std::uint32_t state = 129130;
        for (unsigned sample = 0; sample < 256; ++sample) {
            std::string value(1, static_cast<char>(sample));
            for (unsigned byte = 0; byte < sample % 64; ++byte) {
                state = state * 1664525U + 1013904223U;
                value.push_back(static_cast<char>(state >> 24));
            }
            fields.push_back(std::move(value));
        }
    }
    std::ofstream manifest(root / "fields.txt", std::ios::binary);
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto& field = fields[index];
        manifest << std::dec << index << ' ';
        for (const unsigned char ch : field) {
            manifest << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(ch);
        }
        manifest << '\n';
        loglens::ReportData data;
        // Empty path prevents the renderer from rereading unrelated input files.
        data.parse_metadata.assume_year = 2026;
        data.parser_quality.total_lines = 3;
        data.parser_quality.parsed_lines = 2;
        data.parser_quality.unparsed_lines = 1;
        loglens::Event event;
        event.event_type = loglens::EventType::SshAcceptedPassword;
        event.hostname = field;
        event.username = field;
        event.line_number = 1;
        data.events.push_back(event);
        event.hostname = "example-fixed-host";
        event.line_number = 2;
        data.events.push_back(event);
        loglens::Finding finding;
        finding.type = loglens::FindingType::SudoBurst;
        finding.subject_kind = "username";
        finding.subject = field;
        finding.usernames = {field};
        finding.summary = field;
        finding.event_count = 1;
        finding.evidence_event_ids = {"line:1"};
        data.findings = {finding};
        data.warnings.push_back({3, field, loglens::ParserFailureCategory::KnownProgramUnknownMessage});
        for (const auto& copy : {"first", "second"}) {
            loglens::write_reports(data, root / std::to_string(index) / copy, true);
        }
    }
    if (!manifest) {
        throw std::runtime_error("cannot write synthetic field manifest");
    }
    std::cout << fields.size() << " synthetic report cases\n";
}
