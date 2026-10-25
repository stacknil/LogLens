#include "parser.hpp"
#include "detector.hpp"
#include "signal.hpp"
#include "support/qualification_cases.hpp"
#include "support/qualification_pipeline.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string envelope(bool journal, const std::string& program, const std::string& message) {
    return (journal ? "Tue 2026-03-10 09:00:00 UTC " : "Mar 10 09:00:00 ")
        + std::string("example-host ") + program + "[4200]: " + message;
}

loglens::AuthLogParser parser(bool journal) {
    return loglens::AuthLogParser({journal ? loglens::InputMode::JournalctlShortFull
                                         : loglens::InputMode::SyslogLegacy, 2026});
}

void malformed_addresses() {
    // Authored lexical counterexamples; no production validator supplies expected results.
    const std::vector<std::string> invalid{
        "203.0.113.1.", "203.0.113.-0", "2001:db8:1", "2001:::db8",
        "2001:db8::1::2", "2001:db8:00000::1", "2001:db8:1:2:3:4:5:6:7",
        "::", "2001:db8::203.0.113.999", ":2001:db8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1:",
        "2001:db8::1:2:3:4:5:6", "invalid user user-b 203.0.113.1"};
    for (const bool journal : {false, true}) {
        for (const auto& address : invalid) {
            const auto line = envelope(journal, "sshd", "Failed password for user-a from "
                + address + " port 50101 ssh2");
            std::string reason;
            auto category = loglens::ParserFailureCategory::UnknownProgram;
            const auto event = parser(journal).parse_line(line, 1, &reason, &category);
            require(!event, "malformed source admitted: " + address);
            require(category == loglens::ParserFailureCategory::MalformedSourceIp,
                    "malformed source taxonomy changed");
            std::istringstream stream(line + '\n' + line + '\n' + line + '\n' + line + '\n' + line);
            const auto parsed = parser(journal).parse_stream(stream);
            require(parsed.events.empty() && parsed.warnings.size() == 5,
                    "malformed stream became events");
            require(loglens::Detector{}.analyze(parsed.events).empty(),
                    "malformed source produced findings");
        }
    }
}

void valid_addresses() {
    const std::vector<std::string> valid{
        "203.0.113.1", "2001:db8::1", "2001:db8:0:0:0:0:0:1",
        "2001:db8::203.0.113.1", "2001:db8::", "::ffff:203.0.113.1",
        "2001:db8:0:0:0:0:203.0.113.1", "2001:db8::1:2:3:4:5"};
    for (const bool journal : {false, true}) {
        for (const auto& address : valid) {
            const auto event = parser(journal).parse_line(envelope(journal, "sshd",
                "Failed password for user-a from " + address + " port 50101 ssh2"), 7);
            require(event && event->source_ip == address
                    && event->event_type == loglens::EventType::SshFailedPassword,
                    "supported address changed: " + address);
        }
    }
}

void envelope_variants() {
    for (const bool journal : {false, true}) {
        for (const auto& host : {"example-host", "example.example", "host-2"}) {
            for (const auto& tag : {"sshd", "sshd[0]", "sshd[2147483647]"}) {
                const auto line = std::string(journal ? "Tue 2026-03-10 09:00:00 UTC " : "Mar 10 09:00:00 ")
                    + host + " " + tag + ": Failed password for user-a from 203.0.113.1 port 50101 ssh2";
                const auto event = parser(journal).parse_line(line, 3);
                require(event && event->hostname == host && event->program == "sshd"
                        && event->username == "user-a" && event->source_ip == "203.0.113.1"
                        && event->timestamp.time_since_epoch().count() == 1773133200,
                        "envelope variation changed authentication evidence");
                const std::string tag_value{tag};
                require(tag_value == "sshd" ? !event->pid.has_value()
                            : event->pid == (tag_value == "sshd[0]" ? 0 : 2147483647),
                        "PID boundary normalized incorrectly");
            }
        }
    }
}

void sudo_payload() {
    const std::vector<std::string> payloads{
        "from example", "rhost=example", "incorrect password attempt",
        "command not allowed", "user NOT in sudoers"};
    for (const bool journal : {false, true}) {
        for (const auto& payload : payloads) {
            const auto line = envelope(journal, "sudo",
                "user-a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/echo " + payload);
            std::istringstream stream(line + '\n' + line + '\n' + line);
            const auto result = parser(journal).parse_stream(stream);
            require(result.events.size() == 3 && result.warnings.empty(),
                    "sudo command payload caused evidence loss: " + payload);
            for (const auto& event : result.events) {
                require(event.event_type == loglens::EventType::SudoCommand
                        && event.username == "user-a" && event.source_ip.empty(),
                        "sudo command payload changed classification: " + payload);
            }
            const auto findings = loglens::Detector{}.analyze(result.events);
            require(findings.size() == 1 && findings[0].type == loglens::FindingType::SudoBurst
                    && findings[0].event_count == 3
                    && findings[0].evidence_event_ids == std::vector<std::string>{"line:1", "line:2", "line:3"},
                    "sudo command payload changed detector evidence");
        }
    }
}

void sudo_denial_precedence() {
    for (const bool journal : {false, true}) {
        for (const auto& prefix : {"user NOT in sudoers", "command not allowed"}) {
            const auto event = parser(journal).parse_line(envelope(journal, "sudo",
                std::string("user-a : ") + prefix + " ; COMMAND=/usr/bin/echo example"), 1);
            require(event && event->event_type == loglens::EventType::SudoPolicyDenied,
                    "actual denial metadata lost precedence");
            require(loglens::Detector{}.analyze({*event, *event, *event}).empty(),
                    "denied command became sudo burst");
        }
    }
}

void marker_username() {
    for (const bool journal : {false, true}) {
        for (const auto& prefix : {"Failed password for ", "Accepted password for ",
                                  "Accepted publickey for ", "Failed publickey for ",
                                  "Failed keyboard-interactive/pam for ", "Invalid user "}) {
            const auto event = parser(journal).parse_line(envelope(journal, "sshd",
                std::string(prefix) + "from from 203.0.113.1 port 50101 ssh2"), 1);
            require(event && event->username == "from" && event->source_ip == "203.0.113.1",
                    "username marker consumed as source delimiter");
        }
    }
}

void sudo_metadata_values() {
    for (const auto& value : {"incorrect password attempt", "command not allowed", "from example"}) {
        const auto event = parser(false).parse_line(envelope(false, "sudo",
            std::string("user-a : TTY=pts/0 ; PWD=/tmp/") + value
            + " ; USER=root ; COMMAND=/usr/bin/true"), 1);
        require(event && event->event_type == loglens::EventType::SudoCommand,
                "opaque PWD value changed sudo event");
    }
}

void sudo_command_field_boundaries() {
    for (const bool journal : {false, true}) {
        for (const auto& details : {
                 "TTY=pts/0 ; PWD=/tmp/COMMAND=marker ; USER=root",
                 "TTY=pts/0 ; PWD=/tmp/;COMMAND=marker ; USER=root",
                 "TTY=pts/0 ; PWD=/ ; USER=root ; NOTCOMMAND=/usr/bin/true"}) {
            const auto line = envelope(journal, "sudo", std::string("user-a : ") + details);
            std::string reason;
            auto category = loglens::ParserFailureCategory::UnknownProgram;
            require(!parser(journal).parse_line(line, 1, &reason, &category),
                    "sudo value substring admitted as command field");
            require(category == loglens::ParserFailureCategory::KnownProgramUnknownMessage
                    && reason == "unrecognized auth pattern: sudo_other", "sudo missing-field taxonomy");
            std::istringstream stream(line + '\n' + line + '\n' + line);
            const auto parsed = parser(journal).parse_stream(stream);
            require(parsed.events.empty() && parsed.warnings.size() == 3,
                    "sudo missing command became normalized evidence");
            require(loglens::Detector{}.analyze(parsed.events).empty(),
                    "sudo missing command produced a burst");
        }
        for (const auto& details : {
                 "COMMAND=/usr/bin/true",
                 "TTY=pts/0 ; PWD=/tmp/COMMAND=marker ; USER=root ; COMMAND=/usr/bin/true",
                 "TTY=pts/0 ; PWD=/ ; USER=root ;   COMMAND=/usr/bin/echo COMMAND=payload"}) {
            const auto line = envelope(journal, "sudo", std::string("user-a : ") + details);
            std::istringstream stream(line + '\n' + line + '\n' + line);
            const auto parsed = parser(journal).parse_stream(stream);
            require(parsed.events.size() == 3 && parsed.warnings.empty(), "supported sudo command field lost");
            for (const auto& event : parsed.events) {
                require(event.event_type == loglens::EventType::SudoCommand, "sudo field classification changed");
            }
            const auto findings = loglens::Detector{}.analyze(parsed.events);
            require(findings.size() == 1 && findings[0].type == loglens::FindingType::SudoBurst
                    && findings[0].evidence_event_ids == std::vector<std::string>{"line:1", "line:2", "line:3"},
                    "supported sudo command lost burst evidence");
        }
    }
}

void check_expected_event(const loglens::Event& event, const qualification::Case& expected) {
    require(event.event_type == expected.type && event.username == expected.username
            && event.source_ip == expected.address && event.program == expected.program,
            "authored normalization expectation failed");
    require(event.timestamp.time_since_epoch().count() == 1773133200,
            "independent epoch anchor failed");
}

void family_matrix() {
    for (const auto& sample : qualification::cases()) {
        for (const bool journal : {false, true}) {
            const auto event = parser(journal).parse_line(envelope(journal, sample.program, sample.message), 1);
            require(event.has_value(), "supported family lost: " + sample.program);
            check_expected_event(*event, sample);
        }
    }
}

void line_stream_equivalence() {
    for (const bool journal : {false, true}) {
        std::string text;
        const auto samples = qualification::cases();
        for (const auto& sample : samples) {
            text += envelope(journal, sample.program, sample.message) + '\n';
        }
        std::istringstream input(text);
        const auto result = parser(journal).parse_stream(input);
        require(result.events.size() == samples.size() && result.warnings.empty(), "stream lost family");
        for (std::size_t i = 0; i < samples.size(); ++i) {
            check_expected_event(result.events[i], samples[i]);
            require(result.events[i].line_number == i + 1, "stream reference changed");
        }
    }
}

void signal_eligibility() {
    for (const auto& sample : qualification::cases()) {
        const auto event = parser(false).parse_line(envelope(false, sample.program, sample.message), 7);
        require(event.has_value(), "signal fixture did not parse");
        const auto signals = loglens::build_auth_signals({*event}, {});
        const auto count = [&](auto predicate) { return std::count_if(signals.begin(), signals.end(), predicate); };
        require(count([](const auto& s) { return s.counts_as_attempt_evidence; }) == (sample.attempt ? 1 : 0)
                && count([](const auto& s) { return s.counts_as_terminal_auth_failure; }) == (sample.terminal ? 1 : 0)
                && count([](const auto& s) { return s.counts_as_sudo_burst_evidence; }) == (sample.sudo ? 1 : 0),
                "default eligibility differs from independent table");
        for (const auto& signal : signals) {
            require(signal.event_id == "line:7" && signal.line_number == 7, "signal provenance changed");
        }
    }
}

void unsupported_and_blank_insertion() {
    const auto line = envelope(false, "sshd", "Failed password for user-a from 203.0.113.1 port 50101 ssh2");
    const auto unsupported = envelope(false, "sshd", "Connection closed by 203.0.113.1 port 50101 [preauth]");
    std::istringstream input(line + "\n\n" + unsupported + "\n" + line + "\n" + line + "\n" + line + "\n" + line);
    const auto parsed = parser(false).parse_stream(input);
    require(parsed.events.size() == 5 && parsed.warnings.size() == 1
            && parsed.quality.skipped_blank_lines == 1 && parsed.quality.total_lines == 6,
            "insertions violated accounting");
    require(parsed.warnings[0].line_number == 3
            && parsed.warnings[0].category == loglens::ParserFailureCategory::KnownProgramUnknownMessage
            && parsed.quality.top_unknown_patterns.size() == 1
            && parsed.quality.top_unknown_patterns[0].pattern == "sshd_connection_closed_preauth"
            && parsed.quality.top_unknown_patterns[0].count == 1, "unsupported telemetry lost");
    const auto findings = loglens::Detector{}.analyze(parsed.events);
    require(findings.size() == 1 && findings[0].event_count == 5
            && findings[0].evidence_event_ids == std::vector<std::string>{"line:1", "line:4", "line:5", "line:6", "line:7"},
            "unsupported/blank line entered detector evidence");
}

void timezone_equivalence() {
    for (const auto& prefix : {"Tue 2026-03-10 09:00:00 UTC", "Tue 2026-03-10 09:00:00 Z",
                              "Tue 2026-03-10 09:00:00 GMT", "Tue 2026-03-10 17:00:00 +0800",
                              "Tue 2026-03-11 08:59:00 +23:59", "Mon 2026-03-09 09:01:00 -2359"}) {
        const auto event = parser(true).parse_line(std::string(prefix)
            + " example-host sshd: Failed password for user-a from 203.0.113.1 port 50101 ssh2", 1);
        require(event && event->timestamp.time_since_epoch().count() == 1773133200,
                "timezone instant/rollover changed");
    }
}

void invalid_timestamps() {
    for (const auto& prefix : {"Tue 2026-02-29 09:00:00 UTC", "Tue 2026-03-10 24:00:00 UTC",
                              "Tue 2026-03-10 09:00:60 UTC", "Tue 2026-03-10 09:00:00 +2400",
                              "Tue 2026-03-10 09:00:00 +1260", "Tue 2026-04-31 09:00:00 UTC"}) {
        std::string error;
        auto category = loglens::ParserFailureCategory::UnknownProgram;
        const auto event = parser(true).parse_line(std::string(prefix)
            + " example-host sshd: Failed password for user-a from 203.0.113.1 port 50101 ssh2", 1, &error, &category);
        require(!event && category == loglens::ParserFailureCategory::UnknownTimestamp && !error.empty(),
                "illegal timestamp admitted");
    }
}

void exhaustive_pipeline_properties() {
    std::uint32_t state = 0x129130U;
    for (unsigned run = 0; run < 512; ++run) {
        std::vector<std::uint8_t> bytes(1 + 4 * (run % 24));
        for (auto& byte : bytes) {
            state = state * 1664525U + 1013904223U;
            byte = static_cast<std::uint8_t>(state >> 24U);
        }
        qualification::check_pipeline(bytes.data(), bytes.size());
    }
    // Explicit threshold/window witnesses supplement random structured combinations.
    for (const auto family : {0U, 11U}) {
        for (const auto count : {2U, 3U, 4U, 5U, 6U}) {
            for (unsigned endpoint = 2; endpoint <= 10; ++endpoint) {
                std::vector<std::uint8_t> bytes{0};
                for (unsigned i = 0; i < count; ++i) {
                    bytes.insert(bytes.end(), {static_cast<std::uint8_t>(family),
                        static_cast<std::uint8_t>(i + 1 == count ? endpoint : 0), 0, 0});
                }
                qualification::check_pipeline(bytes.data(), bytes.size());
            }
        }
    }
}

void oracle_negative_controls() {
    std::vector<std::uint8_t> bytes{0};
    for (int i = 0; i < 10; ++i) {
        bytes.insert(bytes.end(), {0, static_cast<std::uint8_t>(i < 5 ? 0 : 11), 0, 0});
    }
    const auto input = qualification::records(bytes.data(), bytes.size());
    const auto expected = qualification::expected_findings(input);
    require(expected.size() == 2, "negative-control witness needs two episodes");
    std::istringstream stream(qualification::render_input(input, false));
    const auto parsed = parser(false).parse_stream(stream);
    const auto findings = loglens::Detector{}.analyze(parsed.events);
    qualification::check_parsed(parsed, input);
    qualification::check_findings(findings, expected);
    const auto reject = [&](const char* label, const char* diagnostic, auto check) {
        bool detected = false;
        try { check(); }
        catch (const std::runtime_error& error) { detected = error.what() == std::string(diagnostic); }
        require(detected, std::string("targeted corruption not detected: ") + label);
        std::cout << "RED_DETECTED " << label << '\n';
    };
    auto lost = parsed;
    lost.events.pop_back();
    lost.warnings.push_back({10, "deliberately unsupported", loglens::ParserFailureCategory::KnownProgramUnknownMessage});
    reject("supported-to-warning", "generated supported evidence lost", [&] { qualification::check_parsed(lost, input); });
    auto admitted = parsed;
    admitted.events.push_back(parsed.events.front());
    reject("unsupported-to-evidence", "generated supported evidence lost", [&] { qualification::check_parsed(admitted, input); });
    auto altered = parsed;
    altered.events[0].timestamp += std::chrono::seconds{1};
    reject("altered-timestamp", "generated normalized fields", [&] { qualification::check_parsed(altered, input); });
    altered = parsed;
    altered.events[0].username = "corrupted-user";
    reject("altered-field", "generated normalized fields", [&] { qualification::check_parsed(altered, input); });
    auto corrupt = findings;
    ++corrupt[0].observed_count;
    reject("wrong-threshold-count", "detector threshold/count", [&] { qualification::check_findings(corrupt, expected); });
    corrupt = findings;
    corrupt[0].evidence_event_ids.pop_back();
    reject("missing-evidence", "detector evidence references", [&] { qualification::check_findings(corrupt, expected); });
    corrupt = findings;
    corrupt[0].evidence_event_ids.push_back(corrupt[0].evidence_event_ids[0]);
    reject("duplicate-evidence", "detector evidence references", [&] { qualification::check_findings(corrupt, expected); });
    corrupt = findings;
    ++corrupt[0].episode_index;
    reject("wrong-episode", "detector episode numbering", [&] { qualification::check_findings(corrupt, expected); });
}
} // namespace

int main() {
    int failures = 0;
    const auto run = [&](const char* name, auto test) {
        try {
            test();
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        }
    };
    run("malformed-source-rejection", malformed_addresses);
    run("valid-source-preservation", valid_addresses);
    run("envelope-host-pid-variation", envelope_variants);
    run("sudo-command-payload-isolation", sudo_payload);
    run("sudo-denial-metadata-precedence", sudo_denial_precedence);
    run("marker-word-username", marker_username);
    run("sudo-metadata-value-isolation", sudo_metadata_values);
    run("sudo-command-field-boundaries", sudo_command_field_boundaries);
    run("authored-family-envelope-matrix", family_matrix);
    run("line-stream-equivalence", line_stream_equivalence);
    run("default-signal-eligibility", signal_eligibility);
    run("unsupported-blank-telemetry-provenance", unsupported_and_blank_insertion);
    run("timezone-instant-equivalence", timezone_equivalence);
    run("invalid-timestamp-taxonomy", invalid_timestamps);
    run("exhaustive-window-pipeline-model", exhaustive_pipeline_properties);
    run("targeted-oracle-negative-controls", oracle_negative_controls);
    return failures == 0 ? 0 : 1;
}
