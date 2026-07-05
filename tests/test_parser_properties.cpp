#include "parser.hpp"
#include "parser/program_dispatch.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

loglens::AuthLogParser make_syslog_parser() {
    return loglens::AuthLogParser(loglens::ParserConfig{
        loglens::InputMode::SyslogLegacy,
        2026});
}

bool events_equal(const loglens::Event& left, const loglens::Event& right) {
    return left.timestamp == right.timestamp
        && left.hostname == right.hostname
        && left.program == right.program
        && left.pid == right.pid
        && left.message == right.message
        && left.source_ip == right.source_ip
        && left.username == right.username
        && left.event_type == right.event_type
        && left.line_number == right.line_number;
}

bool results_equal(const loglens::parser_internal::HandlerResult& left,
                   const loglens::parser_internal::HandlerResult& right) {
    if (left.matched != right.matched
        || left.failure_category != right.failure_category
        || left.reason != right.reason
        || left.event.has_value() != right.event.has_value()) {
        return false;
    }

    return !left.event.has_value() || events_equal(*left.event, *right.event);
}

loglens::Event make_source_event(std::string program, std::string message) {
    loglens::Event event;
    event.program = std::move(program);
    event.message = std::move(message);
    event.hostname = "example-host";
    event.line_number = 1;
    return event;
}

std::array<loglens::Event, 6> representative_registry_events() {
    return {
        make_source_event(
            "sshd",
            "Failed password for user-a from 203.0.113.10 port 50101 ssh2"),
        make_source_event(
            "pam_unix(sshd:auth)",
            "authentication failure; rhost=203.0.113.11 user=user-b"),
        make_source_event(
            "pam_faillock(sshd:auth)",
            "Authentication failure for user user-c from 203.0.113.12"),
        make_source_event(
            "pam_sss(sshd:auth)",
            "received for user user-d: 7 (Authentication failure)"),
        make_source_event(
            "sudo",
            "user-e : TTY=pts/1 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id"),
        make_source_event(
            "su",
            "FAILED SU (to root) user-f on pts/2"),
    };
}

void test_registry_dispatch_is_order_independent() {
    const auto registry = loglens::parser_internal::program_handler_registry();
    const auto sources = representative_registry_events();
    expect(registry.size() == sources.size(), "expected one registry entry per supported program family");

    for (const auto& source : sources) {
        const auto match_count = std::count_if(
            registry.begin(),
            registry.end(),
            [&source](const loglens::parser_internal::ProgramHandlerRegistration& registration) {
                return registration.matches(source.program);
            });
        expect(match_count == 1, "expected each representative program to match exactly one handler");
    }

    std::vector<std::size_t> order(registry.size());
    std::iota(order.begin(), order.end(), 0);
    std::size_t permutation_count = 0;

    do {
        std::vector<loglens::parser_internal::ProgramHandlerRegistration> permuted;
        permuted.reserve(order.size());
        for (const auto index : order) {
            permuted.push_back(registry[index]);
        }

        for (const auto& source : sources) {
            const auto expected = loglens::parser_internal::dispatch_program(source);
            const auto actual = loglens::parser_internal::dispatch_program(source, permuted);
            expect(results_equal(actual, expected), "expected dispatch result to be registry-order independent");
        }
        ++permutation_count;
    } while (std::next_permutation(order.begin(), order.end()));

    expect(permutation_count == 720, "expected all six-handler registry permutations to be checked");
}

std::uint32_t next_random(std::uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

std::string generated_malformed_ipv4(std::size_t index, std::uint32_t& state) {
    const auto first = 1U + next_random(state) % 223U;
    const auto second = next_random(state) % 256U;
    const auto third = next_random(state) % 256U;
    const auto fourth = next_random(state) % 256U;

    switch (index % 4) {
    case 0:
        return std::to_string(first) + "." + std::to_string(second) + "."
            + std::to_string(third) + "." + std::to_string(256U + next_random(state) % 744U);
    case 1:
        return std::to_string(first) + "." + std::to_string(second) + "." + std::to_string(third);
    case 2:
        return std::to_string(first) + ".invalid." + std::to_string(third) + "." + std::to_string(fourth);
    default:
        return std::to_string(first) + "." + std::to_string(second) + "."
            + std::to_string(third) + "." + std::to_string(fourth) + ",";
    }
}

void test_generated_malformed_source_tokens_keep_failure_taxonomy() {
    const auto parser = make_syslog_parser();
    std::uint32_t state = 0x6c6f676cU;

    for (std::size_t index = 0; index < 256; ++index) {
        const auto source_ip = generated_malformed_ipv4(index, state);
        const auto line = "Mar 10 08:30:00 example-host sshd[4200]: Failed password for user-a from "
            + source_ip + " port 50101 ssh2";
        std::string reason;
        auto category = loglens::ParserFailureCategory::KnownProgramUnknownMessage;

        const auto event = parser.parse_line(line, index + 1, &reason, &category);

        expect(!event.has_value(), "expected malformed source token not to emit an event");
        expect(category == loglens::ParserFailureCategory::MalformedSourceIp,
               "expected malformed source token to keep malformed_source_ip category");
        expect(reason == "malformed source IP", "expected stable malformed source failure reason");
    }
}

void test_failure_classification_is_stable_across_envelope_variants() {
    struct FailureCase {
        std::string program;
        std::string message;
        loglens::ParserFailureCategory category;
        std::string reason;
    };

    const std::array<FailureCase, 7> cases{{
        {"sshd", "Connection closed by 203.0.113.50 port 50100 [preauth]",
         loglens::ParserFailureCategory::KnownProgramUnknownMessage,
         "unrecognized auth pattern: sshd_connection_closed_preauth"},
        {"pam_unix(sshd:session)", "session closed for user user-a",
         loglens::ParserFailureCategory::UnsupportedPamVariant,
         "unrecognized auth pattern: pam_unix_session_closed"},
        {"pam_faillock(sshd:auth)", "Account temporarily locked for user user-b",
         loglens::ParserFailureCategory::UnsupportedPamVariant,
         "unrecognized auth pattern: pam_faillock_account_locked"},
        {"pam_sss(sshd:auth)", "User not known to the underlying authentication module",
         loglens::ParserFailureCategory::UnsupportedPamVariant,
         "unrecognized auth pattern: pam_sss_unknown_user"},
        {"sudo", "user-c : TTY=pts/1 ; PWD=/home/user/project ; USER=root",
         loglens::ParserFailureCategory::KnownProgramUnknownMessage,
         "unrecognized auth pattern: sudo_other"},
        {"su", "pam_authenticate: Authentication failure",
         loglens::ParserFailureCategory::KnownProgramUnknownMessage,
         "unrecognized auth pattern: su_other"},
        {"cron", "job completed",
         loglens::ParserFailureCategory::UnknownProgram,
         "unrecognized auth pattern: program_cron"},
    }};

    const auto parser = make_syslog_parser();
    for (const auto& test_case : cases) {
        for (std::size_t variant = 0; variant < 16; ++variant) {
            const auto tag = variant % 2 == 0
                ? test_case.program
                : test_case.program + "[" + std::to_string(4300 + variant) + "]";
            auto line = "Mar 10 08:31:00 example-host " + tag + ": " + test_case.message;
            if (variant % 3 == 0) {
                line.push_back('\r');
            }

            std::string reason;
            auto category = loglens::ParserFailureCategory::MalformedSourceIp;
            const auto event = parser.parse_line(line, variant + 1, &reason, &category);

            expect(!event.has_value(), "expected unsupported pattern not to emit an event");
            expect(category == test_case.category, "expected stable failure category across envelope variants");
            expect(reason == test_case.reason, "expected stable failure reason across envelope variants");
        }
    }
}

void test_deterministic_byte_corpus_never_breaks_result_invariants() {
    const std::array<loglens::AuthLogParser, 2> parsers{{
        make_syslog_parser(),
        loglens::AuthLogParser(loglens::ParserConfig{
            loglens::InputMode::JournalctlShortFull,
            std::nullopt}),
    }};
    std::uint32_t state = 0x70617273U;

    for (std::size_t index = 0; index < 512; ++index) {
        const auto length = static_cast<std::size_t>(next_random(state) % 257U);
        std::string line(length, '\0');
        for (auto& character : line) {
            character = static_cast<char>(next_random(state) & 0xffU);
        }

        for (const auto& parser : parsers) {
            std::string reason;
            auto category = loglens::ParserFailureCategory::KnownProgramUnknownMessage;
            const auto event = parser.parse_line(line, index + 1, &reason, &category);

            if (event.has_value()) {
                expect(event->event_type != loglens::EventType::Unknown,
                       "expected every emitted event to have a normalized type");
                expect(!event->program.empty(), "expected every emitted event to have a program");
            } else {
                expect(!reason.empty(), "expected every rejected input to have a failure reason");
            }
        }
    }
}

}  // namespace

int main() {
    try {
        test_registry_dispatch_is_order_independent();
        test_generated_malformed_source_tokens_keep_failure_taxonomy();
        test_failure_classification_is_stable_across_envelope_variants();
        test_deterministic_byte_corpus_never_breaks_result_invariants();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
