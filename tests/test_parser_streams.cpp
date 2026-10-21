#include "parser.hpp"

#include <array>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>

namespace {

struct InjectedReadError : std::runtime_error {
    InjectedReadError() : std::runtime_error("injected transport failure") {}
};

// No get area: every consumed character passes through uflow. A fault throws
// before the next character; returning EOF here would model a different contract.
class FaultBuffer : public std::streambuf {
  public:
    explicit FaultBuffer(std::string text,
                         std::size_t fail_after = std::numeric_limits<std::size_t>::max())
        : text_(std::move(text)), fail_after_(fail_after) {}

    std::size_t delivered = 0;

  protected:
    int_type underflow() override {
        if (delivered == fail_after_) {
            throw InjectedReadError{};
        }
        return delivered == text_.size() ? traits_type::eof()
                                        : traits_type::to_int_type(text_[delivered]);
    }

    int_type uflow() override {
        const auto next = underflow();
        if (!traits_type::eq_int_type(next, traits_type::eof())) {
            ++delivered;
        }
        return next;
    }

  private:
    std::string text_;
    std::size_t fail_after_;
};

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct Outcome {
    std::optional<loglens::ParseReport> report;
    std::string exception;
    std::string message;
};

Outcome observe(const loglens::AuthLogParser& parser, std::istream& input,
                const std::string& name, const FaultBuffer& buffer) {
    Outcome outcome;
    try {
        outcome.report = parser.parse_stream(input);
    } catch (const InjectedReadError& error) {
        outcome.exception = "InjectedReadError";
        outcome.message = error.what();
    } catch (const std::ios_base::failure& error) {
        outcome.exception = "ios_base::failure";
        outcome.message = error.what();
    } catch (const std::exception& error) {
        outcome.exception = "unexpected std::exception";
        outcome.message = error.what();
    }
    std::cout << name << " result=" << (outcome.report ? "report" : outcome.exception)
              << " rdstate=" << input.rdstate()
              << " badbit=" << ((input.rdstate() & std::ios::badbit) != 0)
              << " failbit=" << ((input.rdstate() & std::ios::failbit) != 0)
              << " eofbit=" << ((input.rdstate() & std::ios::eofbit) != 0)
              << " delivered=" << buffer.delivered;
    if (outcome.report) {
        std::cout << " events=" << outcome.report->events.size()
                  << " warnings=" << outcome.report->warnings.size();
    }
    std::cout << '\n';
    return outcome;
}

void expect_metadata(const loglens::ParseReport& report, loglens::InputMode mode) {
    expect(report.metadata.input_mode == mode, "input mode changed");
    expect(report.metadata.timezone_present == (mode == loglens::InputMode::JournalctlShortFull),
           "timezone metadata changed");
    expect(report.metadata.assume_year == (mode == loglens::InputMode::SyslogLegacy
               ? std::optional<int>{2026} : std::nullopt), "assumed year changed");
}

std::size_t failures = 0;
std::size_t cases = 0;
std::string_view filter;

template <typename Test>
void run(const std::string& name, Test test) {
    if (!filter.empty() && name.find(filter) == std::string::npos) {
        return;
    }
    ++cases;
    try {
        test();
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "FAIL " << name << ": " << error.what() << '\n';
    }
}

void test_mode(loglens::InputMode mode) {
    const loglens::AuthLogParser parser({mode, mode == loglens::InputMode::SyslogLegacy
                                             ? std::optional<int>{2026} : std::nullopt});
    const std::string prefix = loglens::to_string(mode) + "/";
    const std::string header = mode == loglens::InputMode::SyslogLegacy
        ? "Mar 10 08:11:22 " : "Tue 2026-03-10 08:11:22 UTC ";
    const auto envelope = header + "example-host sshd[1234]: ";
    const auto valid = envelope + "Failed password for user-a from 203.0.113.10 port 50100 ssh2";
    const auto unsupported = envelope + "Connection closed by 203.0.113.10 port 50100 [preauth]";

    for (const bool newline : {true, false}) {
        const auto name = prefix + (newline ? "clean_eof" : "unterminated_final_line");
        run(name, [&] {
            FaultBuffer buffer(valid + "\n" + valid + (newline ? "\n" : ""));
            std::istream input(&buffer);
            const auto outcome = observe(parser, input, name, buffer);
            expect(outcome.report.has_value(), "normal EOF must return a report");
            const auto& report = *outcome.report;
            expect(report.events.size() == 2 && report.warnings.empty(), "final valid record lost");
            expect(report.quality.total_lines == 2 && report.quality.parsed_lines == 2
                       && report.quality.unparsed_lines == 0 && report.quality.parse_success_rate == 1.0,
                   "clean input counts changed");
            expect(report.events[0].line_number == 1 && report.events[1].line_number == 2,
                   "event line numbers changed");
            expect(report.events[1].hostname == "example-host" && report.events[1].username == "user-a"
                       && report.events[1].source_ip == "203.0.113.10"
                       && report.events[1].event_type == loglens::EventType::SshFailedPassword,
                   "owning event content changed");
            expect_metadata(report, mode);
            expect(input.eof() && !input.bad(), "clean EOF state misclassified");
        });
    }

    run(prefix + "content_warnings", [&] {
        FaultBuffer buffer(valid + "\n\n" + unsupported + "\nmalformed\n" + valid + "\n");
        std::istream input(&buffer);
        const auto outcome = observe(parser, input, prefix + "content_warnings", buffer);
        expect(outcome.report.has_value(), "content warnings became transport failure");
        const auto& report = *outcome.report;
        expect(report.events.size() == 2 && report.events[1].line_number == 5, "recovery/event lines changed");
        expect(report.warnings.size() == 2 && report.warnings[0].line_number == 3
                   && report.warnings[1].line_number == 4, "warning line numbers changed");
        expect(report.warnings[0].category == loglens::ParserFailureCategory::KnownProgramUnknownMessage
                   && report.warnings[1].category == loglens::ParserFailureCategory::UnknownTimestamp,
               "content failure taxonomy changed");
        expect(report.quality.total_lines == 4 && report.quality.skipped_blank_lines == 1
                   && report.quality.parsed_lines == 2 && report.quality.unparsed_lines == 2
                   && report.quality.parse_success_rate == 0.5
                   && report.quality.top_unknown_patterns.size() == 2
                   && report.quality.failure_categories.size() == 2, "warning accounting changed");
        expect_metadata(report, mode);
    });

    const auto first_two = valid + "\n" + valid + "\n";
    const auto after_warning = valid + "\nmalformed\n";
    struct FaultCase { const char* name; std::string text; std::size_t position; std::ios::iostate mask; };
    const std::array faults{
        FaultCase{"before_data", first_two, 0, std::ios::goodbit},
        FaultCase{"after_complete_lines", first_two + valid, first_two.size(), std::ios::goodbit},
        FaultCase{"within_line", first_two + valid, first_two.size() + 20, std::ios::goodbit},
        FaultCase{"after_malformed", after_warning + valid, after_warning.size() + 20, std::ios::goodbit},
        FaultCase{"bad_mask_after_lines", first_two + valid, first_two.size(), std::ios::badbit},
        FaultCase{"bad_mask_within_line", first_two + valid, first_two.size() + 20, std::ios::badbit},
        FaultCase{"fail_mask_after_lines", first_two + valid, first_two.size(), std::ios::failbit},
        FaultCase{"fail_mask_within_line", first_two + valid, first_two.size() + 20, std::ios::failbit},
        FaultCase{"combined_mask", first_two + valid, first_two.size() + 20, std::ios::badbit | std::ios::failbit},
        FaultCase{"eof_mask", first_two + valid, first_two.size() + 20, std::ios::eofbit},
    };
    for (const auto& fault : faults) {
        const auto name = prefix + fault.name;
        run(name, [&] {
            FaultBuffer buffer(fault.text, fault.position);
            std::istream input(&buffer);
            input.exceptions(fault.mask);
            const auto outcome = observe(parser, input, name, buffer);
            expect(!outcome.report, "read failure returned a successful partial report");
            expect(outcome.exception == "InjectedReadError" || outcome.exception == "ios_base::failure",
                   "unexpected failure classification");
            expect(input.bad() && !input.eof(), "injected transport failure was mistaken for EOF");
            expect(buffer.delivered == fault.position && input.exceptions() == fault.mask,
                   "fault position or caller exception policy changed");
            expect(outcome.message.find("Failed password") == std::string::npos,
                   "transport diagnostic copied log contents");
        });
    }

    for (const auto state : {std::ios::goodbit, std::ios::failbit, std::ios::badbit,
                            std::ios::badbit | std::ios::eofbit, std::ios::eofbit,
                            std::ios::failbit | std::ios::eofbit}) {
        const auto name = prefix + "initial_state_" + std::to_string(state);
        run(name, [&] {
            FaultBuffer buffer(state == std::ios::goodbit ? "" : valid);
            std::istream input(&buffer);
            input.setstate(state);
            const auto outcome = observe(parser, input, name, buffer);
            const bool failed = (state & std::ios::badbit) != 0
                || ((state & std::ios::failbit) != 0 && (state & std::ios::eofbit) == 0);
            expect(outcome.report.has_value() != failed, "empty/exhausted and failed streams conflated");
            if (outcome.report) {
                expect(outcome.report->events.empty() && outcome.report->warnings.empty()
                           && outcome.report->quality.total_lines == 0, "empty input counts changed");
                expect_metadata(*outcome.report, mode);
            }
            expect(buffer.delivered == 0, "initially failed stream consumed characters");
        });
    }

    // Preserve the caller's native policy: fail/eof exception masks can throw on
    // clean exhaustion too. The parser neither clears state nor changes the mask.
    for (const auto mask : {std::ios::failbit, std::ios::eofbit}) {
        const auto name = prefix + "native_eof_exception_" + std::to_string(mask);
        run(name, [&] {
            FaultBuffer buffer(valid);
            std::istream input(&buffer);
            input.exceptions(mask);
            const auto outcome = observe(parser, input, name, buffer);
            expect(!outcome.report && outcome.exception == "ios_base::failure", "native exception policy changed");
            expect(input.eof() && !input.bad() && input.exceptions() == mask, "normal EOF confused with badbit");
        });
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2) {
        filter = argv[1];
    }
#ifdef __GLIBCXX__
    std::cout << "libstdc++=" << __GLIBCXX__ << '\n';
#endif
#ifdef _MSVC_STL_VERSION
    std::cout << "MSVC_STL=" << _MSVC_STL_VERSION << '\n';
#endif
    test_mode(loglens::InputMode::SyslogLegacy);
    test_mode(loglens::InputMode::JournalctlShortFull);
    std::cout << "stream cases=" << cases << " failed=" << failures << '\n';
    return cases != 0 && failures == 0 ? 0 : 1;
}
