#include "config.hpp"
#include "detector.hpp"
#include "parser.hpp"
#include "signal.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
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

const loglens::Finding* find_finding(const std::vector<loglens::Finding>& findings,
                                     loglens::FindingType type,
                                     const std::string& subject) {
    const auto it = std::find_if(findings.begin(), findings.end(), [&](const loglens::Finding& finding) {
        return finding.type == type && finding.subject == subject;
    });
    return it == findings.end() ? nullptr : &(*it);
}

std::vector<const loglens::Finding*> find_findings(const std::vector<loglens::Finding>& findings,
                                                   loglens::FindingType type,
                                                   const std::string& subject) {
    std::vector<const loglens::Finding*> matches;
    for (const auto& finding : findings) {
        if (finding.type == type && finding.subject == subject) {
            matches.push_back(&finding);
        }
    }
    return matches;
}

const loglens::AuthSignal* find_signal(const std::vector<loglens::AuthSignal>& signals,
                                       loglens::AuthSignalKind signal_kind) {
    const auto it = std::find_if(signals.begin(), signals.end(), [&](const loglens::AuthSignal& signal) {
        return signal.signal_kind == signal_kind;
    });
    return it == signals.end() ? nullptr : &(*it);
}

std::size_t count_signals(const std::vector<loglens::AuthSignal>& signals,
                          loglens::AuthSignalKind signal_kind) {
    return static_cast<std::size_t>(std::count_if(signals.begin(), signals.end(), [&](const loglens::AuthSignal& signal) {
        return signal.signal_kind == signal_kind;
    }));
}

std::vector<loglens::Event> parse_events(loglens::ParserConfig config, std::string_view input_text) {
    const loglens::AuthLogParser parser(config);
    std::istringstream input(std::string{input_text});
    return parser.parse_stream(input).events;
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

std::filesystem::path asset_path(std::string_view filename) {
    return repo_root() / "assets" / std::string(filename);
}

loglens::ParserConfig make_syslog_config() {
    return loglens::ParserConfig{
        loglens::InputMode::SyslogLegacy,
        2026};
}

loglens::ParserConfig make_journalctl_config() {
    return loglens::ParserConfig{
        loglens::InputMode::JournalctlShortFull,
        std::nullopt};
}

std::vector<loglens::Event> build_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed password for invalid user deploy from 203.0.113.10 port 51060 ssh2\n"
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:22:10 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -xe\n"
        "Mar 10 08:24:15 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/ssh/sshd_config\n");
}

std::vector<loglens::Event> build_two_bruteforce_episode_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 09:00:00 example-host sshd[2001]: Failed password for user001 from 203.0.113.10 port 52001 ssh2\n"
        "Mar 10 09:01:00 example-host sshd[2002]: Failed password for user001 from 203.0.113.10 port 52002 ssh2\n"
        "Mar 10 09:02:00 example-host sshd[2003]: Failed password for user001 from 203.0.113.10 port 52003 ssh2\n"
        "Mar 10 09:03:00 example-host sshd[2004]: Failed password for user001 from 203.0.113.10 port 52004 ssh2\n"
        "Mar 10 09:04:00 example-host sshd[2005]: Failed password for user001 from 203.0.113.10 port 52005 ssh2\n"
        "Mar 10 15:00:00 example-host sshd[2006]: Failed password for user001 from 203.0.113.10 port 53001 ssh2\n"
        "Mar 10 15:01:00 example-host sshd[2007]: Failed password for user001 from 203.0.113.10 port 53002 ssh2\n"
        "Mar 10 15:02:00 example-host sshd[2008]: Failed password for user001 from 203.0.113.10 port 53003 ssh2\n"
        "Mar 10 15:03:00 example-host sshd[2009]: Failed password for user001 from 203.0.113.10 port 53004 ssh2\n"
        "Mar 10 15:04:00 example-host sshd[2010]: Failed password for user001 from 203.0.113.10 port 53005 ssh2\n");
}

std::vector<loglens::Event> build_two_multi_user_episode_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 09:00:00 example-host sshd[2101]: Failed password for user001 from 203.0.113.20 port 52001 ssh2\n"
        "Mar 10 09:01:00 example-host sshd[2102]: Failed password for user002 from 203.0.113.20 port 52002 ssh2\n"
        "Mar 10 09:02:00 example-host sshd[2103]: Failed password for user003 from 203.0.113.20 port 52003 ssh2\n"
        "Mar 10 15:00:00 example-host sshd[2104]: Failed password for user004 from 203.0.113.20 port 53001 ssh2\n"
        "Mar 10 15:01:00 example-host sshd[2105]: Failed password for user005 from 203.0.113.20 port 53002 ssh2\n"
        "Mar 10 15:02:00 example-host sshd[2106]: Failed password for user006 from 203.0.113.20 port 53003 ssh2\n");
}

std::vector<loglens::Event> build_two_sudo_episode_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 09:00:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/systemctl status ssh\n"
        "Mar 10 09:01:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/journalctl -u ssh\n"
        "Mar 10 09:02:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/systemctl reload ssh\n"
        "Mar 10 15:00:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/systemctl status ssh\n"
        "Mar 10 15:01:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/journalctl -u ssh\n"
        "Mar 10 15:02:00 example-host sudo:    user001 : TTY=pts/0 ; PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/systemctl reload ssh\n");
}

std::vector<loglens::Event> build_bruteforce_exact_boundary_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 09:00:00 example-host sshd[2201]: Failed password for user001 from 203.0.113.30 port 52001 ssh2\n"
        "Mar 10 09:02:00 example-host sshd[2202]: Failed password for user001 from 203.0.113.30 port 52002 ssh2\n"
        "Mar 10 09:04:00 example-host sshd[2203]: Failed password for user001 from 203.0.113.30 port 52003 ssh2\n"
        "Mar 10 09:06:00 example-host sshd[2204]: Failed password for user001 from 203.0.113.30 port 52004 ssh2\n"
        "Mar 10 09:10:00 example-host sshd[2205]: Failed password for user001 from 203.0.113.30 port 52005 ssh2\n");
}

std::vector<loglens::Event> build_bruteforce_over_boundary_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 09:00:00 example-host sshd[2301]: Failed password for user001 from 203.0.113.31 port 52001 ssh2\n"
        "Mar 10 09:02:00 example-host sshd[2302]: Failed password for user001 from 203.0.113.31 port 52002 ssh2\n"
        "Mar 10 09:04:00 example-host sshd[2303]: Failed password for user001 from 203.0.113.31 port 52003 ssh2\n"
        "Mar 10 09:06:00 example-host sshd[2304]: Failed password for user001 from 203.0.113.31 port 52004 ssh2\n"
        "Mar 10 09:10:01 example-host sshd[2305]: Failed password for user001 from 203.0.113.31 port 52005 ssh2\n");
}

std::vector<loglens::Event> build_publickey_bruteforce_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for root from 203.0.113.10 port 51060 ssh2\n");
}

std::vector<loglens::Event> build_publickey_success_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Accepted publickey for alice from 203.0.113.10 port 51060 ssh2: ED25519 SHA256:SANITIZEDKEY\n");
}

std::vector<loglens::Event> build_pam_bruteforce_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for root from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for root from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for root from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=root\n");
}

std::vector<loglens::Event> build_sudo_signal_candidate_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:21:05 example-host pam_unix(sudo:session): session opened for user root by alice(uid=0)\n"
        "Mar 10 08:21:10 example-host pam_unix(sshd:session): session closed for user alice\n");
}

std::vector<loglens::Event> build_sudo_burst_preservation_events() {
    return parse_events(
        make_syslog_config(),
        "Mar 10 08:21:00 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh\n"
        "Mar 10 08:21:05 example-host pam_unix(sudo:session): session opened for user root by alice(uid=0)\n"
        "Mar 10 08:22:10 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -xe\n"
        "Mar 10 08:24:15 example-host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/vi /etc/ssh/sshd_config\n");
}

void expect_same_rule_threshold(const loglens::RuleThreshold& actual,
                                const loglens::RuleThreshold& expected,
                                const std::string& rule_name) {
    expect(actual.threshold == expected.threshold, "expected " + rule_name + " threshold to match default");
    expect(actual.window == expected.window, "expected " + rule_name + " window to match default");
}

void expect_same_auth_signal_behavior(const loglens::AuthSignalBehavior& actual,
                                      const loglens::AuthSignalBehavior& expected,
                                      const std::string& signal_name) {
    expect(actual.counts_as_attempt_evidence == expected.counts_as_attempt_evidence,
           "expected " + signal_name + " attempt-evidence mapping to match default");
    expect(actual.counts_as_terminal_auth_failure == expected.counts_as_terminal_auth_failure,
           "expected " + signal_name + " terminal-failure mapping to match default");
}

void expect_same_detector_config(const loglens::DetectorConfig& actual,
                                 const loglens::DetectorConfig& expected) {
    expect_same_rule_threshold(actual.brute_force, expected.brute_force, "brute_force");
    expect_same_rule_threshold(actual.multi_user_probing, expected.multi_user_probing, "multi_user_probing");
    expect_same_rule_threshold(actual.sudo_burst, expected.sudo_burst, "sudo_burst");

    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.ssh_failed_password,
        expected.auth_signal_mappings.ssh_failed_password,
        "ssh_failed_password");
    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.ssh_invalid_user,
        expected.auth_signal_mappings.ssh_invalid_user,
        "ssh_invalid_user");
    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.ssh_failed_publickey,
        expected.auth_signal_mappings.ssh_failed_publickey,
        "ssh_failed_publickey");
    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.ssh_failed_keyboard_interactive,
        expected.auth_signal_mappings.ssh_failed_keyboard_interactive,
        "ssh_failed_keyboard_interactive");
    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.ssh_max_auth_tries,
        expected.auth_signal_mappings.ssh_max_auth_tries,
        "ssh_max_auth_tries");
    expect_same_auth_signal_behavior(
        actual.auth_signal_mappings.pam_auth_failure,
        expected.auth_signal_mappings.pam_auth_failure,
        "pam_auth_failure");
}

void test_default_thresholds() {
    const auto events = build_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    expect(findings.size() == 3, "expected three findings");

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force != nullptr, "expected brute force finding");
    expect(brute_force->rule_id == "brute_force", "expected brute force rule id");
    expect(brute_force->grouping_key == "source_ip", "expected brute force grouping key");
    expect(brute_force->threshold == 5, "expected brute force threshold");
    expect(brute_force->observed_count == 5, "expected brute force observed count");
    expect(brute_force->event_count == 5, "expected brute force count");
    expect((brute_force->evidence_event_ids == std::vector<std::string>{
               "line:1", "line:2", "line:3", "line:4", "line:5"}),
           "expected brute force evidence event ids");
    expect(brute_force->verdict_boundary == "triage_signal_not_compromise_or_attribution",
           "expected brute force verdict boundary");

    const auto* multi_user = find_finding(findings, loglens::FindingType::MultiUserProbing, "203.0.113.10");
    expect(multi_user != nullptr, "expected multi-user finding");
    expect(multi_user->rule_id == "multi_user_probing", "expected multi-user rule id");
    expect(multi_user->grouping_key == "source_ip", "expected multi-user grouping key");
    expect(multi_user->threshold == 3, "expected multi-user threshold");
    expect(multi_user->observed_count == 5, "expected multi-user observed username count");
    expect(multi_user->event_count == 5, "expected multi-user event count");
    expect((multi_user->evidence_event_ids == std::vector<std::string>{
               "line:1", "line:2", "line:3", "line:4", "line:5"}),
           "expected multi-user evidence event ids");
    expect(multi_user->verdict_boundary == "triage_signal_not_intent_or_attribution",
           "expected multi-user verdict boundary");
    expect(multi_user->usernames.size() == 5, "expected five usernames");

    const auto* sudo = find_finding(findings, loglens::FindingType::SudoBurst, "alice");
    expect(sudo != nullptr, "expected sudo finding");
    expect(sudo->rule_id == "sudo_burst", "expected sudo rule id");
    expect(sudo->grouping_key == "username", "expected sudo grouping key");
    expect(sudo->threshold == 3, "expected sudo threshold");
    expect(sudo->observed_count == 3, "expected sudo observed count");
    expect(sudo->event_count == 3, "expected sudo count");
    expect((sudo->evidence_event_ids == std::vector<std::string>{"line:6", "line:7", "line:8"}),
           "expected sudo evidence event ids");
    expect(sudo->verdict_boundary == "triage_signal_not_maliciousness_or_authorization",
           "expected sudo verdict boundary");
}

void test_custom_thresholds() {
    const auto events = build_events();
    loglens::DetectorConfig config;
    config.brute_force.threshold = 6;
    config.multi_user_probing.threshold = 6;
    config.sudo_burst.threshold = 4;

    const loglens::Detector detector(config);
    const auto findings = detector.analyze(events);
    expect(findings.empty(), "expected custom thresholds to suppress findings");
}

void test_bruteforce_emits_multiple_episodes_for_same_source() {
    const auto events = build_two_bruteforce_episode_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto episodes = find_findings(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(episodes.size() == 2, "expected two brute-force episodes for the same source IP");
    expect(episodes[0]->episode_index == 1, "expected first brute-force episode index");
    expect(episodes[1]->episode_index == 2, "expected second brute-force episode index");
    expect(episodes[0]->finding_id.rfind("finding:brute_force:", 0) == 0,
           "expected first brute-force stable finding id");
    expect(episodes[1]->finding_id.rfind("finding:brute_force:", 0) == 0,
           "expected second brute-force stable finding id");
    expect(episodes[0]->finding_id != episodes[1]->finding_id,
           "expected separated brute-force episodes to have distinct finding ids");
    expect(episodes[0]->event_count == 5, "expected first brute-force episode count");
    expect(episodes[0]->observed_count == 5, "expected first brute-force observed count");
    expect(loglens::format_timestamp(episodes[0]->first_seen) == "2026-03-10 09:00:00",
           "expected first brute-force episode start");
    expect(loglens::format_timestamp(episodes[0]->last_seen) == "2026-03-10 09:04:00",
           "expected first brute-force episode end");
    expect((episodes[0]->evidence_event_ids == std::vector<std::string>{
               "line:1", "line:2", "line:3", "line:4", "line:5"}),
           "expected first brute-force episode evidence ids");

    expect(episodes[1]->event_count == 5, "expected second brute-force episode count");
    expect(episodes[1]->observed_count == 5, "expected second brute-force observed count");
    expect(loglens::format_timestamp(episodes[1]->first_seen) == "2026-03-10 15:00:00",
           "expected second brute-force episode start");
    expect(loglens::format_timestamp(episodes[1]->last_seen) == "2026-03-10 15:04:00",
           "expected second brute-force episode end");
    expect((episodes[1]->evidence_event_ids == std::vector<std::string>{
               "line:6", "line:7", "line:8", "line:9", "line:10"}),
           "expected second brute-force episode evidence ids");
}

void test_multi_user_emits_multiple_episodes_for_same_source() {
    const auto events = build_two_multi_user_episode_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto episodes = find_findings(findings, loglens::FindingType::MultiUserProbing, "203.0.113.20");
    expect(episodes.size() == 2, "expected two multi-user probing episodes for the same source IP");
    expect(episodes[0]->episode_index == 1, "expected first multi-user episode index");
    expect(episodes[1]->episode_index == 2, "expected second multi-user episode index");
    expect(episodes[0]->finding_id.rfind("finding:multi_user_probing:", 0) == 0,
           "expected first multi-user stable finding id");
    expect(episodes[1]->finding_id.rfind("finding:multi_user_probing:", 0) == 0,
           "expected second multi-user stable finding id");
    expect(episodes[0]->finding_id != episodes[1]->finding_id,
           "expected separated multi-user episodes to have distinct finding ids");
    expect(episodes[0]->event_count == 3, "expected first multi-user episode event count");
    expect(episodes[0]->observed_count == 3, "expected first multi-user episode distinct username count");
    expect((episodes[0]->usernames == std::vector<std::string>{"user001", "user002", "user003"}),
           "expected first multi-user episode usernames");
    expect(loglens::format_timestamp(episodes[0]->first_seen) == "2026-03-10 09:00:00",
           "expected first multi-user episode start");
    expect(loglens::format_timestamp(episodes[0]->last_seen) == "2026-03-10 09:02:00",
           "expected first multi-user episode end");

    expect(episodes[1]->event_count == 3, "expected second multi-user episode event count");
    expect(episodes[1]->observed_count == 3, "expected second multi-user episode distinct username count");
    expect((episodes[1]->usernames == std::vector<std::string>{"user004", "user005", "user006"}),
           "expected second multi-user episode usernames");
    expect(loglens::format_timestamp(episodes[1]->first_seen) == "2026-03-10 15:00:00",
           "expected second multi-user episode start");
    expect(loglens::format_timestamp(episodes[1]->last_seen) == "2026-03-10 15:02:00",
           "expected second multi-user episode end");
}

void test_sudo_burst_emits_multiple_episodes_for_same_user() {
    const auto events = build_two_sudo_episode_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto episodes = find_findings(findings, loglens::FindingType::SudoBurst, "user001");
    expect(episodes.size() == 2, "expected two sudo burst episodes for the same user");
    expect(episodes[0]->episode_index == 1, "expected first sudo episode index");
    expect(episodes[1]->episode_index == 2, "expected second sudo episode index");
    expect(episodes[0]->finding_id.rfind("finding:sudo_burst:", 0) == 0,
           "expected first sudo stable finding id");
    expect(episodes[1]->finding_id.rfind("finding:sudo_burst:", 0) == 0,
           "expected second sudo stable finding id");
    expect(episodes[0]->finding_id != episodes[1]->finding_id,
           "expected separated sudo episodes to have distinct finding ids");
    expect(episodes[0]->event_count == 3, "expected first sudo episode count");
    expect(episodes[0]->observed_count == 3, "expected first sudo episode observed count");
    expect(loglens::format_timestamp(episodes[0]->first_seen) == "2026-03-10 09:00:00",
           "expected first sudo episode start");
    expect(loglens::format_timestamp(episodes[0]->last_seen) == "2026-03-10 09:02:00",
           "expected first sudo episode end");
    expect((episodes[0]->evidence_event_ids == std::vector<std::string>{"line:1", "line:2", "line:3"}),
           "expected first sudo episode evidence ids");

    expect(episodes[1]->event_count == 3, "expected second sudo episode count");
    expect(episodes[1]->observed_count == 3, "expected second sudo episode observed count");
    expect(loglens::format_timestamp(episodes[1]->first_seen) == "2026-03-10 15:00:00",
           "expected second sudo episode start");
    expect(loglens::format_timestamp(episodes[1]->last_seen) == "2026-03-10 15:02:00",
           "expected second sudo episode end");
    expect((episodes[1]->evidence_event_ids == std::vector<std::string>{"line:4", "line:5", "line:6"}),
           "expected second sudo episode evidence ids");
}

void test_episode_identity_is_stable_for_unsorted_input_events() {
    const auto ordered_events = build_two_bruteforce_episode_events();
    const std::vector<loglens::Event> shuffled_events{
        ordered_events[7],
        ordered_events[0],
        ordered_events[4],
        ordered_events[8],
        ordered_events[1],
        ordered_events[5],
        ordered_events[2],
        ordered_events[9],
        ordered_events[3],
        ordered_events[6]};

    const loglens::Detector detector;
    const auto ordered_findings = detector.analyze(ordered_events);
    const auto shuffled_findings = detector.analyze(shuffled_events);
    const auto ordered_episodes = find_findings(ordered_findings, loglens::FindingType::BruteForce, "203.0.113.10");
    const auto shuffled_episodes = find_findings(shuffled_findings, loglens::FindingType::BruteForce, "203.0.113.10");

    expect(ordered_episodes.size() == 2, "expected ordered input to produce two brute-force episodes");
    expect(shuffled_episodes.size() == 2, "expected shuffled input to produce two brute-force episodes");
    for (std::size_t index = 0; index < ordered_episodes.size(); ++index) {
        expect(ordered_episodes[index]->episode_index == shuffled_episodes[index]->episode_index,
               "expected shuffled input to preserve episode index");
        expect(ordered_episodes[index]->finding_id == shuffled_episodes[index]->finding_id,
               "expected shuffled input to preserve stable finding id");
        expect(ordered_episodes[index]->first_seen == shuffled_episodes[index]->first_seen,
               "expected shuffled input to preserve episode start");
        expect(ordered_episodes[index]->last_seen == shuffled_episodes[index]->last_seen,
               "expected shuffled input to preserve episode end");
    }

    auto relabeled_episode = *ordered_episodes[0];
    relabeled_episode.episode_index = 99;
    expect(loglens::build_finding_id(relabeled_episode) == ordered_episodes[0]->finding_id,
           "expected finding id to remain independent of episode index");
}

void test_bruteforce_window_boundary_is_inclusive() {
    const loglens::Detector detector;

    const auto exact_findings = detector.analyze(build_bruteforce_exact_boundary_events());
    const auto exact = find_findings(exact_findings, loglens::FindingType::BruteForce, "203.0.113.30");
    expect(exact.size() == 1, "expected exact ten-minute boundary to count inside the window");
    expect(exact[0]->event_count == 5, "expected exact-boundary brute-force count");
    expect(loglens::format_timestamp(exact[0]->first_seen) == "2026-03-10 09:00:00",
           "expected exact-boundary window start");
    expect(loglens::format_timestamp(exact[0]->last_seen) == "2026-03-10 09:10:00",
           "expected exact-boundary window end");

    const auto over_findings = detector.analyze(build_bruteforce_over_boundary_events());
    const auto over = find_findings(over_findings, loglens::FindingType::BruteForce, "203.0.113.31");
    expect(over.empty(), "expected one second over the window to stay below threshold");
}

void test_auth_signal_defaults() {
    const auto events = parse_events(
        make_syslog_config(),
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for root from 203.0.113.10 port 51060 ssh2\n"
        "Mar 10 08:18:06 example-host sshd[1239]: Failed keyboard-interactive/pam for root from 203.0.113.12 port 51061 ssh2\n"
        "Mar 10 08:18:07 example-host sshd[1240]: maximum authentication attempts exceeded for root from 203.0.113.13 port 51062 ssh2 [preauth]\n"
        "Mar 10 08:18:08 example-host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.11  user=alice\n");

    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);
    expect(signals.size() == 4, "expected four auth signals");

    const auto* publickey = find_signal(signals, loglens::AuthSignalKind::SshFailedPublicKey);
    expect(publickey != nullptr, "expected publickey signal");
    expect(publickey->counts_as_attempt_evidence, "expected publickey to count as attempt evidence");
    expect(publickey->counts_as_terminal_auth_failure, "expected publickey to count as terminal auth failure");

    const auto* keyboard_interactive = find_signal(signals, loglens::AuthSignalKind::SshFailedKeyboardInteractive);
    expect(keyboard_interactive != nullptr, "expected keyboard-interactive signal");
    expect(keyboard_interactive->counts_as_attempt_evidence,
           "expected keyboard-interactive to count as attempt evidence");
    expect(keyboard_interactive->counts_as_terminal_auth_failure,
           "expected keyboard-interactive to count as terminal auth failure");

    const auto* max_auth_tries = find_signal(signals, loglens::AuthSignalKind::SshMaxAuthTries);
    expect(max_auth_tries != nullptr, "expected max-auth-tries signal");
    expect(max_auth_tries->counts_as_attempt_evidence,
           "expected max-auth-tries to count as attempt evidence");
    expect(max_auth_tries->counts_as_terminal_auth_failure,
           "expected max-auth-tries to count as terminal auth failure");

    const auto* pam = find_signal(signals, loglens::AuthSignalKind::PamAuthFailure);
    expect(pam != nullptr, "expected pam auth signal");
    expect(pam->counts_as_attempt_evidence, "expected pam auth failure to count as attempt evidence");
    expect(!pam->counts_as_terminal_auth_failure, "expected pam auth failure to stay non-terminal by default");
}

void test_failed_publickey_contributes_to_bruteforce_by_default() {
    const auto events = build_publickey_bruteforce_candidate_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force != nullptr, "expected publickey evidence to contribute to brute force");
    expect(brute_force->event_count == 5, "expected publickey evidence to raise brute force count to five");
}

void test_accepted_publickey_success_stays_out_of_failure_signals() {
    const auto events = build_publickey_success_candidate_events();
    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);

    expect(signals.size() == 4, "expected accepted publickey success to stay out of the signal layer");

    const loglens::Detector detector;
    const auto findings = detector.analyze(events);
    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force == nullptr,
           "expected accepted publickey success to stay out of brute-force counting");
}

void test_sudo_signals_include_command_and_session_opened() {
    const auto events = build_sudo_signal_candidate_events();
    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);

    expect(signals.size() == 2, "expected sudo command and supported sudo session-opened signals only");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoCommand) == 1,
           "expected one sudo command signal");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoSessionOpened) == 1,
           "expected one sudo session-opened signal");

    const auto* sudo_command = find_signal(signals, loglens::AuthSignalKind::SudoCommand);
    expect(sudo_command != nullptr, "expected sudo command signal");
    expect(sudo_command->counts_as_sudo_burst_evidence,
           "expected sudo command signal to count toward sudo burst evidence");
    expect(!sudo_command->counts_as_attempt_evidence, "did not expect sudo command to count as auth attempt evidence");
    expect(!sudo_command->counts_as_terminal_auth_failure,
           "did not expect sudo command to count as terminal auth failure");

    const auto* sudo_session = find_signal(signals, loglens::AuthSignalKind::SudoSessionOpened);
    expect(sudo_session != nullptr, "expected sudo session-opened signal");
    expect(!sudo_session->counts_as_sudo_burst_evidence,
           "expected sudo session-opened signal to stay out of sudo burst counting by default");
    expect(!sudo_session->counts_as_attempt_evidence,
           "did not expect sudo session-opened to count as auth attempt evidence");
    expect(!sudo_session->counts_as_terminal_auth_failure,
           "did not expect sudo session-opened to count as terminal auth failure");
}

void test_privilege_auth_failures_are_non_counting_signals() {
    const auto events = parse_events(
        make_syslog_config(),
        "Mar 10 08:21:40 example-host sudo:    alice : 1 incorrect password attempt ; TTY=pts/0 ; "
        "PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id\n"
        "Mar 10 08:21:45 example-host sudo:    bob : user NOT in sudoers ; TTY=pts/1 ; "
        "PWD=/home/user/project ; USER=root ; COMMAND=/usr/bin/id\n"
        "Mar 10 08:21:50 example-host su[1243]: FAILED SU (to root) carol on pts/2\n");
    expect(events.size() == 3, "expected sudo and su auth failures to parse");
    expect(events[0].event_type == loglens::EventType::SudoAuthFailure,
           "expected sudo password failure event");
    expect(events[1].event_type == loglens::EventType::SudoPolicyDenied,
           "expected sudo policy denied event");
    expect(events[2].event_type == loglens::EventType::SuAuthFailure,
           "expected su auth failure event");

    const auto signals = loglens::build_auth_signals(events, loglens::DetectorConfig{}.auth_signal_mappings);
    expect(signals.size() == 3, "expected privilege auth failures to be visible as signals");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoAuthFailure) == 1,
           "expected one sudo auth failure signal");
    expect(count_signals(signals, loglens::AuthSignalKind::SudoPolicyDenied) == 1,
           "expected one sudo policy denied signal");
    expect(count_signals(signals, loglens::AuthSignalKind::SuAuthFailure) == 1,
           "expected one su auth failure signal");

    for (const auto& signal : signals) {
        expect(!signal.counts_as_attempt_evidence,
               "did not expect privilege auth signals to count as auth attempt evidence");
        expect(!signal.counts_as_terminal_auth_failure,
               "did not expect privilege auth signals to count as terminal auth failures");
        expect(!signal.counts_as_sudo_burst_evidence,
               "did not expect privilege auth signals to count toward sudo burst evidence");
    }

    const loglens::Detector detector;
    const auto findings = detector.analyze(events);
    expect(findings.empty(), "expected privilege auth signals to stay out of detector findings by default");
}

void test_sudo_burst_behavior_is_preserved_with_signal_layer() {
    const auto events = build_sudo_burst_preservation_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* sudo = find_finding(findings, loglens::FindingType::SudoBurst, "alice");
    expect(sudo != nullptr, "expected sudo burst finding");
    expect(sudo->event_count == 3,
           "expected sudo burst count to remain based on command events rather than session-opened lines");
}

void test_unsupported_pam_session_close_remains_telemetry_only() {
    const loglens::AuthLogParser parser(make_syslog_config());
    std::istringstream input(
        "Mar 10 09:06:10 example-host pam_unix(sudo:session): session closed for user alice\n");

    const auto result = parser.parse_stream(input);
    expect(result.events.empty(), "expected unsupported session-close line to stay out of parsed events");
    expect(result.warnings.size() == 1, "expected unsupported session-close line to produce one warning");
    expect(result.quality.top_unknown_patterns.size() == 1, "expected one unknown pattern bucket");
    expect(result.quality.top_unknown_patterns.front().pattern == "pam_unix_session_closed",
           "expected unsupported session-close line to remain in session-closed telemetry");

    const auto signals = loglens::build_auth_signals(result.events, loglens::DetectorConfig{}.auth_signal_mappings);
    expect(signals.empty(), "expected unsupported session-close line to stay out of the signal layer");
}

void test_pam_auth_failure_does_not_trigger_bruteforce_by_default() {
    const auto events = build_pam_bruteforce_candidate_events();
    const loglens::Detector detector;
    const auto findings = detector.analyze(events);

    const auto* brute_force = find_finding(findings, loglens::FindingType::BruteForce, "203.0.113.10");
    expect(brute_force == nullptr, "expected pam auth failure to stay out of brute force by default");
}

void test_equivalent_attack_scenario_yields_same_finding_count_across_modes() {
    const auto syslog_events = parse_events(
        make_syslog_config(),
        "Mar 10 08:11:22 example-host sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Mar 10 08:12:05 example-host sshd[1235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Mar 10 08:13:10 example-host sshd[1236]: Failed password for test from 203.0.113.10 port 51040 ssh2\n"
        "Mar 10 08:14:44 example-host sshd[1237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Mar 10 08:18:05 example-host sshd[1238]: Failed publickey for invalid user deploy from 203.0.113.10 port 51060 ssh2\n");

    const auto journalctl_events = parse_events(
        make_journalctl_config(),
        "Tue 2026-03-10 08:11:22 UTC example-host sshd[2234]: Failed password for invalid user admin from 203.0.113.10 port 51022 ssh2\n"
        "Tue 2026-03-10 08:12:05 UTC example-host sshd[2235]: Failed password for root from 203.0.113.10 port 51030 ssh2\n"
        "Tue 2026-03-10 08:13:10 UTC example-host sshd[2236]: Failed password for test from 203.0.113.10 port 51040 ssh\n"
        "Tue 2026-03-10 08:14:44 UTC example-host sshd[2237]: Failed password for guest from 203.0.113.10 port 51050 ssh2\n"
        "Tue 2026-03-10 08:18:05 UTC example-host sshd[2238]: Failed publickey for invalid user deploy from 203.0.113.10 port 51060 ssh2\n");

    const loglens::Detector detector;
    const auto syslog_findings = detector.analyze(syslog_events);
    const auto journalctl_findings = detector.analyze(journalctl_events);

    expect(syslog_findings.size() == journalctl_findings.size(),
           "expected equivalent scenarios to yield the same finding count across modes");
    expect(find_finding(syslog_findings, loglens::FindingType::BruteForce, "203.0.113.10") != nullptr,
           "expected syslog brute force finding");
    expect(find_finding(journalctl_findings, loglens::FindingType::BruteForce, "203.0.113.10") != nullptr,
           "expected journalctl brute force finding");
}

void test_load_valid_config() {
    const auto temp_path = std::filesystem::current_path() / "valid_config_test.json";
    {
        std::ofstream output(temp_path);
        output << "{\n"
               << "  \"input_mode\": \"syslog_legacy\",\n"
               << "  \"timestamp\": { \"assume_year\": 2026 },\n"
               << "  \"brute_force\": { \"threshold\": 5, \"window_minutes\": 10 },\n"
               << "  \"multi_user_probing\": { \"threshold\": 3, \"window_minutes\": 15 },\n"
               << "  \"sudo_burst\": { \"threshold\": 3, \"window_minutes\": 5 },\n"
               << "  \"auth_signal_mappings\": {\n"
               << "    \"ssh_failed_password\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_invalid_user\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_failed_publickey\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"pam_auth_failure\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": false }\n"
               << "  }\n"
               << "}\n";
    }

    const auto config = loglens::load_app_config(temp_path);
    std::filesystem::remove(temp_path);

    expect(config.input_mode == loglens::InputMode::SyslogLegacy, "expected input mode from config");
    expect(config.timestamp.assume_year == 2026, "expected assume_year from config");
    expect(config.detector.brute_force.threshold == 5, "expected brute force threshold from config");
    expect(config.detector.auth_signal_mappings.ssh_failed_publickey.counts_as_terminal_auth_failure,
           "expected publickey mapping from config");
    expect(!config.detector.auth_signal_mappings.pam_auth_failure.counts_as_terminal_auth_failure,
           "expected pam auth mapping from config");

    const auto events = build_events();
    const loglens::Detector detector(config.detector);
    const auto findings = detector.analyze(events);
    expect(findings.size() == 3, "expected loaded config to preserve default findings");
}

void test_sample_config_matches_default_detector_contract() {
    const auto config = loglens::load_app_config(asset_path("sample_config.json"));
    expect(config.input_mode == loglens::InputMode::SyslogLegacy,
           "expected sample config to use syslog legacy input");
    expect(config.timestamp.assume_year == 2026,
           "expected sample config to provide the sample syslog year");
    expect_same_detector_config(config.detector, loglens::DetectorConfig{});

    const auto events = build_events();
    const loglens::Detector default_detector;
    const loglens::Detector sample_config_detector(config.detector);
    const auto default_findings = default_detector.analyze(events);
    const auto sample_config_findings = sample_config_detector.analyze(events);

    expect(sample_config_findings.size() == default_findings.size(),
           "expected sample config to preserve default finding count");
    expect(find_finding(sample_config_findings, loglens::FindingType::BruteForce, "203.0.113.10") != nullptr,
           "expected sample config to preserve brute-force finding");
    expect(find_finding(sample_config_findings, loglens::FindingType::MultiUserProbing, "203.0.113.10") != nullptr,
           "expected sample config to preserve multi-user finding");
    expect(find_finding(sample_config_findings, loglens::FindingType::SudoBurst, "alice") != nullptr,
           "expected sample config to preserve sudo-burst finding");
}

void test_reject_invalid_config() {
    const auto temp_path = std::filesystem::current_path() / "invalid_config_test.json";
    {
        std::ofstream output(temp_path);
        output << "{\n"
               << "  \"input_mode\": \"syslog_legacy\",\n"
               << "  \"timestamp\": { \"assume_year\": \"bad\" },\n"
               << "  \"brute_force\": { \"threshold\": 5, \"window_minutes\": 10 },\n"
               << "  \"multi_user_probing\": { \"threshold\": 3, \"window_minutes\": 15 },\n"
               << "  \"sudo_burst\": { \"threshold\": 3, \"window_minutes\": 5 },\n"
               << "  \"auth_signal_mappings\": {\n"
               << "    \"ssh_failed_password\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_invalid_user\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"ssh_failed_publickey\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": true },\n"
               << "    \"pam_auth_failure\": { \"counts_as_attempt_evidence\": true, \"counts_as_terminal_auth_failure\": false }\n"
               << "  }\n"
               << "}\n";
    }

    bool threw = false;
    std::string message;
    try {
        static_cast<void>(loglens::load_app_config(temp_path));
    } catch (const std::runtime_error& error) {
        threw = true;
        message = error.what();
    }

    std::filesystem::remove(temp_path);
    expect(threw, "expected invalid config to be rejected");
    expect(message.find("assume_year") != std::string::npos,
           "expected invalid config error to mention assume_year");
}

}  // namespace

int main() {
    test_default_thresholds();
    test_custom_thresholds();
    test_bruteforce_emits_multiple_episodes_for_same_source();
    test_multi_user_emits_multiple_episodes_for_same_source();
    test_sudo_burst_emits_multiple_episodes_for_same_user();
    test_episode_identity_is_stable_for_unsorted_input_events();
    test_bruteforce_window_boundary_is_inclusive();
    test_auth_signal_defaults();
    test_failed_publickey_contributes_to_bruteforce_by_default();
    test_accepted_publickey_success_stays_out_of_failure_signals();
    test_sudo_signals_include_command_and_session_opened();
    test_privilege_auth_failures_are_non_counting_signals();
    test_sudo_burst_behavior_is_preserved_with_signal_layer();
    test_unsupported_pam_session_close_remains_telemetry_only();
    test_pam_auth_failure_does_not_trigger_bruteforce_by_default();
    test_equivalent_attack_scenario_yields_same_finding_count_across_modes();
    test_load_valid_config();
    test_sample_config_matches_default_detector_contract();
    test_reject_invalid_config();
    return 0;
}
