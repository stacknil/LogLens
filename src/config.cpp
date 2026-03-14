#include "config.hpp"

#include <charconv>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

namespace loglens {
namespace {

class JsonCursor {
  public:
    explicit JsonCursor(std::string_view text)
        : text_(text) {}

    void skip_whitespace() {
        while (position_ < text_.size()
               && std::isspace(static_cast<unsigned char>(text_[position_])) != 0) {
            ++position_;
        }
    }

    void expect(char expected, std::string_view context) {
        skip_whitespace();
        if (position_ >= text_.size() || text_[position_] != expected) {
            throw std::runtime_error("invalid config.json: expected '" + std::string(1, expected)
                                     + "' while parsing " + std::string(context));
        }
        ++position_;
    }

    bool consume(char token) {
        skip_whitespace();
        if (position_ < text_.size() && text_[position_] == token) {
            ++position_;
            return true;
        }
        return false;
    }

    std::string parse_string(std::string_view context) {
        skip_whitespace();
        if (position_ >= text_.size() || text_[position_] != '"') {
            throw std::runtime_error("invalid config.json: expected string while parsing "
                                     + std::string(context));
        }

        ++position_;
        std::string value;
        while (position_ < text_.size()) {
            const char current = text_[position_++];
            if (current == '"') {
                return value;
            }
            if (current == '\\') {
                if (position_ >= text_.size()) {
                    throw std::runtime_error("invalid config.json: unterminated escape sequence");
                }

                const char escaped = text_[position_++];
                switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    value.push_back(escaped);
                    break;
                case 'b':
                    value.push_back('\b');
                    break;
                case 'f':
                    value.push_back('\f');
                    break;
                case 'n':
                    value.push_back('\n');
                    break;
                case 'r':
                    value.push_back('\r');
                    break;
                case 't':
                    value.push_back('\t');
                    break;
                default:
                    throw std::runtime_error("invalid config.json: unsupported escape sequence");
                }
                continue;
            }
            value.push_back(current);
        }

        throw std::runtime_error("invalid config.json: unterminated string");
    }

    int parse_positive_int(std::string_view context) {
        skip_whitespace();
        const auto start = position_;
        while (position_ < text_.size()
               && std::isdigit(static_cast<unsigned char>(text_[position_])) != 0) {
            ++position_;
        }

        if (start == position_) {
            throw std::runtime_error("invalid config.json: expected positive integer while parsing "
                                     + std::string(context));
        }

        int value = 0;
        const auto token = text_.substr(start, position_ - start);
        const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
        if (result.ec != std::errc{} || result.ptr != token.data() + token.size() || value <= 0) {
            throw std::runtime_error("invalid config.json: expected positive integer while parsing "
                                     + std::string(context));
        }

        return value;
    }

    bool parse_bool(std::string_view context) {
        skip_whitespace();
        const auto remaining = text_.substr(position_);
        if (remaining.starts_with("true")) {
            position_ += 4;
            return true;
        }
        if (remaining.starts_with("false")) {
            position_ += 5;
            return false;
        }

        throw std::runtime_error("invalid config.json: expected boolean while parsing "
                                 + std::string(context));
    }

    void expect_end() {
        skip_whitespace();
        if (position_ != text_.size()) {
            throw std::runtime_error("invalid config.json: trailing content after root object");
        }
    }

  private:
    std::string_view text_;
    std::size_t position_ = 0;
};

RuleThreshold parse_rule_threshold(JsonCursor& cursor, std::string_view rule_name) {
    cursor.expect('{', rule_name);

    bool threshold_seen = false;
    bool window_seen = false;
    int threshold = 0;
    int window_minutes = 0;
    std::unordered_set<std::string> keys_seen;

    while (true) {
        const auto key = cursor.parse_string(rule_name);
        if (!keys_seen.insert(key).second) {
            throw std::runtime_error("invalid config.json: duplicate key '" + key
                                     + "' in rule '" + std::string(rule_name) + "'");
        }

        cursor.expect(':', key);
        if (key == "threshold") {
            threshold = cursor.parse_positive_int("threshold");
            threshold_seen = true;
        } else if (key == "window_minutes") {
            window_minutes = cursor.parse_positive_int("window_minutes");
            window_seen = true;
        } else {
            throw std::runtime_error("invalid config.json: unexpected key '" + key
                                     + "' in rule '" + std::string(rule_name) + "'");
        }

        if (cursor.consume('}')) {
            break;
        }

        cursor.expect(',', rule_name);
    }

    if (!threshold_seen || !window_seen) {
        throw std::runtime_error("invalid config.json: rule '" + std::string(rule_name)
                                 + "' must contain threshold and window_minutes");
    }

    return RuleThreshold{
        static_cast<std::size_t>(threshold),
        std::chrono::minutes{window_minutes}};
}

AuthSignalBehavior parse_auth_signal_behavior(JsonCursor& cursor, std::string_view signal_name) {
    cursor.expect('{', signal_name);

    bool attempt_seen = false;
    bool terminal_seen = false;
    bool counts_as_attempt_evidence = false;
    bool counts_as_terminal_auth_failure = false;
    std::unordered_set<std::string> keys_seen;

    while (true) {
        const auto key = cursor.parse_string(signal_name);
        if (!keys_seen.insert(key).second) {
            throw std::runtime_error("invalid config.json: duplicate key '" + key
                                     + "' in signal mapping '" + std::string(signal_name) + "'");
        }

        cursor.expect(':', key);
        if (key == "counts_as_attempt_evidence") {
            counts_as_attempt_evidence = cursor.parse_bool(key);
            attempt_seen = true;
        } else if (key == "counts_as_terminal_auth_failure") {
            counts_as_terminal_auth_failure = cursor.parse_bool(key);
            terminal_seen = true;
        } else {
            throw std::runtime_error("invalid config.json: unexpected key '" + key
                                     + "' in signal mapping '" + std::string(signal_name) + "'");
        }

        if (cursor.consume('}')) {
            break;
        }

        cursor.expect(',', signal_name);
    }

    if (!attempt_seen || !terminal_seen) {
        throw std::runtime_error("invalid config.json: signal mapping '" + std::string(signal_name)
                                 + "' must contain counts_as_attempt_evidence and counts_as_terminal_auth_failure");
    }

    return AuthSignalBehavior{counts_as_attempt_evidence, counts_as_terminal_auth_failure};
}

AuthSignalConfig parse_auth_signal_config(JsonCursor& cursor) {
    cursor.expect('{', "auth_signal_mappings");

    AuthSignalConfig config;
    bool ssh_failed_password_seen = false;
    bool ssh_invalid_user_seen = false;
    bool ssh_failed_publickey_seen = false;
    bool pam_auth_failure_seen = false;
    std::unordered_set<std::string> keys_seen;

    while (true) {
        const auto key = cursor.parse_string("auth_signal_mappings");
        if (!keys_seen.insert(key).second) {
            throw std::runtime_error("invalid config.json: duplicate key '" + key
                                     + "' in auth_signal_mappings");
        }

        cursor.expect(':', key);
        if (key == "ssh_failed_password") {
            config.ssh_failed_password = parse_auth_signal_behavior(cursor, key);
            ssh_failed_password_seen = true;
        } else if (key == "ssh_invalid_user") {
            config.ssh_invalid_user = parse_auth_signal_behavior(cursor, key);
            ssh_invalid_user_seen = true;
        } else if (key == "ssh_failed_publickey") {
            config.ssh_failed_publickey = parse_auth_signal_behavior(cursor, key);
            ssh_failed_publickey_seen = true;
        } else if (key == "pam_auth_failure") {
            config.pam_auth_failure = parse_auth_signal_behavior(cursor, key);
            pam_auth_failure_seen = true;
        } else {
            throw std::runtime_error("invalid config.json: unexpected key '" + key
                                     + "' in auth_signal_mappings");
        }

        if (cursor.consume('}')) {
            break;
        }

        cursor.expect(',', "auth_signal_mappings");
    }

    if (!ssh_failed_password_seen || !ssh_invalid_user_seen
        || !ssh_failed_publickey_seen || !pam_auth_failure_seen) {
        throw std::runtime_error(
            "invalid config.json: auth_signal_mappings must contain ssh_failed_password, ssh_invalid_user, ssh_failed_publickey, and pam_auth_failure");
    }

    return config;
}

TimestampConfig parse_timestamp_config(JsonCursor& cursor) {
    cursor.expect('{', "timestamp");

    TimestampConfig config;
    bool assume_year_seen = false;
    std::unordered_set<std::string> keys_seen;

    while (true) {
        const auto key = cursor.parse_string("timestamp");
        if (!keys_seen.insert(key).second) {
            throw std::runtime_error("invalid config.json: duplicate key '" + key + "' in timestamp");
        }

        cursor.expect(':', key);
        if (key == "assume_year") {
            config.assume_year = cursor.parse_positive_int(key);
            assume_year_seen = true;
        } else {
            throw std::runtime_error("invalid config.json: unexpected key '" + key + "' in timestamp");
        }

        if (cursor.consume('}')) {
            break;
        }

        cursor.expect(',', "timestamp");
    }

    if (!assume_year_seen) {
        throw std::runtime_error("invalid config.json: timestamp must contain assume_year");
    }

    return config;
}

}  // namespace

AppConfig load_app_config(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("unable to open config.json: " + path.string());
    }

    const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    JsonCursor cursor(text);
    cursor.expect('{', "root object");

    AppConfig config;
    bool brute_force_seen = false;
    bool multi_user_seen = false;
    bool sudo_seen = false;
    bool auth_signal_mappings_seen = false;
    std::unordered_set<std::string> keys_seen;

    while (true) {
        const auto key = cursor.parse_string("root object");
        if (!keys_seen.insert(key).second) {
            throw std::runtime_error("invalid config.json: duplicate top-level key '" + key + "'");
        }

        cursor.expect(':', key);
        if (key == "brute_force") {
            config.detector.brute_force = parse_rule_threshold(cursor, key);
            brute_force_seen = true;
        } else if (key == "multi_user_probing") {
            config.detector.multi_user_probing = parse_rule_threshold(cursor, key);
            multi_user_seen = true;
        } else if (key == "sudo_burst") {
            config.detector.sudo_burst = parse_rule_threshold(cursor, key);
            sudo_seen = true;
        } else if (key == "auth_signal_mappings") {
            config.detector.auth_signal_mappings = parse_auth_signal_config(cursor);
            auth_signal_mappings_seen = true;
        } else if (key == "input_mode") {
            const auto parsed_mode = parse_input_mode(cursor.parse_string(key));
            if (!parsed_mode.has_value()) {
                throw std::runtime_error("invalid config.json: unsupported input_mode");
            }
            config.input_mode = *parsed_mode;
        } else if (key == "timestamp") {
            config.timestamp = parse_timestamp_config(cursor);
        } else {
            throw std::runtime_error("invalid config.json: unexpected top-level key '" + key + "'");
        }

        if (cursor.consume('}')) {
            break;
        }

        cursor.expect(',', "root object");
    }

    if (!brute_force_seen || !multi_user_seen || !sudo_seen || !auth_signal_mappings_seen) {
        throw std::runtime_error(
            "invalid config.json: root object must contain brute_force, multi_user_probing, sudo_burst, and auth_signal_mappings");
    }

    cursor.expect_end();
    return config;
}

DetectorConfig load_detector_config(const std::filesystem::path& path) {
    return load_app_config(path).detector;
}

}  // namespace loglens
