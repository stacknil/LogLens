#include "parser/text_utils.hpp"

#include <charconv>
#include <cctype>

namespace loglens::parser_internal {

std::string_view trim_left(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    return value;
}

std::string_view trim(std::string_view value) {
    value = trim_left(value);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
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

bool parse_int(std::string_view token, int& value) {
    const auto* begin = token.data();
    const auto* end = token.data() + token.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

std::string extract_token_after(std::string_view input, std::string_view marker) {
    const auto marker_position = input.find(marker);
    if (marker_position == std::string_view::npos) {
        return {};
    }

    auto remaining = input.substr(marker_position + marker.size());
    return std::string(consume_token(remaining));
}

std::string extract_kv_value(std::string_view input, std::string_view key) {
    std::size_t search_position = 0;
    while (search_position < input.size()) {
        const auto key_position = input.find(key, search_position);
        if (key_position == std::string_view::npos) {
            return {};
        }

        if (key_position == 0
            || std::isspace(static_cast<unsigned char>(input[key_position - 1])) != 0
            || input[key_position - 1] == ';') {
            auto remaining = input.substr(key_position + key.size());
            const auto end = remaining.find_first_of(" ;");
            if (end != std::string_view::npos) {
                remaining = remaining.substr(0, end);
            }
            return std::string(remaining);
        }

        search_position = key_position + key.size();
    }

    return {};
}

std::string sanitize_pattern_label(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());

    bool previous_was_separator = false;
    for (const char character : value) {
        if (std::isalnum(static_cast<unsigned char>(character)) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
            previous_was_separator = false;
            continue;
        }

        if (!normalized.empty() && !previous_was_separator) {
            normalized.push_back('_');
            previous_was_separator = true;
        }
    }

    while (!normalized.empty() && normalized.back() == '_') {
        normalized.pop_back();
    }

    return normalized.empty() ? "unknown_pattern" : normalized;
}

}  // namespace loglens::parser_internal
