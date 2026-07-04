#pragma once

#include <string>
#include <string_view>

namespace loglens::parser_internal {

std::string_view trim_left(std::string_view value);
std::string_view trim(std::string_view value);
std::string_view consume_token(std::string_view& input);
bool parse_int(std::string_view token, int& value);
std::string extract_token_after(std::string_view input, std::string_view marker);
std::string extract_kv_value(std::string_view input, std::string_view key);
std::string sanitize_pattern_label(std::string_view value);

}  // namespace loglens::parser_internal
