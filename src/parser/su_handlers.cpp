#include "parser/su_handlers.hpp"

#include "parser/failure_classifier.hpp"
#include "parser/text_utils.hpp"

#include <string_view>
#include <utility>

namespace loglens::parser_internal {
namespace {

bool parse_su_message(std::string_view message, Event& event) {
    static constexpr std::string_view failed_prefix = "FAILED SU (to ";
    static constexpr std::string_view success_prefix = "Successful su for ";

    if (message.starts_with(failed_prefix)) {
        const auto close_target = message.find(") ");
        if (close_target == std::string_view::npos) {
            return false;
        }

        auto remaining = message.substr(close_target + 2);
        const auto location_marker = remaining.find(" on ");
        if (location_marker != std::string_view::npos) {
            remaining = remaining.substr(0, location_marker);
        }

        const auto actor = trim(remaining);
        if (actor.empty()) {
            return false;
        }

        event.username.assign(actor);
        event.event_type = EventType::SuAuthFailure;
        return true;
    }

    if (message.starts_with(success_prefix)) {
        const auto by_position = message.find(" by ");
        if (by_position == std::string_view::npos) {
            return false;
        }

        auto actor = message.substr(by_position + std::string_view{" by "}.size());
        const auto actor_end = actor.find_first_of("( ");
        if (actor_end != std::string_view::npos) {
            actor = actor.substr(0, actor_end);
        }

        actor = trim(actor);
        if (actor.empty()) {
            return false;
        }

        event.username.assign(actor);
        event.event_type = EventType::SessionOpened;
        return true;
    }

    return false;
}

}  // namespace

HandlerResult handle_su_event(const Event& source) {
    Event event = source;
    if (parse_su_message(event.message, event)) {
        return matched_event(std::move(event));
    }

    return classify_unrecognized_event(source);
}

}  // namespace loglens::parser_internal
