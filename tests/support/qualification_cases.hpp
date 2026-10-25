#pragma once

#include "event.hpp"

#include <string>
#include <vector>

namespace qualification {
struct Case {
    std::string program;
    std::string message;
    loglens::EventType type;
    std::string username;
    std::string address;
    bool attempt;
    bool terminal;
    bool sudo;
};

// Independently authored expectations from the conformance matrix and rule catalog.
inline std::vector<Case> cases() {
    using T = loglens::EventType;
    return {
        {"sshd", "Failed password for user-a from 203.0.113.1 port 50101 ssh2", T::SshFailedPassword, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "Failed password for illegal user user-a from 203.0.113.1 port 50101 ssh2", T::SshInvalidUser, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "Failed none for invalid user user-a from 203.0.113.1 port 50101 ssh2", T::SshInvalidUser, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "Accepted password for user-a from 203.0.113.1 port 50101 ssh2", T::SshAcceptedPassword, "user-a", "203.0.113.1", false, false, false},
        {"sshd", "Accepted publickey for user-a from 203.0.113.1 port 50101 ssh2", T::SshAcceptedPublicKey, "user-a", "203.0.113.1", false, false, false},
        {"sshd", "Accepted keyboard-interactive/pam for user-a from 203.0.113.1 port 50101 ssh2", T::SshAcceptedKeyboardInteractive, "user-a", "203.0.113.1", false, false, false},
        {"sshd", "Failed publickey for invalid user user-a from 203.0.113.1 port 50101 ssh2", T::SshFailedPublicKey, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "Failed keyboard-interactive/pam for user-a from 203.0.113.1 port 50101 ssh2", T::SshFailedKeyboardInteractive, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "maximum authentication attempts exceeded for user-a from 203.0.113.1 port 50101 ssh2", T::SshMaxAuthTries, "user-a", "203.0.113.1", true, true, false},
        {"sshd", "PAM: Authentication failure for user-a from 203.0.113.1", T::PamAuthFailure, "user-a", "203.0.113.1", true, false, false},
        {"sshd", "input_userauth_request: invalid user user-a [preauth]", T::SshInvalidUser, "user-a", "", true, true, false},
        {"sudo", "user-a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true", T::SudoCommand, "user-a", "", false, false, true},
        {"sudo", "user-a : 1 incorrect password attempt ; TTY=pts/0 ; COMMAND=/usr/bin/true", T::SudoAuthFailure, "user-a", "", false, false, false},
        {"sudo", "user-a : user NOT in sudoers ; COMMAND=/usr/bin/true", T::SudoPolicyDenied, "user-a", "", false, false, false},
        {"su", "FAILED SU (to root) user-a on pts/0", T::SuAuthFailure, "user-a", "", false, false, false},
        {"su", "Successful su for root by user-a", T::SessionOpened, "user-a", "", false, false, false},
        {"login", "LOGIN ON pts/0 BY user-a FROM example-host", T::SessionOpened, "user-a", "", false, false, false},
        {"pam_unix(sshd:auth)", "authentication failure; rhost=203.0.113.1 user=user-a", T::PamAuthFailure, "user-a", "203.0.113.1", true, false, false},
        {"pam_unix(sudo:session)", "session opened for user root by user-a(uid=1000)", T::SessionOpened, "user-a", "", false, false, false},
        {"pam_faillock(sshd:auth)", "Authentication failure for user user-a from 203.0.113.1", T::PamAuthFailure, "user-a", "203.0.113.1", true, false, false},
        {"pam_sss(sshd:auth)", "received for user user-a: 7 (Authentication failure)", T::PamAuthFailure, "user-a", "", true, false, false},
    };
}
} // namespace qualification
