/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Generic utility objects used in tests.
    For MsQuic specific helper, see TestHelpers.h

--*/

#pragma once

#ifdef QUIC_CLOG
#include "TestUtility.h.clog.h"
#endif

#include "msquic.hpp"

//
// Call Condition every RetryIntervalMs until TimeoutMs has elapsed.
// Returns QUIC_STATUS_CONNECTION_TIMEOUT if it runs until TimeoutMs
// has elapsed.
// The Condition lambda takes no parameters, and returns a QUIC_STATUS.
// If Condition returns QUIC_STATUS_CONTINUE, TryUntil will keep trying.
// Any other QUIC_STATUS, TryUntil will stop and return that value.
//
template<class Predicate>
QUIC_STATUS
TryUntil(
    uint32_t RetryIntervalMs,
    uint32_t TimeoutMs,
    Predicate Condition)
{
    const uint32_t Tries = TimeoutMs / RetryIntervalMs + 1;
    for (uint32_t i = 0; i < Tries; i++) {
        QUIC_STATUS Status = Condition();
        if (Status == QUIC_STATUS_CONTINUE) {
            CxPlatSleep(RetryIntervalMs);
        } else {
            return Status;
        }
    }
    return QUIC_STATUS_CONNECTION_TIMEOUT;
}


//
// Simple RAII lock guard for CxPlatLock.
// Similar to std::lock_guard.
//
class LockGuard {
public:
    explicit LockGuard(CxPlatLock& lock) noexcept : m_lock(lock) {
        m_lock.Acquire();
    }
    ~LockGuard() noexcept{
        m_lock.Release();
    }

    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;

private:
    CxPlatLock& m_lock;
};
