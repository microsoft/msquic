/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Perf Helpers

--*/

#pragma once

#ifdef QUIC_CLOG
#include "PerfHelpers.h.clog.h"
#endif

#include <msquic.h>

extern const QUIC_API_TABLE* MsQuic;

#define QUIC_SKIP_GLOBAL_CONSTRUCTORS

#include <quic_platform.h>
#include <msquic.hpp>

#include <msquichelper.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _KERNEL_MODE
#include <new> // Needed for placement new
#else
#include <new.h>
#endif

#ifdef _KERNEL_MODE
extern uint8_t SelfSignedSecurityHash[20];
#else
extern QUIC_SEC_CONFIG_PARAMS* SelfSignedParams;
#endif
extern bool IsSelfSignedValid;

#define QUIC_TEST_SESSION_CLOSED    1

inline
int
WriteOutput(
    _In_z_ const char* format
    ...
    )
{
#ifndef _KERNEL_MODE
    va_list args;
    va_start(args, format);
    int rval = vprintf(format, args);
    va_end(args);
    return rval;
#else
    UNREFERENCED_PARAMETER(format);
    return 0;
#endif
}

struct MsQuicListener {
    HQUIC Handle{ nullptr };
    QUIC_LISTENER_CALLBACK_HANDLER Handler;
    void* Context;
    MsQuicListener(const MsQuicSession& Session) {
        if (!Session.IsValid()) {
            return;
        }
        if (QUIC_FAILED(
            MsQuic->ListenerOpen(
                Session,
                [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                    MsQuicListener* Listener = (MsQuicListener*)Context;
                    return Listener->Handler(Handle, Listener->Context, Event);
                },
                this,
                &Handle))) {
            Handle = nullptr;
        }
    }
    ~MsQuicListener() noexcept {
        if (Handler != nullptr) {
            MsQuic->ListenerStop(Handle);
        }
        if (Handle) {
            MsQuic->ListenerClose(Handle);
        }
    }

    QUIC_STATUS
    Start(
        _In_ QUIC_ADDR* Address,
        _In_ QUIC_LISTENER_CALLBACK_HANDLER ShadowHandler,
        _In_ void* ShadowContext) {
        Handler = ShadowHandler;
        Context = ShadowContext;
        return MsQuic->ListenerStart(Handle, Address);
    }

    QUIC_STATUS
    ListenerCallback(HQUIC Listener, QUIC_LISTENER_EVENT* Event) {
        return Handler(Listener, Context, Event);
    }

    bool IsValid() const { return Handle != nullptr; }
};

struct MsQuicSecurityConfig {
    QUIC_STATUS Initialize(int argc, char** argv, const MsQuicRegistration& Registration) {
        uint16_t useSelfSigned = 0;
        if (TryGetValue(argc, argv, "selfsign", &useSelfSigned)) {
            if (!IsSelfSignedValid) {
                WriteOutput("Self Signed Not Configured Correctly\n");
                return QUIC_STATUS_INVALID_STATE;
            }
#ifdef _KERNEL_MODE
            CreateSecConfigHelper Helper;
            SecurityConfig =
                Helper.Create(
                    MsQuic,
                    Registration,
                    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
                    &SelfSignedSecurityHash,
                    nullptr);
#else
            SecurityConfig =
                GetSecConfigForSelfSigned(
                    MsQuic,
                    Registration,
                    SelfSignedParams);
#endif
            if (!SecurityConfig) {
                WriteOutput("Failed to create security config for self signed certificate\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else {
            const char* certThumbprint;
            if (!TryGetValue(argc, argv, "thumbprint", &certThumbprint)) {
                WriteOutput("Must specify -thumbprint: for server mode.\n");
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            const char* certStoreName;
            if (!TryGetValue(argc, argv, "cert_store", &certStoreName)) {
                SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, certThumbprint);
                if (SecurityConfig == nullptr) {
                    WriteOutput("Failed to create security configuration for thumbprint:'%s'.\n", certThumbprint);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            } else {
                uint32_t machineCert = 0;
                TryGetValue(argc, argv, "machine_cert", &machineCert);
                QUIC_CERTIFICATE_HASH_STORE_FLAGS flags =
                    machineCert ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;

                SecurityConfig = GetSecConfigForThumbprintAndStore(MsQuic, Registration, flags, certThumbprint, certStoreName);
                if (SecurityConfig == nullptr) {
                    WriteOutput(
                        "Failed to create security configuration for thumbprint:'%s' and store: '%s'.\n",
                        certThumbprint,
                        certStoreName);
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    ~MsQuicSecurityConfig() {
        if (SecurityConfig) {
            MsQuic->SecConfigDelete(SecurityConfig);
        }
    }

    operator QUIC_SEC_CONFIG*() const { return SecurityConfig; }

    QUIC_SEC_CONFIG* SecurityConfig {nullptr};
};

struct CountHelper {
    long RefCount;

    QUIC_EVENT Done;

    CountHelper() :
        RefCount{1}, Done{} {}

    CountHelper(QUIC_EVENT Done) :
        RefCount{1}, Done{Done} { }

    bool
    Wait(
        uint32_t Milliseconds
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return true;
        } else {
            return !QuicEventWaitWithTimeout(Done, Milliseconds);
        }
    }

    void
    WaitForever(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            return;
        } else {
            QuicEventWaitForever(Done);
        }
    }

    void
    AddItem(
        ) {
        InterlockedIncrement(&RefCount);
    }

    void
    CompleteItem(
        ) {
        if (InterlockedDecrement(&RefCount) == 0) {
            QuicEventSet(Done);
        }
    }
};

struct PerfRunner {
    //
    // Virtual destructor so we can destruct the base class
    //
    virtual
    ~PerfRunner() = default;

    //
    // Called to initialize the runner.
    //
    virtual
    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        ) = 0;

    //
    // Start the runner. The StopEvent can be triggered to stop early
    // Passed here rather then Wait so we can synchronize off of it.
    // This event must be kept alive until Wait is called.
    //
    virtual
    QUIC_STATUS
    Start(
        _In_ QUIC_EVENT StopEvent
        ) = 0;

    //
    // Wait for a run to finish, until timeout.
    // If 0 or less, wait forever
    //
    virtual
    QUIC_STATUS
    Wait(
        int Timeout
        ) = 0;
};

//
// Arg Value Parsers
//

inline
_Success_(return != false)
bool
IsValue(
    _In_z_ const char* name,
    _In_z_ const char* toTestAgainst
    )
{
    return _strnicmp(name, toTestAgainst, min(strlen(name), strlen(toTestAgainst))) == 0;
}
