/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides simple client MsQuic example that leverages custom execution.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "msquic.hpp"
#include <stdio.h>
#include <stdlib.h>

const MsQuicApi* MsQuic;

void PrintUsage()
{
    printf(
        "\n"
        "quicexec is a simple app that can connect to an HTTP/3 server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  quicexec <host or ip>\n"
        );
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    MsQuicApi _MsQuic;
    if (!_MsQuic.IsValid()) { return 1; }
    MsQuic = &_MsQuic;

    QUIC_STATUS Status;
    QUIC_EXECUTION_TABLE MsQuicExec;
    uint32_t MsQuicExecLength = sizeof(MsQuicExec);
    if (QUIC_FAILED(
        Status = MsQuic->GetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_EXECUTION_TABLE,
            &MsQuicExecLength,
            &MsQuicExec))) {
        return 1;
    }

    HANDLE IOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    QUIC_EXECUTION_CONTEXT_CONFIG ExecConfig = { 0, 0, &IOCP };
    QUIC_EXECUTION_CONTEXT* ExecContext = nullptr;
    if (QUIC_FAILED(
        Status = MsQuicExec.ExecutionCreate(
            QUIC_EXECUTION_CONFIG_FLAG_NONE,
            1,
            &ExecConfig,
            &ExecContext))) {
        return 1;
    }

    do {
        MsQuicRegistration Registration("quicexec");
        MsQuicSettings Settings;
        Settings.SetPeerUnidiStreamCount(3); // required for H3
        MsQuicConfiguration Configuration(Registration, "h3", Settings, MsQuicCredentialConfig());
        if (!Configuration.IsValid()) { break; }

        MsQuicConnection Connection(Registration);
        if (QUIC_FAILED(
            Status = Connection.Start(Configuration, argv[1], 443))) {
            break;
        }

        while (true) {
            uint32_t WaitTime = MsQuicExec.Poll(ExecContext);

            OVERLAPPED_ENTRY Cqes[8];
            ULONG CqeCount = 0;
            if (GetQueuedCompletionStatusEx(IOCP, Cqes, ARRAYSIZE(Cqes), &CqeCount, WaitTime, FALSE)) {
                for (ULONG i = 0; i < CqeCount; ++i) {
                    if (MsQuicExec.CheckCqe(Cqes+i)) {
                        MsQuicExec.ProcessCqe(ExecContext, Cqes+i, 1);
                    } else {
                        // We should handle our own completions here.
                    }
                }
            }

            if (Connection.HandshakeComplete) {
                Connection.Shutdown(0);
            }

            // TODO - Stop once the connection is shutdown complete
        }

    } while (false);

    MsQuicExec.ExecutionDelete(1, &ExecContext);
    CloseHandle(IOCP);

    return 0;
}
