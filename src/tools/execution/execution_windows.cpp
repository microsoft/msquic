/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides simple client MsQuic example that leverages custom execution.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "msquic.hpp"
#include <stdio.h>

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

HANDLE IOCP;

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

    IOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (IOCP == nullptr) {
        return 1;
    }
    
    QUIC_STATUS Status;
    QUIC_EXECUTION_CONTEXT* ExecContext = nullptr;
    QUIC_EXECUTION_CONTEXT_CONFIG ExecConfig = { 0, &IOCP };
    if (QUIC_FAILED(Status = MsQuic->ExecutionCreate(QUIC_EXECUTION_CONFIG_FLAG_NONE, 0, 1, &ExecConfig, &ExecContext))) {
        return 1;
    }

    do {
        bool AllDone = false;
        MsQuicRegistration Registration("quicexec");
        MsQuicSettings Settings;
        Settings.SetPeerUnidiStreamCount(3); // required for H3
        MsQuicConfiguration Configuration(Registration, "h3", Settings, MsQuicCredentialConfig());
        if (!Configuration.IsValid()) { break; }

        struct ConnectionCallback {
            static QUIC_STATUS MsQuicConnectionCallback(_In_ struct MsQuicConnection* Connection, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
                if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
                    auto Sqe = new(std::nothrow) QUIC_SQE;
                    ZeroMemory(&Sqe->Overlapped, sizeof(Sqe->Overlapped));
                    Sqe->Completion = [](QUIC_CQE* Cqe) {
                        printf("Connected.\n");
                        delete CONTAINING_RECORD(Cqe->lpOverlapped, QUIC_SQE, Overlapped);
                    };
                    PostQueuedCompletionStatus(IOCP, 0, 0, &Sqe->Overlapped);
                    Connection->Shutdown(0);
                } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
                    *((bool*)Context) = true;
                }
            }
        };

        MsQuicConnection Connection(Registration, CleanUpManual, ConnectionCallback::MsQuicConnectionCallback, &AllDone);
        if (QUIC_FAILED(
            Status = Connection.Start(Configuration, argv[1], 443))) {
            break;
        }

        while (!AllDone) {
            uint32_t WaitTime = MsQuic->ExecutionPoll(ExecContext);

            ULONG OverlappedCount = 0;
            OVERLAPPED_ENTRY Overlapped[8];
            if (GetQueuedCompletionStatusEx(IOCP, Overlapped, ARRAYSIZE(Overlapped), &OverlappedCount, WaitTime, FALSE)) {
                for (ULONG i = 0; i < OverlappedCount; ++i) {
                    QUIC_SQE* Sqe = CONTAINING_RECORD(Overlapped[i].lpOverlapped, QUIC_SQE, Overlapped);
                    Sqe->Completion(&Overlapped[i]);
                }
            }
        }

    } while (false);

    MsQuic->ExecutionDelete(1, &ExecContext);
    CloseHandle(IOCP);

    return 0;
}
