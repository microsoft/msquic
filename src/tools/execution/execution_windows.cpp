/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides simple client MsQuic example that leverages custom execution.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "quic_platform.h"
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

struct WindowsIOCP {
    HANDLE IOCP;
    operator const HANDLE () const noexcept { return IOCP; }
    WindowsIOCP() : IOCP(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1)) { }
    ~WindowsIOCP() { CloseHandle(IOCP); }
    bool IsValid() const noexcept { return IOCP != nullptr; }
    bool Enqueue(
        _In_ LPOVERLAPPED lpOverlapped,
        _In_ DWORD dwNumberOfBytesTransferred = 0,
        _In_ ULONG_PTR dwCompletionKey = 0
        ) noexcept {
        return PostQueuedCompletionStatus(IOCP, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped);
    }
    bool Dequeue(
        _Out_writes_to_(ulCount,*ulNumEntriesRemoved) LPOVERLAPPED_ENTRY lpCompletionPortEntries,
        _In_ ULONG ulCount,
        _Out_ PULONG ulNumEntriesRemoved,
        _In_ DWORD dwMilliseconds
        ) noexcept {
        return GetQueuedCompletionStatusEx(IOCP, lpCompletionPortEntries, ulCount, ulNumEntriesRemoved, dwMilliseconds, FALSE);
    }
};

char* Host = nullptr;
WindowsIOCP* IOCP;
const MsQuicApi* MsQuic;
MsQuicRegistration* Registration;
MsQuicConnection* Connection;
bool AllDone = false;

void QueueCleanupJob() {
    auto Sqe = new(std::nothrow) QUIC_SQE;
    ZeroMemory(&Sqe->Overlapped, sizeof(Sqe->Overlapped));
    Sqe->Completion = [](QUIC_CQE* Cqe) {
        printf("Cleaning up...\n");
        AllDone = true;
        delete CONTAINING_RECORD(Cqe->lpOverlapped, QUIC_SQE, Overlapped);
    };
    IOCP->Enqueue(&Sqe->Overlapped);
}

void QueueConnectedJob() {
    auto Sqe = new(std::nothrow) QUIC_SQE;
    ZeroMemory(&Sqe->Overlapped, sizeof(Sqe->Overlapped));
    Sqe->Completion = [](QUIC_CQE* Cqe) {
        QuicAddr Addr;
        Connection->GetRemoteAddr(Addr);
        QUIC_ADDR_STR AddrStr;
        QuicAddrToString(&Addr.SockAddr, &AddrStr);
        printf("Connected to %s.\n", AddrStr.Address);
        delete CONTAINING_RECORD(Cqe->lpOverlapped, QUIC_SQE, Overlapped);
    };
    IOCP->Enqueue(&Sqe->Overlapped);
}

QUIC_STATUS QUIC_API ConnectionCallback(_In_ struct MsQuicConnection* Conn, _In_opt_ void*, _Inout_ QUIC_CONNECTION_EVENT* Event) {
    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        QueueConnectedJob();
        Conn->Shutdown(0);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
        QueueCleanupJob();
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    }
    return QUIC_STATUS_SUCCESS;
}

void ConnectJob(QUIC_CQE* Cqe) {
    bool Success = false;

    printf("Connecting...\n");

    do {
        MsQuicSettings Settings;
        Settings.SetPeerUnidiStreamCount(3); // required for H3
        MsQuicConfiguration Configuration(*Registration, "h3", Settings, MsQuicCredentialConfig());
        if (!Configuration.IsValid()) { break; }

        Connection = new(std::nothrow) MsQuicConnection(*Registration, CleanUpAutoDelete, ConnectionCallback);
        if (QUIC_FAILED(Connection->Start(Configuration, Host, 443))) {
            delete Connection;
            break;
        }

        Success = true;
    } while (false);

    if (!Success) {
        QueueCleanupJob();
    }

    delete CONTAINING_RECORD(Cqe->lpOverlapped, QUIC_SQE, Overlapped);
}

void QueueConnectJob() {
    auto Sqe = new(std::nothrow) QUIC_SQE;
    ZeroMemory(&Sqe->Overlapped, sizeof(Sqe->Overlapped));
    Sqe->Completion = ConnectJob;
    IOCP->Enqueue(&Sqe->Overlapped);
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    if (argc < 2) { return 1; }
    Host = argv[1];

    WindowsIOCP _IOCP; if (!_IOCP.IsValid()) { return 1; }
    IOCP = &_IOCP;

    MsQuicApi _MsQuic; if (!_MsQuic.IsValid()) { return 1; }
    MsQuic = &_MsQuic;

    MsQuicExecution Execution(&_IOCP.IOCP); if (!Execution.IsValid()) { return 1; }

    MsQuicRegistration _Registration("quicexec"); if (!_Registration.IsValid()) { return 1; }
    Registration = &_Registration;

    QueueConnectJob();

    while (!AllDone) {
        uint32_t WaitTime = MsQuic->ExecutionPoll(Execution[0]);

        ULONG OverlappedCount = 0;
        OVERLAPPED_ENTRY Overlapped[8];
        if (IOCP->Dequeue(Overlapped, ARRAYSIZE(Overlapped), &OverlappedCount, WaitTime)) {
            for (ULONG i = 0; i < OverlappedCount; ++i) {
                QUIC_SQE* Sqe = CONTAINING_RECORD(Overlapped[i].lpOverlapped, QUIC_SQE, Overlapped);
                Sqe->Completion(&Overlapped[i]);
            }
        }
    }

    printf("Done.\n");

    return 0;
}
