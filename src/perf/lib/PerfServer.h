/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Server declaration. Defines the functions and
    variables used in the PerfServer class.

--*/

#pragma once

#include "SecNetPerf.h"
#include "Tcp.h"

class PerfServer {
public:
    PerfServer(const QUIC_CREDENTIAL_CONFIG* CredConfig) :
        Engine(TcpAcceptCallback, TcpConnectCallback, TcpReceiveCallback, TcpSendCompleteCallback, TcpDefaultExecutionProfile),
        Server(&Engine, CredConfig, this) {
        CxPlatZeroMemory(&LocalAddr, sizeof(LocalAddr));
        QuicAddrSetFamily(&LocalAddr, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(&LocalAddr, PERF_DEFAULT_PORT);
        InitStatus =
            Configuration.IsValid() ?
                Configuration.LoadCredential(CredConfig) :
                Configuration.GetInitStatus();
    }

    ~PerfServer() {
        if (TeardownBinding) {
            CxPlatSocketDelete(TeardownBinding);
            TeardownBinding = nullptr;
        }
    }

    QUIC_STATUS
    Init(
        _In_ int argc,
        _In_reads_(argc) _Null_terminated_ char* argv[]
        );
    QUIC_STATUS Start(_In_ CXPLAT_EVENT* StopEvent);
    QUIC_STATUS Wait(int Timeout);

    static CXPLAT_DATAPATH_RECEIVE_CALLBACK DatapathReceive;
    static void DatapathUnreachable(_In_ CXPLAT_SOCKET*, _In_ void*, _In_ const QUIC_ADDR*) { }

private:

    struct PerfIoBuffer {
        QUIC_BUFFER* Buffer {nullptr};
        operator QUIC_BUFFER* () noexcept { return Buffer; }
        uint8_t* Raw() noexcept { return Buffer->Buffer; }
        PerfIoBuffer() {
            Buffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + PERF_DEFAULT_IO_SIZE, QUIC_POOL_PERF);
            CXPLAT_FRE_ASSERT(Buffer);
            Buffer->Length = PERF_DEFAULT_IO_SIZE;
            Buffer->Buffer = (uint8_t*)(Buffer + 1);
            for (uint32_t i = sizeof(uint64_t); i < PERF_DEFAULT_IO_SIZE; ++i) {
                Buffer->Buffer[i] = (uint8_t)i;
            }
        }
        ~PerfIoBuffer() noexcept { CXPLAT_FREE(Buffer, QUIC_POOL_PERF); }
    } ResponseBuffer;

    struct TcpConnectionContext {
        PerfServer* Server;
        CxPlatHashTable StreamTable;
        TcpConnectionContext(PerfServer* Server) : Server(Server) { }
        ~TcpConnectionContext();
    };

    CxPlatPoolT<TcpConnectionContext> TcpConnectionContextAllocator;

    struct StreamContext {
        StreamContext(
            PerfServer* Server, bool Unidirectional, bool BufferedIo) :
            Server{Server}, Unidirectional{Unidirectional}, BufferedIo{BufferedIo} {
            if (BufferedIo) {
                IdealSendBuffer = 1; // Hack to get just do 1 send at a time.
            }
        }
        CXPLAT_HASHTABLE_ENTRY Entry; // To TCP StreamTable
        PerfServer* Server;
        const bool Unidirectional;
        const bool BufferedIo;
        bool ResponseSizeSet{false};
        bool SendShutdown{false};
        bool RecvShutdown{false};
        uint64_t IdealSendBuffer{PERF_DEFAULT_SEND_BUFFER_SIZE};
        uint64_t ResponseSize{0};
        uint64_t BytesSent{0};
        uint64_t OutstandingBytes{0};
        QUIC_BUFFER LastBuffer;
    };

    CxPlatPoolT<StreamContext> StreamContextAllocator; // TODO - Make this per-CPU
    CxPlatPoolT<TcpSendData> TcpSendDataAllocator;

    QUIC_STATUS
    ListenerCallback(
        _Inout_ QUIC_LISTENER_EVENT* Event
        );

    QUIC_STATUS
    ConnectionCallback(
        _In_ HQUIC ConnectionHandle,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        );

    QUIC_STATUS
    StreamCallback(
        _In_ StreamContext* Context,
        _In_ HQUIC StreamHandle,
        _Inout_ QUIC_STREAM_EVENT* Event
        );

    void
    SendResponse(
        _In_ StreamContext* Context,
        _In_ void* Handle,
        _In_ bool IsTcp
        );

    CXPLAT_SOCKET* TeardownBinding {nullptr};

    QUIC_STATUS InitStatus;
    MsQuicRegistration Registration {
        "secnetperf-server",
        PerfDefaultExecutionProfile,
        true};
    MsQuicConfiguration Configuration {
        Registration,
        PERF_ALPN,
        MsQuicSettings()
            .SetConnFlowControlWindow(PERF_DEFAULT_CONN_FLOW_CONTROL)
            .SetPeerBidiStreamCount(PERF_DEFAULT_STREAM_COUNT)
            .SetPeerUnidiStreamCount(PERF_DEFAULT_STREAM_COUNT)
            .SetDisconnectTimeoutMs(PERF_DEFAULT_DISCONNECT_TIMEOUT)
            .SetIdleTimeoutMs(PERF_DEFAULT_IDLE_TIMEOUT)
            .SetSendBufferingEnabled(false)
            .SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT)
            .SetCongestionControlAlgorithm(PerfDefaultCongestionControl)
            .SetEcnEnabled(PerfDefaultEcnEnabled)
            .SetEncryptionOffloadAllowed(PerfDefaultQeoAllowed)
            .SetOneWayDelayEnabled(true)};
    MsQuicListener Listener {Registration, CleanUpManual, ListenerCallbackStatic, this};
    QUIC_ADDR LocalAddr;
    CXPLAT_EVENT* StopEvent {nullptr};
    uint8_t PrintStats {FALSE};

    TcpEngine Engine;
    TcpServer Server;

    static
    QUIC_STATUS
    ListenerCallbackStatic(
        _In_ MsQuicListener* /*Listener*/,
        _In_ void* Context,
        _Inout_ QUIC_LISTENER_EVENT* Event
        ) {
        return ((PerfServer*)Context)->ListenerCallback(Event);
    }

    static TcpAcceptCallback TcpAcceptCallback;
    static TcpConnectCallback TcpConnectCallback;
    static TcpReceiveCallback TcpReceiveCallback;
    static TcpSendCompleteCallback TcpSendCompleteCallback;
};
