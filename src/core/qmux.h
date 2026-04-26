/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_CONNECTION QUIC_CONNECTION;

typedef struct QUIC_QMUX {

    //
    // The parent connection for this QMux.
    //
    QUIC_CONNECTION* Connection;

    //
    // The datapath binding for QMUX.
    //
    CXPLAT_SOCKET* Socket;

    //
    // The local and remote addresses for the connection.
    //
    CXPLAT_ROUTE Route;

    //
    // Event to signal when the TCP connection is established.
    // 
    CXPLAT_EVENT ConnectEvent;

    //
    // The TLS context.
    //
    CXPLAT_TLS* TLS;

    //
    // Send State
    //
    CXPLAT_TLS_PROCESS_STATE TlsState;

    //
    // Result flags from the last Tls process call.
    //
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    CXPLAT_RECV_DATA* TcpReceiveQueue;
    CXPLAT_RECV_DATA** TcpReceiveQueueTail;
    CXPLAT_DISPATCH_LOCK TcpReceiveQueueLock;
    uint32_t TcpReceiveQueueCount;
    uint32_t TcpReceiveQueueByteCount;

    //
    // Sequence numbers for QX_PING frames.
    // The next ping sequence number to send, and the last one received from the peer.
    //
    QUIC_VAR_INT NextPingSequenceNumber;
    QUIC_VAR_INT RecvPingSequenceNumber;

    BOOLEAN RecvPing;

} QUIC_QMUX;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxInitializeTls(
    _Inout_ QUIC_QMUX* QMux,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicQMuxFlushRecv(
    _In_ QUIC_QMUX* QMux
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxProcessTcpDisconnect(
    _In_ QUIC_QMUX* QMux
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxTcpAccept(
    _In_ CXPLAT_SOCKET* ListenerSocket,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpConnect(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpReceive(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpSendComplete(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_ uint32_t ByteCount
    );
