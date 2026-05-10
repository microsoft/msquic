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
    // Buffer for decrypted data.
    //
    uint8_t* RecvBuffer;
    uint32_t RecvBufferAllocLength;
    uint32_t RecvBufferLength;

    //
    // Sequence numbers for QX_PING frames.
    // The next ping sequence number to send, and the last one received from the peer.
    //
    QUIC_VAR_INT NextPingSequenceNumber;
    QUIC_VAR_INT RecvPingSequenceNumber;

    BOOLEAN RecvPing;

    BOOLEAN PermitEarlyData;
    BOOLEAN ReadEarlyData;

    //
    // Buffer for early data.
    //
    uint8_t* EarlyDataBuffer;
    uint32_t EarlyDataBufferAllocLength;
    uint32_t EarlyDataBufferLength;

    //
    // Outstanding packets.
    //
    QUIC_SENT_PACKET_METADATA* SentEarlyDataPackets;
    QUIC_SENT_PACKET_METADATA** SentEarlyDataPacketsTail;

    //
    // Indicates Resumption ticket validation is under validation asynchronously
    //
    BOOLEAN TicketValidationPending : 1;
    BOOLEAN TicketValidationRejecting : 1;
    uint32_t PendingValidationBufferLength;

    //
    // Resumption ticket to send to server.
    //
    uint8_t* ResumptionTicket;
    uint32_t ResumptionTicketLength;

} QUIC_QMUX;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_QMUX** NewQMux
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxUninitialize(
    _In_ QUIC_QMUX* QMux
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxInitializeTls(
    _Inout_ QUIC_QMUX* QMux,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxProcessHandshake(
    _In_ QUIC_QMUX* QMux,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicQMuxFlushRecv(
    _In_ QUIC_QMUX* QMux
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxOnPacketAcknowledged(
    _In_ QUIC_QMUX* QMux,
    _In_ QUIC_SENT_PACKET_METADATA* Packet
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
