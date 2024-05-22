/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_DATAGRAM {

    //
    // Datagram send queue.
    //
    QUIC_SEND_REQUEST* SendQueue;
    QUIC_SEND_REQUEST** PrioritySendQueueTail;
    QUIC_SEND_REQUEST** SendQueueTail;

    //
    // API calls to DatagramSend queue the send request here and then queue the
    // send operation. That operation moves the send request onto the
    // send queue.
    //
    QUIC_SEND_REQUEST* ApiQueue;
    CXPLAT_DISPATCH_LOCK ApiQueueLock;

    //
    // The maximum datagram frame we allow the peer to send.
    //
    // TODO - Allow this to be configurable.

    //
    // The maximum length of data that we can fit in an outgoing datagram frame.
    //
    uint16_t MaxSendLength;

    //
    // Indicates that datagrams are allowed by the peer and can be queued up to
    // send.
    //
    BOOLEAN SendEnabled : 1;

} QUIC_DATAGRAM;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramInitialize(
    _In_ QUIC_DATAGRAM* Datagram
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramUninitialize(
    _In_ QUIC_DATAGRAM* Datagram
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramSendShutdown(
    _In_ QUIC_DATAGRAM* Datagram
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramOnSendStateChanged(
    _In_ QUIC_DATAGRAM* Datagram
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDatagramQueueSend(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ QUIC_SEND_REQUEST* SendRequest
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramSendFlush(
    _In_ QUIC_DATAGRAM* Datagram
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramWriteFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDatagramIndicateSendStateChange(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ void** ClientContext,
    _In_ QUIC_DATAGRAM_SEND_STATE State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicDatagramProcessFrame(
    _In_ QUIC_DATAGRAM* Datagram,
    _In_ const QUIC_RX_PACKET* const Packet,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset
    );
