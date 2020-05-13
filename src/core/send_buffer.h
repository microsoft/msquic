/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_SEND_BUFFER {

    //
    // Sum of bytes over all send requests (both buffered
    // and unbuffered requests). This is a useful diagnostic
    // counter for cases when throughput is starved by an
    // app that is sending too slowly.
    //
    uint64_t PostedBytes;

    //
    // Sum of bytes in buffered requests. This is tracked so that
    // IdealBytes can be used as a soft limit on buffering.
    //
    uint64_t BufferedBytes;

    //
    // The number of bytes that need to be available in the send
    // buffer to avoid limiting throughput.
    //
    uint64_t IdealBytes;

} QUIC_SEND_BUFFER;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferInitialize(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferUninitialize(
    _In_ QUIC_SEND_BUFFER* SendBuffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
uint8_t*
QuicSendBufferAlloc(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer,
    _In_ uint32_t Size
    );

//
// Caller must pass the same size that was passed to QuicSendBufferAlloc.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendBufferFree(
    _Inout_ QUIC_SEND_BUFFER* SendBuffer,
    _In_ uint8_t* Buf,
    _In_ uint32_t Size
    );

//
// Buffers pending send requests until the send buffer is full.
// Should be called when the send buffer is adjusted or bytes are ACKed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferFill(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Indicates an ISB update to the stream.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferStreamAdjust(
    _In_ QUIC_STREAM* Stream
    );

//
// Updates IdealBytes upon change of BytesInFlightMax.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendBufferConnectionAdjust(
    _In_ QUIC_CONNECTION* Connection
    );
