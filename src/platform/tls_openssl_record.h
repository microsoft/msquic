/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

//
// Tracks records borrowed by OpenSSL from a caller-owned CRYPTO receive buffer.
// The input window is valid only while processing the current buffer. OpenSSL
// normally releases the complete borrowed record before that processing call
// returns, advancing InputOffset and reducing OutstandingLength to zero.
//
// During error handling, OpenSSL may release only a prefix and retain the
// remainder until SSL_free. OutstandingLength deliberately survives the
// processing call so that deferred release can be tracked. The receive-buffer
// owner must not drain or move the input while this value is nonzero.
//
typedef struct QUIC_TLS_RECORD_STATE {
    //
    // Input window supplied for the current processing call.
    //
    const uint8_t* InputBuffer;
    size_t InputLength;

    //
    // Prefix of InputBuffer that OpenSSL has released.
    //
    size_t InputOffset;

    //
    // Bytes in the current record that OpenSSL has not yet released.
    //
    size_t OutstandingLength;
} QUIC_TLS_RECORD_STATE;

void
QuicTlsReceiveRecordInner(
    _Inout_ QUIC_TLS_RECORD_STATE* State,
    _Outptr_result_buffer_maybenull_(*BytesRead)
        const unsigned char** Buffer,
    _Out_ size_t* BytesRead
    );

int
QuicTlsReleaseRecordInner(
    _Inout_ QUIC_TLS_RECORD_STATE* State,
    _In_ size_t BytesRead
    );

#if defined(__cplusplus)
}
#endif
