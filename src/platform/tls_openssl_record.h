/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef struct QUIC_TLS_RECORD_STATE {
    const uint8_t* InputBuffer;
    size_t InputLength;
    size_t InputOffset;
    size_t OutstandingLength;
} QUIC_TLS_RECORD_STATE;

#if defined(__cplusplus)
extern "C" {
#endif

int
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
