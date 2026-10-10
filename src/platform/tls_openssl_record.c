/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the OpenSSL TLS record callbacks.

--*/

#include "platform_internal.h"
#include "tls_openssl_record.h"

//
// @brief Finds the next complete TLS message in the current receive state.
//
// The returned pointer aliases MsQuic's receive buffer and remains valid until
// OpenSSL calls QuicTlsReleaseRecord. Only one message may be outstanding at a time.
//
// @param[in,out] State     Current receive state.
// @param[out] Buffer       Pointer to the buffer containing the record data.
//                          If no data is available, set to NULL.
// @param[out] BytesRead    Length of the record returned in @p Buffer.
//                          If no data is available, set to 0.
void
QuicTlsReceiveRecordInner(
    _Inout_ QUIC_TLS_RECORD_STATE* State,
    _Outptr_result_buffer_maybenull_(*BytesRead)
        const unsigned char** Buf,
    _Out_ size_t* BytesRead
    )
{
    CXPLAT_DBG_ASSERT(State != NULL);
    CXPLAT_DBG_ASSERT(State->OutstandingLength == 0);

    *Buf = NULL;
    *BytesRead = 0;

    size_t Remaining = State->InputLength - State->InputOffset;
    if (Remaining < 4) {
        return;
    }

    const uint8_t* Message = State->InputBuffer + State->InputOffset;
    size_t MessageLength =
        4 + ((size_t)Message[1] << 16) +
            ((size_t)Message[2] << 8) +
            Message[3];
    if (MessageLength > Remaining) {
        return;
    }

    State->OutstandingLength = MessageLength;
    *Buf = Message;
    *BytesRead = MessageLength;
}

//
// @brief Releases TLS data borrowed from MsQuic.
//
// This function advances the released prefix of the current input window
// and tracks any portion that remains outstanding.
// The receive buffer itself remains owned by MsQuic and is drained after
// CxPlatTlsProcessData returns.
//
// @param[in,out] State     Current receive state.
// @param[in] BytesRead     The number of bytes OpenSSL no longer needs.
//
// @return 1 if the bytes were released; 0 if the length exceeds the
//         outstanding data.
//
int
QuicTlsReleaseRecordInner(
    _Inout_ QUIC_TLS_RECORD_STATE* State,
    _In_ size_t BytesRead
    )
{
    CXPLAT_DBG_ASSERT(State != NULL);

    if (BytesRead > State->OutstandingLength) {
        return 0;
    }

    State->InputOffset += BytesRead;
    State->OutstandingLength -= BytesRead;
    return 1;
}
