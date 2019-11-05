/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Miscellaneous helpers.

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "utils.tmh"
#endif

#if QUIC_LOG_BUFFERS

#define QUIC_LOG_LINE_LENGTH 16

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLogBuffer(
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _In_ uint32_t BufferLength
    )
{
    uint32_t Index = 0;
    while (Index < BufferLength)
    {
        uint16_t Length = QUIC_LOG_LINE_LENGTH;
        if (Index + Length > BufferLength) {
            Length = (uint16_t)(BufferLength - Index);
        }
        LogVerbose("%!HEXBUF!", LOG_HEXBUF(Buffer + Index, Length));
        Index += QUIC_LOG_LINE_LENGTH;
    }
}

#endif
