/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer storage interface.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "storage_linux.c.clog"
#endif

QUIC_STATUS
QuicStorageOpen(
    _In_opt_z_ const char * Path,
    _In_ QUIC_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_STORAGE** NewStorage
    )
{
    // TODO
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
QuicStorageClose(
    _In_opt_ QUIC_STORAGE* Storage
    )
{
    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStorageReadValue(
    _In_ QUIC_STORAGE* Storage,
    _In_opt_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength
    )
{
    // TODO
    return QUIC_STATUS_NOT_SUPPORTED;
}
