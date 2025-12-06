/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer storage interface.

Environment:

    Linux and Darwin (Posix)

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "storage_posix.c.clog.h"
#endif

QUIC_STATUS
CxPlatStorageOpen(
    _In_opt_z_ const char * Path,
    _In_opt_ CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _In_ CXPLAT_STORAGE_OPEN_FLAGS Flags,
    _Out_ CXPLAT_STORAGE** NewStorage
    )
{
    UNREFERENCED_PARAMETER(Path);
    UNREFERENCED_PARAMETER(Callback);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(NewStorage);
    // TODO
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatStorageClose(
    _In_opt_ _Post_invalid_ CXPLAT_STORAGE* Storage
    )
{
    UNREFERENCED_PARAMETER(Storage);
    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageReadValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_opt_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength
    )
{
    UNREFERENCED_PARAMETER(Storage);
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    // TODO
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageWriteValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_z_ const char * Name,
    _In_ CXPLAT_STORAGE_TYPE Type,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * Buffer
    )
{
    UNREFERENCED_PARAMETER(Storage);
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageDeleteValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_z_ const char * Name
    )
{
    UNREFERENCED_PARAMETER(Storage);
    UNREFERENCED_PARAMETER(Name);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageClear(
    _In_ CXPLAT_STORAGE* Storage
    )
{
    UNREFERENCED_PARAMETER(Storage);
    return QUIC_STATUS_NOT_SUPPORTED;
}
