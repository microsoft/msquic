/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for QUIC platform persistent storage.
    The QUIC persistent store is a tree of keys, with each key having a set of
    name/value pairs. For each key, all names under that key are unique. Names
    are UTF8 strings that must be less than 65536 bytes long. Values are read as
    binary blobs.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_STORAGE CXPLAT_STORAGE;

//
// Function pointer type for storage change callbacks.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_STORAGE_CHANGE_CALLBACK)
void
(CXPLAT_STORAGE_CHANGE_CALLBACK)(
    _In_ void* Context
    );

typedef CXPLAT_STORAGE_CHANGE_CALLBACK *CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER;

typedef enum CXPLAT_STORAGE_OPEN_FLAGS {
    CXPLAT_STORAGE_OPEN_FLAG_READ =     0x0,
    CXPLAT_STORAGE_OPEN_FLAG_WRITE =    0x1,
    CXPLAT_STORAGE_OPEN_FLAG_DELETE =   0x2,
    CXPLAT_STORAGE_OPEN_FLAG_CREATE =   0x4
} CXPLAT_STORAGE_OPEN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_STORAGE_OPEN_FLAGS);

//
// Opens a storage context, registers for change callbacks and returns a
// handle to it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageOpen(
    _In_opt_z_ const char * Path,
    _In_opt_ CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _In_ CXPLAT_STORAGE_OPEN_FLAGS Flags,
    _Out_ CXPLAT_STORAGE** NewStorage
    );

//
// Cleans up a handle to a storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatStorageClose(
    _In_opt_ _Post_invalid_ CXPLAT_STORAGE* Storage
    );

//
// Reads a value from the storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageReadValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_opt_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength
    );

typedef enum CXPLAT_STORAGE_TYPE {
    CXPLAT_STORAGE_TYPE_BINARY = 3,
    CXPLAT_STORAGE_TYPE_UINT32 = 4,
    CXPLAT_STORAGE_TYPE_UINT64 = 11
    //
    // Non-Windows Registry types begin at 16 or above.
    //
} CXPLAT_STORAGE_TYPE;

//
// Write support is not needed in the product code, and is potentially
// dangerous in product code, so it is gated behind this flag that is only
// enabled in test code.
//
#ifdef CXPLAT_STORAGE_ENABLE_WRITE_SUPPORT

//
// Writes a value to the storage context
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageWriteValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_z_ const char * Name,
    _In_ CXPLAT_STORAGE_TYPE Type,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * Buffer
    );

//
// Deletes a value from the storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageDeleteValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_z_ const char * Name
    );

//
// Clears all settings from a storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageClear(
    _In_ CXPLAT_STORAGE* Storage
    );

#endif // CXPLAT_STORAGE_ENABLE_WRITE_SUPPORT

#if defined(__cplusplus)
}
#endif
