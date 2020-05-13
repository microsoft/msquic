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

typedef struct QUIC_STORAGE QUIC_STORAGE;

//
// Function pointer type for storage change callbacks.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
(QUIC_STORAGE_CHANGE_CALLBACK)(
    _In_ void* Context
    );

typedef QUIC_STORAGE_CHANGE_CALLBACK *QUIC_STORAGE_CHANGE_CALLBACK_HANDLER;

//
// Opens a storage context, registers for change callbacks and returns a
// handle to it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStorageOpen(
    _In_opt_z_ const char * Path,
    _In_ QUIC_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_STORAGE** NewStorage
    );

//
// Cleans up a handle to a storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStorageClose(
    _In_opt_ QUIC_STORAGE* Storage
    );

//
// Reads a value from the storage context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStorageReadValue(
    _In_ QUIC_STORAGE* Storage,
    _In_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength
    );

#if defined(__cplusplus)
}
#endif
