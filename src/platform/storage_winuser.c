/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Windows User-mode implementation for the QUIC persistent storage. Backed by
    the normal registry APIs.

Environment:

    Windows User Mode

--*/


#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "storage_winuser.c.clog.h"
#endif

void
NTAPI
QuicStorageRegKeyChangeCallback(
    _Inout_     PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID                 Context,
    _Inout_     PTP_WAIT              Wait,
    _In_        TP_WAIT_RESULT        WaitResult
    );

//
// The storage context returned that abstracts a registry key handle.
//
typedef struct QUIC_STORAGE {

    HKEY RegKey;
    HANDLE NotifyEvent;
    PTP_WAIT ThreadPoolWait;
    QUIC_STORAGE_CHANGE_CALLBACK_HANDLER Callback;
    void* CallbackContext;

} QUIC_STORAGE;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStorageOpen(
    _In_opt_z_ const char * Path,
    _In_ QUIC_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_STORAGE** NewStorage
    )
{
    QUIC_STATUS Status;
    QUIC_STORAGE* Storage = NULL;

    char FullKeyName[256] = QUIC_BASE_REG_PATH;

    if (Path != NULL) {
        size_t PathLength = strlen(Path);
        if (PathLength + sizeof(QUIC_BASE_REG_PATH) > sizeof(FullKeyName)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        memcpy(
            FullKeyName + sizeof(QUIC_BASE_REG_PATH) - 1,
            Path,
            PathLength + 1);
    }

    Storage = QUIC_ALLOC_PAGED(sizeof(QUIC_STORAGE));
    if (Storage == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Storage, sizeof(QUIC_STORAGE));
    Storage->Callback = Callback;
    Storage->CallbackContext = CallbackContext;

    Storage->NotifyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (Storage->NotifyEvent == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Storage->ThreadPoolWait =
        CreateThreadpoolWait(
            QuicStorageRegKeyChangeCallback,
            Storage,
            NULL);
    if (Storage->ThreadPoolWait == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicTraceLogVerbose(
        StorageOpenKey,
        "[ reg] Opening %s",
        FullKeyName);

    Status =
        HRESULT_FROM_WIN32(
        RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            FullKeyName,
            0,
            KEY_READ | KEY_NOTIFY,
            &Storage->RegKey));
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    Status =
        HRESULT_FROM_WIN32(
        RegNotifyChangeKeyValue(
            Storage->RegKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            Storage->NotifyEvent,
            TRUE));
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    SetThreadpoolWait(Storage->ThreadPoolWait, Storage->NotifyEvent, NULL);

    *NewStorage = Storage;
    Storage = NULL;

Exit:

    if (Storage != NULL) {
        if (Storage->RegKey != NULL) {
            RegCloseKey(Storage->RegKey);
        }
        if (Storage->ThreadPoolWait) {
            CloseThreadpoolWait(Storage->ThreadPoolWait);
        }
        if (Storage->NotifyEvent != NULL) {
            CloseHandle(Storage->NotifyEvent);
        }
        QUIC_FREE(Storage);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStorageClose(
    _In_opt_ QUIC_STORAGE* Storage
    )
{
    if (Storage != NULL) {
        WaitForThreadpoolWaitCallbacks(Storage->ThreadPoolWait, TRUE);
        RegCloseKey(Storage->RegKey);
        CloseThreadpoolWait(Storage->ThreadPoolWait);
        CloseHandle(Storage->NotifyEvent);
        QUIC_FREE(Storage);
    }
}

void
NTAPI
QuicStorageRegKeyChangeCallback(
    _Inout_     PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID                 Context,
    _Inout_     PTP_WAIT              Wait,
    _In_        TP_WAIT_RESULT        WaitResult
    )
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(WaitResult);
    QUIC_DBG_ASSERT(Context);

    QUIC_STORAGE* Storage = (QUIC_STORAGE*)Context;
    Storage->Callback(Storage->CallbackContext);

    if (NO_ERROR ==
        RegNotifyChangeKeyValue(
            Storage->RegKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            Storage->NotifyEvent,
            TRUE)) {
        SetThreadpoolWait(Storage->ThreadPoolWait, Storage->NotifyEvent, NULL);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStorageReadValue(
    _In_ QUIC_STORAGE* Storage,
    _In_opt_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        UINT8 * Buffer,
    _Inout_ uint32_t * BufferLength
    )
{
    DWORD Type;
    return
        HRESULT_FROM_WIN32(
            RegQueryValueExA(
                Storage->RegKey,
                Name,
                NULL,
                &Type,
                Buffer,
                (PDWORD)BufferLength));
}
