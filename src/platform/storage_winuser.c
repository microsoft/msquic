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
CxPlatStorageRegKeyChangeCallback(
    _Inout_     PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID                 Context,
    _Inout_     PTP_WAIT              Wait,
    _In_        TP_WAIT_RESULT        WaitResult
    );

//
// The storage context returned that abstracts a registry key handle.
//
typedef struct CXPLAT_STORAGE {

    HKEY RegKey;
    HANDLE NotifyEvent;
    PTP_WAIT ThreadPoolWait;
    CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback;
    void* CallbackContext;

} CXPLAT_STORAGE;

#ifdef QUIC_RESTRICTED_BUILD
WINADVAPI
LSTATUS
APIENTRY
RegNotifyChangeKeyValue(
    _In_ HKEY hKey,
    _In_ BOOL bWatchSubtree,
    _In_ DWORD dwNotifyFilter,
    _In_opt_ HANDLE hEvent,
    _In_ BOOL fAsynchronous
    );
#endif

#ifdef QUIC_UWP_BUILD
WINADVAPI
LSTATUS
APIENTRY
RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
    );

WINADVAPI
LSTATUS
APIENTRY
RegCloseKey(
    _In_ HKEY hKey
    );

WINADVAPI
LSTATUS
APIENTRY
RegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
    );
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageOpen(
    _In_opt_z_ const char * Path,
    _In_ CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_STORAGE** NewStorage
    )
{
    QUIC_STATUS Status;
    CXPLAT_STORAGE* Storage = NULL;

    char FullKeyName[256] = CXPLAT_BASE_REG_PATH;

    if (Path != NULL) {
        size_t PathLength = strlen(Path);
        if (PathLength + sizeof(CXPLAT_BASE_REG_PATH) > sizeof(FullKeyName)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        memcpy(
            FullKeyName + sizeof(CXPLAT_BASE_REG_PATH) - 1,
            Path,
            PathLength + 1);
    }

    Storage = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_STORAGE), QUIC_POOL_STORAGE);
    if (Storage == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(Storage, sizeof(CXPLAT_STORAGE));
    Storage->Callback = Callback;
    Storage->CallbackContext = CallbackContext;

    Storage->NotifyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (Storage->NotifyEvent == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Storage->ThreadPoolWait =
        CreateThreadpoolWait(
            CxPlatStorageRegKeyChangeCallback,
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

#pragma prefast(suppress:6001, "SAL can't track FullKeyName")
    Status =
        HRESULT_FROM_WIN32(
        RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            FullKeyName,
            0,
            KEY_READ | KEY_NOTIFY,
            &Storage->RegKey));
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RegOpenKeyExA failed");
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
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RegNotifyChangeKeyValue failed");
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
            CxPlatCloseHandle(Storage->NotifyEvent);
        }
        CXPLAT_FREE(Storage, QUIC_POOL_STORAGE);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatStorageClose(
    _In_opt_ CXPLAT_STORAGE* Storage
    )
{
    if (Storage != NULL) {
        WaitForThreadpoolWaitCallbacks(Storage->ThreadPoolWait, TRUE);
        RegCloseKey(Storage->RegKey);
        CloseThreadpoolWait(Storage->ThreadPoolWait);
        CxPlatCloseHandle(Storage->NotifyEvent);
        CXPLAT_FREE(Storage, QUIC_POOL_STORAGE);
    }
}

void
NTAPI
CxPlatStorageRegKeyChangeCallback(
    _Inout_     PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID                 Context,
    _Inout_     PTP_WAIT              Wait,
    _In_        TP_WAIT_RESULT        WaitResult
    )
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(WaitResult);
    CXPLAT_DBG_ASSERT(Context);

    CXPLAT_STORAGE* Storage = (CXPLAT_STORAGE*)Context;
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
CxPlatStorageReadValue(
    _In_ CXPLAT_STORAGE* Storage,
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
