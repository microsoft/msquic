/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Windows Kenel-mode implementation for the QUIC persistent storage. Backed by
    the normal registry APIs.

Environment:

    Windows Kernel Mode

--*/


#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "storage_winkernel.c.clog.h"
#endif

//
// Copied from wdm.h
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

//
// Copied from wdm.h
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(Length == 0, _Post_satisfies_(return < 0))
_When_(Length > 0, _Post_satisfies_(return <= 0))
_Success_(return == STATUS_SUCCESS)
_On_failure_(_When_(return == STATUS_BUFFER_OVERFLOW || return == STATUS_BUFFER_TOO_SMALL, _Post_satisfies_(*ResultLength > Length)))
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
    );

//
// Copied from zwapi_x.h
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwNotifyChangeKey(
    _In_ HANDLE KeyHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG CompletionFilter,
    _In_ BOOLEAN WatchTree,
    _Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ BOOLEAN Asynchronous
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_functionClass(WORKER_THREAD_ROUTINE)
void
CxPlatStorageRegKeyChangeCallback(
    _In_ void* Context
    );

//
// The storage context returned that abstracts a registry key handle.
//
typedef struct CXPLAT_STORAGE {

    HKEY RegKey;
    CXPLAT_LOCK Lock;
    CXPLAT_EVENT* CleanupEvent;
    WORK_QUEUE_ITEM WorkItem;
    IO_STATUS_BLOCK IoStatusBlock;
    CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback;
    void* CallbackContext;

} CXPLAT_STORAGE;

//
// Converts a UTF-8 string to a UNICODE_STRING object. The variable must be
// freed with CXPLAT_FREE when done with it.
//
QUIC_STATUS
CxPlatConvertUtf8ToUnicode(
    _In_z_ const char * Utf8String,
    _Out_ PUNICODE_STRING * NewUnicodeString
    )
{
    size_t Utf8Length = strlen(Utf8String);
    if (Utf8Length > MAXUINT16) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    ULONG UnicodeLength; // In Bytes

    QUIC_STATUS Status =
        RtlUTF8ToUnicodeN(
            NULL,
            0,
            &UnicodeLength,
            Utf8String,
            (ULONG)Utf8Length);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    if (UnicodeLength > MAXUINT16) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    PUNICODE_STRING UnicodeString =
        CXPLAT_ALLOC_PAGED(sizeof(UNICODE_STRING) + UnicodeLength, QUIC_POOL_PLATFORM_TMP_ALLOC);

    if (UnicodeString == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "UnicodeString from UTF8",
            sizeof(UNICODE_STRING) + UnicodeLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    UnicodeString->Buffer = (PWCH)(UnicodeString + 1);
    UnicodeString->MaximumLength = (USHORT)UnicodeLength;
    UnicodeString->Length = (USHORT)UnicodeLength;

    Status =
        RtlUTF8ToUnicodeN(
            UnicodeString->Buffer,
            UnicodeString->MaximumLength,
            &UnicodeLength,
            Utf8String,
            (ULONG)Utf8Length);
    if (QUIC_FAILED(Status)) {
        CXPLAT_FREE(UnicodeString, QUIC_POOL_PLATFORM_TMP_ALLOC);
        return Status;
    }

    *NewUnicodeString = UnicodeString;

    return Status;
}

DECLARE_CONST_UNICODE_STRING(BaseKeyPath, CXPLAT_BASE_REG_PATH);

static
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatStorageCreateAppKey(
    _In_z_ const char* Utf8String,
    _Out_ PUNICODE_STRING * NewUnicodeString
    )
{
    size_t Utf8Length = strlen(Utf8String);
    if (Utf8Length > MAXUINT16) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    ULONG UnicodeLength; // In Bytes

    QUIC_STATUS Status =
        RtlUTF8ToUnicodeN(
            NULL,
            0,
            &UnicodeLength,
            Utf8String,
            (ULONG)Utf8Length);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUTF8ToUnicodeN failed");
        return Status;
    }

    UnicodeLength += BaseKeyPath.Length;

    if (UnicodeLength > MAXUINT16) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    PUNICODE_STRING UnicodeString =
        CXPLAT_ALLOC_PAGED(sizeof(UNICODE_STRING) + UnicodeLength, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (UnicodeString == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "UnicodeString for app storage key",
            sizeof(UNICODE_STRING) + UnicodeLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    UnicodeString->Buffer = (PWCH)(UnicodeString + 1);
    UnicodeString->MaximumLength = (USHORT)UnicodeLength;
    UnicodeString->Length = 0;

    RtlCopyUnicodeString(
        UnicodeString,
        &BaseKeyPath);

    Status =
        RtlUTF8ToUnicodeN(
            (PWSTR)((char*)UnicodeString->Buffer + UnicodeString->Length),
            UnicodeString->MaximumLength - UnicodeString->Length,
            &UnicodeLength,
            Utf8String,
            (ULONG)Utf8Length);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUTF8ToUnicodeN failed");
        CXPLAT_FREE(UnicodeString, QUIC_POOL_PLATFORM_TMP_ALLOC);
        return Status;
    }

    UnicodeString->Length += (USHORT)UnicodeLength;
    *NewUnicodeString = UnicodeString;

    return Status;
}

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
    OBJECT_ATTRIBUTES Attributes;
    PUNICODE_STRING PathUnicode = NULL;
    CXPLAT_STORAGE* Storage = NULL;

    if (Path != NULL) {
        Status = CxPlatStorageCreateAppKey(Path, &PathUnicode);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "CxPlatStorageCreateAppKey failed");
            goto Exit;
        }

        InitializeObjectAttributes(
            &Attributes,
            PathUnicode,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);
    } else {
        InitializeObjectAttributes(
            &Attributes,
            (PUNICODE_STRING)&BaseKeyPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);
    }

    Storage = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_STORAGE), QUIC_POOL_STORAGE);
    if (Storage == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_STORAGE",
            sizeof(CXPLAT_STORAGE));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(Storage, sizeof(CXPLAT_STORAGE));
    CxPlatLockInitialize(&Storage->Lock);
    Storage->Callback = Callback;
    Storage->CallbackContext = CallbackContext;

#pragma warning(push)
#pragma warning(disable: 4996)
    ExInitializeWorkItem(
        &Storage->WorkItem,
        CxPlatStorageRegKeyChangeCallback,
        Storage);
#pragma warning(pop)

    Status =
        ZwOpenKey(
            &Storage->RegKey,
            KEY_READ | KEY_NOTIFY,
            &Attributes);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "ZwOpenKey failed");
        goto Exit;
    }

    Status =
        ZwNotifyChangeKey(
            Storage->RegKey,
            NULL,
            (PIO_APC_ROUTINE)(ULONG_PTR)&Storage->WorkItem,
            (PVOID)(UINT_PTR)(unsigned int)DelayedWorkQueue,
            &Storage->IoStatusBlock,
            REG_NOTIFY_CHANGE_LAST_SET,
            FALSE,
            NULL,
            0,
            TRUE);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "ZwNotifyChangeKey failed");
        goto Exit;
    }

    *NewStorage = Storage;
    Storage = NULL;

Exit:

    if (PathUnicode != NULL) {
        CXPLAT_FREE(PathUnicode, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }
    if (Storage != NULL) {
        if (Storage->RegKey != NULL) {
            ZwClose(Storage->RegKey);
        }
        CxPlatLockUninitialize(&Storage->Lock);
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
        CXPLAT_EVENT CleanupEvent;
        CxPlatEventInitialize(&CleanupEvent, TRUE, FALSE);

        CxPlatLockAcquire(&Storage->Lock);
        ZwClose(Storage->RegKey); // Triggers one final notif change callback.
        Storage->RegKey = NULL;
        Storage->CleanupEvent = &CleanupEvent;
        CxPlatLockRelease(&Storage->Lock);

        CxPlatEventWaitForever(CleanupEvent);
        CxPlatEventUninitialize(CleanupEvent);
        CxPlatLockUninitialize(&Storage->Lock);
        CXPLAT_FREE(Storage, QUIC_POOL_STORAGE);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_functionClass(WORKER_THREAD_ROUTINE)
void
CxPlatStorageRegKeyChangeCallback(
    _In_ void* Context
    )
{
    CXPLAT_STORAGE* Storage = (CXPLAT_STORAGE*)Context;
    CXPLAT_EVENT* CleanupEvent = NULL;

    CxPlatLockAcquire(&Storage->Lock);
    if (Storage->CleanupEvent == NULL) {
        CXPLAT_DBG_ASSERT(Storage->RegKey != NULL);
        Storage->Callback(Storage->CallbackContext);
        ZwNotifyChangeKey(
            Storage->RegKey,
            NULL,
            (PIO_APC_ROUTINE)(ULONG_PTR)&Storage->WorkItem,
            (PVOID)(UINT_PTR)(unsigned int)DelayedWorkQueue,
            &Storage->IoStatusBlock,
            REG_NOTIFY_CHANGE_LAST_SET,
            FALSE,
            NULL,
            0,
            TRUE);
    } else {
        CleanupEvent = Storage->CleanupEvent;
    }
    CxPlatLockRelease(&Storage->Lock);

    if (CleanupEvent != NULL) {
        CxPlatEventSet(*CleanupEvent);
    }
}

#define BASE_KEY_INFO_LENGTH (offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data))

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
    QUIC_STATUS Status;
    PUNICODE_STRING NameUnicode;

    if (Name != NULL) {
        Status = CxPlatConvertUtf8ToUnicode(Name, &NameUnicode);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    } else {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Buffer == NULL) {

        ULONG InfoLength;

        Status =
            ZwQueryValueKey(
                Storage->RegKey,
                NameUnicode,
                KeyValuePartialInformation,
                NULL,
                0,
                &InfoLength);
        if (Status == STATUS_BUFFER_OVERFLOW ||
            Status == STATUS_BUFFER_TOO_SMALL) {
            Status = QUIC_STATUS_SUCCESS;
        } else if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "ZwQueryValueKey (length) failed");
            goto Exit;
        }

        *BufferLength = InfoLength - BASE_KEY_INFO_LENGTH;

    } else {

        ULONG InfoLength = BASE_KEY_INFO_LENGTH + *BufferLength;
        PKEY_VALUE_PARTIAL_INFORMATION Info = CXPLAT_ALLOC_PAGED(InfoLength, QUIC_POOL_PLATFORM_TMP_ALLOC);
        if (Info == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        Status =
            ZwQueryValueKey(
                Storage->RegKey,
                NameUnicode,
                KeyValuePartialInformation,
                Info,
                InfoLength,
                &InfoLength);
        if (QUIC_SUCCEEDED(Status)) {
            CXPLAT_DBG_ASSERT(*BufferLength == Info->DataLength);
            memcpy(Buffer, Info->Data, Info->DataLength);
        } else if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "ZwQueryValueKey failed");
        }

        CXPLAT_FREE(Info, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

Exit:

    if (NameUnicode != NULL) {
        CXPLAT_FREE(NameUnicode, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return Status;
}
