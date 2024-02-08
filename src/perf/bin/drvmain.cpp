/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Performance Driver

--*/

#include "SecNetPerf.h"
#include "PerfIoctls.h"
#include <new.h>

#ifdef QUIC_CLOG
#include "drvmain.cpp.clog.h"
#endif

DECLARE_CONST_UNICODE_STRING(SecNetPerfCtlDeviceNameBase, L"\\Device\\");
DECLARE_CONST_UNICODE_STRING(SecNetPerfCtlDeviceSymLinkBase, L"\\DosDevices\\");

typedef struct QUIC_DEVICE_EXTENSION {
    EX_PUSH_LOCK Lock;

    _Guarded_by_(Lock)
    LIST_ENTRY ClientList;
    ULONG ClientListSize;

} QUIC_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DEVICE_EXTENSION, SecNetPerfCtlGetDeviceContext);

typedef struct QUIC_DRIVER_CLIENT {
    LIST_ENTRY Link;
    QUIC_CREDENTIAL_CONFIG SelfSignedCredConfig;
    QUIC_CERTIFICATE_HASH_STORE SelfSignedCertHash;
    bool SelfSignedValid;
    CXPLAT_EVENT StopEvent;
    WDFREQUEST Request;
    CXPLAT_THREAD Thread;
    bool Canceled;
    bool CleanupHandleCancellation;
    CXPLAT_LOCK CleanupLock;
} QUIC_DRIVER_CLIENT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DRIVER_CLIENT, SecNetPerfCtlGetFileContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SecNetPerfCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE SecNetPerfCtlEvtIoQueueCanceled;
EVT_WDF_REQUEST_CANCEL SecNetPerfCtlEvtIoCanceled;

PAGEDX EVT_WDF_DEVICE_FILE_CREATE SecNetPerfCtlEvtFileCreate;
PAGEDX EVT_WDF_FILE_CLOSE SecNetPerfCtlEvtFileClose;
PAGEDX EVT_WDF_FILE_CLEANUP SecNetPerfCtlEvtFileCleanup;

WDFDEVICE SecNetPerfCtlDevice = nullptr;
QUIC_DEVICE_EXTENSION* SecNetPerfCtlExtension = nullptr;
QUIC_DRIVER_CLIENT* SecNetPerfClient = nullptr;

EVT_WDF_DRIVER_UNLOAD SecNetPerfDriverUnload;

_No_competing_thread_
INITCODE
NTSTATUS
SecNetPerfCtlInitialize(
    _In_ WDFDRIVER Driver,
    _In_ PUNICODE_STRING BaseRegPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
SecNetPerfCtlUninitialize(
    void
    );

_Ret_maybenull_ _Post_writable_byte_size_(_Size)
void* __cdecl operator new (size_t Size, const std::nothrow_t&) throw(){
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

void __cdecl operator delete (/*_In_opt_*/ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

void __cdecl operator delete (_In_opt_ void* Mem, _In_opt_ size_t) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

namespace std { enum class align_val_t : size_t {}; } // Work around
void __cdecl operator delete(_In_opt_ void* Mem, size_t, std::align_val_t) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

_Ret_maybenull_ _Post_writable_byte_size_(_Size)
void* __cdecl operator new[] (size_t Size, const std::nothrow_t&) throw(){
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

void __cdecl operator delete[] (/*_In_opt_*/ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

void __cdecl operator delete[] (_In_opt_ void* Mem, _In_opt_ size_t) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

extern "C"
INITCODE
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    WDF_DRIVER_CONFIG Config;
    WDFDRIVER Driver;
    BOOLEAN PlatformInitialized = FALSE;

    CxPlatSystemLoad();

    Status = CxPlatInitialize();
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatInitialize failed");
        goto Error;
    }
    PlatformInitialized = TRUE;

    //
    // Create the WdfDriver Object
    //
    WDF_DRIVER_CONFIG_INIT(&Config, NULL);
    Config.EvtDriverUnload = SecNetPerfDriverUnload;
    Config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    Config.DriverPoolTag = QUIC_POOL_PERF;

    Status =
        WdfDriverCreate(
            DriverObject,
            RegistryPath,
            WDF_NO_OBJECT_ATTRIBUTES,
            &Config,
            &Driver);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDriverCreate failed");
        goto Error;
    }

    //
    // Initialize the device control interface.
    //
    Status = SecNetPerfCtlInitialize(Driver, RegistryPath);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }

    QuicTraceLogInfo(
        PerfDriverStarted,
        "[perf] Started");

Error:

    if (!NT_SUCCESS(Status)) {
        if (PlatformInitialized) {
            CxPlatUninitialize();
        }
        CxPlatSystemUnload();
    }

    return Status;
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
SecNetPerfDriverUnload(
    _In_ WDFDRIVER /*Driver*/
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    SecNetPerfCtlUninitialize();

    QuicTraceLogInfo(
        PerfDriverStopped,
        "[perf] Stopped");

    CxPlatUninitialize();
    CxPlatSystemUnload();
}

_No_competing_thread_
INITCODE
NTSTATUS
SecNetPerfGetServiceName(
    _In_ PUNICODE_STRING BaseRegPath,
    _Inout_ PUNICODE_STRING ServiceName
    )
{
    USHORT BaseRegPathLength = BaseRegPath->Length / sizeof(WCHAR);
    if (BaseRegPath->Buffer[BaseRegPathLength - 1] == L'\\') {
        BaseRegPathLength--; // Trim trailing slash
    }

    //
    // Get the service name from the base registry path.
    //
    USHORT ServiceNameLength = 0;
    while (BaseRegPath->Buffer[BaseRegPathLength - ServiceNameLength - 1] != L'\\') {
        ServiceNameLength++;
    }
    if (ServiceNameLength == 0) {
        //LogError("[config] Empty service name!");
        return STATUS_INVALID_PARAMETER;
    }

    *ServiceName = { ServiceNameLength * sizeof(WCHAR), ServiceNameLength * sizeof(WCHAR), BaseRegPath->Buffer + (BaseRegPathLength - ServiceNameLength) };

    return STATUS_SUCCESS;
}

_No_competing_thread_
INITCODE
NTSTATUS
SecNetPerfCtlInitialize(
    _In_ WDFDRIVER Driver,
    _In_ PUNICODE_STRING BaseRegPath
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWDFDEVICE_INIT DeviceInit = nullptr;
    WDF_FILEOBJECT_CONFIG FileConfig;
    WDF_OBJECT_ATTRIBUTES Attribs;
    WDFDEVICE Device;
    QUIC_DEVICE_EXTENSION* DeviceContext;
    WDF_IO_QUEUE_CONFIG QueueConfig;
    WDFQUEUE Queue;
    DECLARE_UNICODE_STRING_SIZE(ServiceName, 64);
    DECLARE_UNICODE_STRING_SIZE(DeviceName, 100);

    DeviceInit =
        WdfControlDeviceInitAllocate(
            Driver,
            &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (DeviceInit == nullptr) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfControlDeviceInitAllocate failed");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error;
    }

    Status =
        SecNetPerfGetServiceName(
            BaseRegPath,
            &ServiceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "SecNetPerfGetServiceName failed");
        goto Error;
    }

    Status = RtlUnicodeStringCopy(&DeviceName, &SecNetPerfCtlDeviceNameBase);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUnicodeStringCopy failed");
        goto Error;
    }

    Status = RtlUnicodeStringCat(&DeviceName, &ServiceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUnicodeStringCat failed");
        goto Error;
    }

    Status =
        WdfDeviceInitAssignName(
            DeviceInit,
            &DeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
        goto Error;
    }

    WDF_FILEOBJECT_CONFIG_INIT(
        &FileConfig,
        SecNetPerfCtlEvtFileCreate,
        SecNetPerfCtlEvtFileClose,
        SecNetPerfCtlEvtFileCleanup);
    FileConfig.FileObjectClass = WdfFileObjectWdfCanUseFsContext2;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_DRIVER_CLIENT);
    WdfDeviceInitSetFileObjectConfig(
        DeviceInit,
        &FileConfig,
        &Attribs);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_DEVICE_EXTENSION);

    Status =
        WdfDeviceCreate(
            &DeviceInit,
            &Attribs,
            &Device);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreate failed");
        goto Error;
    }

    DeviceContext = SecNetPerfCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));
    ExInitializePushLock(&DeviceContext->Lock);
    InitializeListHead(&DeviceContext->ClientList);

    DeviceName.Length = 0;
    Status = RtlUnicodeStringCopy(&DeviceName, &SecNetPerfCtlDeviceSymLinkBase);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUnicodeStringCopy failed");
        goto Error;
    }

    Status = RtlUnicodeStringCat(&DeviceName, &ServiceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "RtlUnicodeStringCat failed");
        goto Error;
    }

    Status = WdfDeviceCreateSymbolicLink(Device, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = SecNetPerfCtlEvtIoDeviceControl;
    QueueConfig.EvtIoCanceledOnQueue = SecNetPerfCtlEvtIoQueueCanceled;

    __analysis_assume(QueueConfig.EvtIoStop != 0);
    Status =
        WdfIoQueueCreate(
            Device,
            &QueueConfig,
            WDF_NO_OBJECT_ATTRIBUTES,
            &Queue);
    __analysis_assume(QueueConfig.EvtIoStop == 0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfIoQueueCreate failed");
        goto Error;
    }

    SecNetPerfCtlDevice = Device;
    SecNetPerfCtlExtension = DeviceContext;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(
        PerfControlInitialized,
        "[perf] Control interface initialized");

Error:

    if (DeviceInit) {
        WdfDeviceInitFree(DeviceInit);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
SecNetPerfCtlUninitialize(
        void
    )
{
    QuicTraceLogVerbose(
        PerfControlUninitializing,
        "[perf] Control interface uninitializing");

    if (SecNetPerfCtlDevice != nullptr) {
        NT_ASSERT(SecNetPerfCtlExtension != nullptr);
        SecNetPerfCtlExtension = nullptr;

        WdfObjectDelete(SecNetPerfCtlDevice);
        SecNetPerfCtlDevice = nullptr;
    }

    QuicTraceLogVerbose(
        PerfControlUninitialized,
        "[perf] Control interface uninitialized");
}

PAGEDX
_Use_decl_annotations_
void
SecNetPerfCtlEvtFileCreate(
    _In_ WDFDEVICE /* Device */,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    KeEnterGuardedRegion();
    ExAcquirePushLockExclusive(&SecNetPerfCtlExtension->Lock);

    do {
        if (SecNetPerfCtlExtension->ClientListSize >= 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Already have max clients");
            Status = STATUS_TOO_MANY_SESSIONS;
            break;
        }

        QUIC_DRIVER_CLIENT* Client = SecNetPerfCtlGetFileContext(FileObject);
        if (Client == nullptr) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "nullptr File context in FileCreate");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_DRIVER_CLIENT));
        CxPlatLockInitialize(&Client->CleanupLock);

        //
        // Insert into the client list
        //
        InsertTailList(&SecNetPerfCtlExtension->ClientList, &Client->Link);
        SecNetPerfCtlExtension->ClientListSize++;

        QuicTraceLogInfo(
            PerfControlClientCreated,
            "[perf] Client %p created",
            Client);

        //
        // Update globals. (TODO: Add multiple device client support)
        //
        SecNetPerfClient = Client;
        InterlockedExchange((volatile LONG*)&BufferCurrent, 0);
        CxPlatEventInitialize(&Client->StopEvent, true, false);
    } while (false);

    ExReleasePushLockExclusive(&SecNetPerfCtlExtension->Lock);
    KeLeaveGuardedRegion();

    WdfRequestComplete(Request, Status);
}

PAGEDX
_Use_decl_annotations_
void
SecNetPerfCtlEvtFileClose(
    _In_ WDFFILEOBJECT /* FileObject */
    )
{
    PAGED_CODE();
}

PAGEDX
_Use_decl_annotations_
void
SecNetPerfCtlEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();

    KeEnterGuardedRegion();

    QUIC_DRIVER_CLIENT* Client = SecNetPerfCtlGetFileContext(FileObject);
    if (Client != nullptr) {

        ExAcquirePushLockExclusive(&SecNetPerfCtlExtension->Lock);

        //
        // Remove the device client from the list
        //
        RemoveEntryList(&Client->Link);
        SecNetPerfCtlExtension->ClientListSize--;

        ExReleasePushLockExclusive(&SecNetPerfCtlExtension->Lock);

        QuicTraceLogInfo(
            PerfControlClientCleaningUp,
            "[perf] Client %p cleaning up",
            Client);

        Client->Canceled = true;
        CxPlatEventSet(Client->StopEvent);

        if (Client->Thread != nullptr) {
            CxPlatThreadWait(&Client->Thread);
            CxPlatThreadDelete(&Client->Thread);
            Client->Thread = nullptr;
        }
        CxPlatEventUninitialize(Client->StopEvent);

        QuicMainFree();

        //
        // Clean up globals.
        //
        SecNetPerfClient = nullptr;
    }

    KeLeaveGuardedRegion();
}

VOID
SecNetPerfCtlEvtIoQueueCanceled(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request
    )
{
    SecNetPerfCtlEvtIoCanceled(Request);
}

VOID
SecNetPerfCtlEvtIoCanceled(
    _In_ WDFREQUEST Request
    )
{
    NTSTATUS Status;
    WDFFILEOBJECT FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Error;
    }

    QUIC_DRIVER_CLIENT* Client = SecNetPerfCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Error;
    }

    Client->Canceled = true;
    CxPlatEventSet(Client->StopEvent);

    QuicTraceLogWarning(
        PerfControlClientCanceledRequest,
        "[perf] Client %p canceled request %p",
        Client,
        Request);

    CxPlatLockAcquire(&Client->CleanupLock);
    if (Client->CleanupHandleCancellation) {
        WdfRequestComplete(Request, STATUS_CANCELLED);
    }
    Client->CleanupHandleCancellation = true;
    CxPlatLockRelease(&Client->CleanupLock);
    return;
Error:
    WdfRequestComplete(Request, Status);
}

NTSTATUS
SecNetPerfCtlSetSecurityConfig(
    _Inout_ QUIC_DRIVER_CLIENT* Client,
    _In_ const QUIC_CERTIFICATE_HASH* CertHash
    )
{
    Client->SelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
    Client->SelfSignedCredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    Client->SelfSignedCredConfig.CertificateHashStore = &Client->SelfSignedCertHash;
    Client->SelfSignedCertHash.Flags = QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;
    RtlCopyMemory(&Client->SelfSignedCertHash.StoreName, "MY", sizeof("MY"));
    RtlCopyMemory(&Client->SelfSignedCertHash.ShaHash, CertHash, sizeof(QUIC_CERTIFICATE_HASH));
    Client->SelfSignedValid = true;
    return QUIC_STATUS_SUCCESS;
}

typedef struct {
    QUIC_CERTIFICATE_HASH ServerCertHash;
    QUIC_CERTIFICATE_HASH ClientCertHash;
} QUIC_RUN_CERTIFICATE_PARAMS;

size_t QUIC_IOCTL_BUFFER_SIZES[] =
{
    0,
    sizeof(QUIC_RUN_CERTIFICATE_PARAMS),
    SIZE_MAX,
    0,
    0,
    0,
    0
};

typedef union {
    struct {
        int Length;
        char Data;
    };
    QUIC_RUN_CERTIFICATE_PARAMS CertParams;
} QUIC_IOCTL_PARAMS;

CXPLAT_STATIC_ASSERT(
    QUIC_PERF_MAX_IOCTL_FUNC_CODE + 1 == (sizeof(QUIC_IOCTL_BUFFER_SIZES) / sizeof(size_t)),
    "QUIC_IOCTL_BUFFER_SIZES must be kept in sync with the IOTCLs");

//
// Since the test is long running, we can't just wait in the Ioctl directly,
// otherwise we can't cancel. Instead, move the wait into a separate thread
// so the Ioctl returns into user mode.
//
CXPLAT_THREAD_CALLBACK(PerformanceWaitForStopThreadCb, Context)
{
    QUIC_DRIVER_CLIENT* Client = (QUIC_DRIVER_CLIENT*)Context;
    WDFREQUEST Request = Client->Request;

    WdfRequestMarkCancelable(Request, SecNetPerfCtlEvtIoCanceled);
    if (Client->Canceled) {
        QuicTraceLogInfo(
            PerformanceStopCancelled,
            "[perf] Performance Stop Cancelled");
        WdfRequestComplete(Request, STATUS_CANCELLED);
        return;
    }

    QuicMainWaitForCompletion();

    if (Client->Canceled) {
        QuicTraceLogInfo(
            PerformanceStopCancelled,
            "[perf] Performance Stop Cancelled");
        WdfRequestComplete(Request, STATUS_CANCELLED);
        return;
    }

    CxPlatLockAcquire(&Client->CleanupLock);
    NTSTATUS Status = WdfRequestUnmarkCancelable(Request);
    bool ExistingCancellation = Client->CleanupHandleCancellation;
    Client->CleanupHandleCancellation = TRUE;
    CxPlatLockRelease(&Client->CleanupLock);
    if (Status == STATUS_CANCELLED && !ExistingCancellation) {
        return;
    }

    DWORD ReturnedLength = 0;
    char* LocalBuffer = nullptr;
    Status =
        WdfRequestRetrieveOutputBuffer(
            Request,
            (size_t)BufferCurrent + 1,
            (void**)&LocalBuffer,
            nullptr);
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    CxPlatCopyMemory(LocalBuffer, Buffer, BufferCurrent);
    LocalBuffer[BufferCurrent] = '\0';

    QuicTraceLogInfo(
        PrintBufferReturn,
        "[perf] Print Buffer %d %s\n",
        BufferCurrent,
        LocalBuffer);

    ReturnedLength = BufferCurrent + 1;

Exit:
    WdfRequestCompleteWithInformation(
        Request,
        QUIC_STATUS_SUCCESS,
        ReturnedLength);
}

void
SecNetPerfCtlReadPrints(
    _In_ WDFREQUEST Request,
    _In_ QUIC_DRIVER_CLIENT* Client
    )
{
    CXPLAT_THREAD_CONFIG ThreadConfig = {0};
    ThreadConfig.Name = "PerfWait";
    ThreadConfig.Callback = PerformanceWaitForStopThreadCb;
    ThreadConfig.Context = Client;
    Client->Request = Request;
    QUIC_STATUS Status = CxPlatThreadCreate(&ThreadConfig, &Client->Thread);
    if (QUIC_FAILED(Status)) {
        if (Client->Thread) {
            Client->Canceled = true;
            CxPlatEventSet(Client->StopEvent);
            CxPlatThreadWait(&Client->Thread);
            CxPlatThreadDelete(&Client->Thread);
            Client->Thread = nullptr;
        }
        WdfRequestCompleteWithInformation(
            Request,
            Status,
            0);
    }
}

NTSTATUS
SecNetPerfCtlStart(
    _In_ QUIC_DRIVER_CLIENT* Client,
    _In_ char* Arguments,
    _In_ int Length
    )
{
    auto Argv = new(std::nothrow) char* [Length];
    if (!Argv) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Arguments += sizeof(Length);
    for (int i = 0; i < Length; i++) {
        Argv[i] = Arguments;
        Arguments += strlen(Arguments);
        Arguments++;
    }

    NTSTATUS Status =
        QuicMainStart(
            (int)Length,
            Argv,
            &Client->StopEvent,
            &Client->SelfSignedCredConfig);
    delete[] Argv;

    return Status;
}

void
SecNetPerfCtlGetExtraDataLength(
    _In_ WDFREQUEST Request
    )
{
    uint32_t* DataLength;
    NTSTATUS Status =
        WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(*DataLength),
            (void**)&DataLength,
            nullptr);
    if (!NT_SUCCESS(Status)) {
        WdfRequestComplete(Request, Status);
        return;
    }

    *DataLength = QuicMainGetExtraDataLength();
    WdfRequestCompleteWithInformation(
        Request,
        Status,
        sizeof(*DataLength));
}

void
SecNetPerfCtlGetExtraData(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
    )
{
    CXPLAT_FRE_ASSERT(OutputBufferLength < UINT32_MAX);
    uint8_t* OutputBuffer = nullptr;
    NTSTATUS Status =
        WdfRequestRetrieveOutputBuffer(
            Request,
            OutputBufferLength,
            (void**)&OutputBuffer,
            nullptr);
    if (!NT_SUCCESS(Status)) {
        WdfRequestComplete(Request, Status);
        return;
    }

    QuicMainGetExtraData(OutputBuffer, (uint32_t)OutputBufferLength);
    WdfRequestCompleteWithInformation(
        Request,
        QUIC_STATUS_SUCCESS,
        OutputBufferLength);
}

VOID
SecNetPerfCtlEvtIoDeviceControl(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t /* InputBufferLength */,
    _In_ ULONG IoControlCode
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    WDFFILEOBJECT FileObject = nullptr;
    QUIC_DRIVER_CLIENT* Client = nullptr;
    ULONG FunctionCode = 0;
    QUIC_IOCTL_PARAMS* Params = nullptr;
    size_t Length = 0;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        Status = STATUS_NOT_SUPPORTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "IOCTL not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestGetFileObject failed");
        goto Error;
    }

    Client = SecNetPerfCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SecNetPerfCtlGetFileContext failed");
        goto Error;
    }

    //
    // Handle IOCTL for read
    //
    if (IoControlCode == IOCTL_QUIC_READ_DATA) {
        SecNetPerfCtlReadPrints(Request, Client);
        return;
    } else if (IoControlCode == IOCTL_QUIC_GET_EXTRA_DATA_LENGTH) {
        SecNetPerfCtlGetExtraDataLength(Request);
        return;
    } else if (IoControlCode == IOCTL_QUIC_GET_EXTRA_DATA) {
        SecNetPerfCtlGetExtraData(Request, OutputBufferLength);
        return;
    }

    FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);
    if (FunctionCode == 0 || FunctionCode > QUIC_PERF_MAX_IOCTL_FUNC_CODE) {
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid FunctionCode");
        goto Error;
    }

    Status =
        WdfRequestRetrieveInputBuffer(
            Request,
            0,
            (void**)&Params,
            &Length);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WfdRequestRetreiveInputBuffer failed");
    } else if (Params == nullptr) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestRetrieveInputBuffer failed to return parameter buffer");
        Status = STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QuicTraceLogInfo(
        PerfControlClientIoctl,
        "[perf] Client %p executing write IOCTL %u",
        Client,
        FunctionCode);

    if (IoControlCode != IOCTL_QUIC_SET_CERT_PARAMS &&
        !Client->SelfSignedValid) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    switch (IoControlCode) {
    case IOCTL_QUIC_SET_CERT_PARAMS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        Status =
            SecNetPerfCtlSetSecurityConfig(
                Client,
                &Params->CertParams.ServerCertHash);
        break;
    case IOCTL_QUIC_RUN_PERF:
        Status =
            SecNetPerfCtlStart(
                Client,
                &Params->Data,
                Params->Length);
        break;
    case IOCTL_CXPLAT_FREE_PERF:
        QuicMainFree();
        Status = QUIC_STATUS_SUCCESS;
        break;
    default:
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    }

Error:
    QuicTraceLogInfo(
        PerfControlClientIoctlComplete,
        "[perf] Client %p completing request, 0x%x",
        Client,
        Status);

    WdfRequestComplete(Request, Status);
}
