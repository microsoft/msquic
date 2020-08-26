/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Performance Driver

--*/

#include "PerfHelpers.h"
#include "PerfIoctls.h"
#include <new.h>

#ifdef QUIC_CLOG
#include "drivermain.cpp.clog.h"
#endif

DECLARE_CONST_UNICODE_STRING(QuicPerfCtlDeviceName, L"\\Device\\quicperf");
DECLARE_CONST_UNICODE_STRING(QuicPerfCtlDeviceSymLink, L"\\DosDevices\\quicperf");

typedef struct QUIC_DEVICE_EXTENSION {
    EX_PUSH_LOCK Lock;

    _Guarded_by_(Lock)
    LIST_ENTRY ClientList;
    ULONG ClientListSize;

} QUIC_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DEVICE_EXTENSION, QuicPerfCtlGetDeviceContext);

typedef struct QUIC_DRIVER_CLIENT {
    LIST_ENTRY Link;
    PerfSelfSignedConfiguration SelfSignedConfiguration;
    bool SelfSignedValid;
    QUIC_EVENT StopEvent;
    WDFREQUEST Request;
    QUIC_THREAD Thread;
    bool Canceled;
} QUIC_DRIVER_CLIENT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DRIVER_CLIENT, QuicPerfCtlGetFileContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicPerfCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE QuicPerfCtlEvtIoQueueCanceled;
EVT_WDF_REQUEST_CANCEL QuicPerfCtlEvtIoCanceled;

PAGEDX EVT_WDF_DEVICE_FILE_CREATE QuicPerfCtlEvtFileCreate;
PAGEDX EVT_WDF_FILE_CLOSE QuicPerfCtlEvtFileClose;
PAGEDX EVT_WDF_FILE_CLEANUP QuicPerfCtlEvtFileCleanup;

WDFDEVICE QuicPerfCtlDevice = nullptr;
QUIC_DEVICE_EXTENSION* QuicPerfCtlExtension = nullptr;
QUIC_DRIVER_CLIENT* QuicPerfClient = nullptr;

EVT_WDF_DRIVER_UNLOAD QuicPerfDriverUnload;

_No_competing_thread_
INITCODE
NTSTATUS
QuicPerfCtlInitialize(
    _In_ WDFDRIVER Driver
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPerfCtlUninitialize(
        void
    );

void* __cdecl operator new (size_t Size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

_Ret_maybenull_ _Post_writable_byte_size_(_Size)
void* __cdecl operator new (size_t Size, const std::nothrow_t&) throw(){
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

void __cdecl operator delete (_In_opt_ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

void __cdecl operator delete (_In_opt_ void* Mem, _In_opt_ size_t) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

void* __cdecl operator new[] (size_t Size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

_Ret_maybenull_ _Post_writable_byte_size_(_Size)
void* __cdecl operator new[] (size_t Size, const std::nothrow_t&) throw(){
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, QUIC_POOL_PERF);
}

void __cdecl operator delete[] (_In_opt_ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_POOL_PERF);
    }
}

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

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

    QuicPlatformSystemLoad(DriverObject, RegistryPath);

    Status = QuicPlatformInitialize();
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicPlatformInitialize failed");
        goto Error;
    }
    PlatformInitialized = TRUE;

    //
    // Create the WdfDriver Object
    //
    WDF_DRIVER_CONFIG_INIT(&Config, NULL);
    Config.EvtDriverUnload = QuicPerfDriverUnload;
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
    Status = QuicPerfCtlInitialize(Driver);
    if (!NT_SUCCESS(Status)) {
        goto Error;
    }

    QuicTraceLogInfo(
        PerfDriverStarted,
        "[perf] Started");

Error:

    if (!NT_SUCCESS(Status)) {
        if (PlatformInitialized) {
            QuicPlatformUninitialize();
        }
        QuicPlatformSystemUnload();
    }

    return Status;
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPerfDriverUnload(
    _In_ WDFDRIVER /*Driver*/
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    QuicPerfCtlUninitialize();

    QuicTraceLogInfo(
        PerfDriverStopped,
        "[perf] Stopped");

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
}

_No_competing_thread_
INITCODE
NTSTATUS
QuicPerfCtlInitialize(
    _In_ WDFDRIVER Driver
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
        WdfDeviceInitAssignName(
            DeviceInit,
            &QuicPerfCtlDeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
        goto Error;
    }

    QuicTraceLogVerbose(
        PerfControlInitialized,
        "[perf] Control interface initialized with %.*S", QuicPerfCtlDeviceName.Length, QuicPerfCtlDeviceName.Buffer);

    WDF_FILEOBJECT_CONFIG_INIT(
        &FileConfig,
        QuicPerfCtlEvtFileCreate,
        QuicPerfCtlEvtFileClose,
        QuicPerfCtlEvtFileCleanup);
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

    DeviceContext = QuicPerfCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));
    ExInitializePushLock(&DeviceContext->Lock);
    InitializeListHead(&DeviceContext->ClientList);

    Status = WdfDeviceCreateSymbolicLink(Device, &QuicPerfCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = QuicPerfCtlEvtIoDeviceControl;
    QueueConfig.EvtIoCanceledOnQueue = QuicPerfCtlEvtIoQueueCanceled;

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

    QuicPerfCtlDevice = Device;
    QuicPerfCtlExtension = DeviceContext;

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
QuicPerfCtlUninitialize(
        void
    )
{
    QuicTraceLogVerbose(
        PerfControlUninitializing,
        "[perf] Control interface uninitializing");

    if (QuicPerfCtlDevice != nullptr) {
        NT_ASSERT(QuicPerfCtlExtension != nullptr);
        QuicPerfCtlExtension = nullptr;

        WdfObjectDelete(QuicPerfCtlDevice);
        QuicPerfCtlDevice = nullptr;
    }

    QuicTraceLogVerbose(
        PerfControlUninitialized,
        "[perf] Control interface uninitialized");
}

PAGEDX
_Use_decl_annotations_
void
QuicPerfCtlEvtFileCreate(
    _In_ WDFDEVICE /* Device */,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    KeEnterGuardedRegion();
    ExfAcquirePushLockExclusive(&QuicPerfCtlExtension->Lock);

    do {
        if (QuicPerfCtlExtension->ClientListSize >= 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Already have max clients");
            Status = STATUS_TOO_MANY_SESSIONS;
            break;
        }

        QUIC_DRIVER_CLIENT* Client = QuicPerfCtlGetFileContext(FileObject);
        if (Client == nullptr) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "nullptr File context in FileCreate");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_DRIVER_CLIENT));

        //
        // Insert into the client list
        //
        InsertTailList(&QuicPerfCtlExtension->ClientList, &Client->Link);
        QuicPerfCtlExtension->ClientListSize++;

        QuicTraceLogInfo(
            PerfControlClientCreated,
            "[perf] Client %p created",
            Client);

        //
        // Update globals. (TODO: Add multiple device client support)
        //
        QuicPerfClient = Client;
        InterlockedExchange((volatile LONG*)&BufferCurrent, 0);
        QuicEventInitialize(&Client->StopEvent, true, false);
    } while (false);

    ExfReleasePushLockExclusive(&QuicPerfCtlExtension->Lock);
    KeLeaveGuardedRegion();

    WdfRequestComplete(Request, Status);
}

PAGEDX
_Use_decl_annotations_
void
QuicPerfCtlEvtFileClose(
    _In_ WDFFILEOBJECT /* FileObject */
    )
{
    PAGED_CODE();
}

PAGEDX
_Use_decl_annotations_
void
QuicPerfCtlEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();

    KeEnterGuardedRegion();

    QUIC_DRIVER_CLIENT* Client = QuicPerfCtlGetFileContext(FileObject);
    if (Client != nullptr) {

        ExfAcquirePushLockExclusive(&QuicPerfCtlExtension->Lock);

        //
        // Remove the device client from the list
        //
        RemoveEntryList(&Client->Link);
        QuicPerfCtlExtension->ClientListSize--;

        ExfReleasePushLockExclusive(&QuicPerfCtlExtension->Lock);

        QuicTraceLogInfo(
            PerfControlClientCleaningUp,
            "[perf] Client %p cleaning up",
            Client);

        Client->Canceled = true;
        QuicEventSet(Client->StopEvent);

        if (Client->Thread != nullptr) {
            QuicThreadWait(&Client->Thread);
            QuicThreadDelete(&Client->Thread);
        }
        QuicEventUninitialize(Client->StopEvent);

        //
        // Clean up globals.
        //
        QuicPerfClient = nullptr;
    }

    KeLeaveGuardedRegion();
}

VOID
QuicPerfCtlEvtIoQueueCanceled(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request
    )
{
    QuicPerfCtlEvtIoCanceled(Request);
}

VOID
QuicPerfCtlEvtIoCanceled(
    _In_ WDFREQUEST Request
    )
{
    NTSTATUS Status;

    WDFFILEOBJECT FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Error;
    }

    QUIC_DRIVER_CLIENT* Client = QuicPerfCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto Error;
    }

    Client->Canceled = true;
    QuicEventSet(Client->StopEvent);

    QuicTraceLogWarning(
        PerfControlClientCanceledRequest,
        "[perf] Client %p canceled request %p",
        Client,
        Request);

    return;
Error:
    WdfRequestComplete(Request, Status);
}

NTSTATUS
QuicPerfCtlSetSecurityConfig(
    _Inout_ QUIC_DRIVER_CLIENT* Client,
    _In_ const QUIC_CERTIFICATE_HASH* CertHash
    )
{
    Client->SelfSignedConfiguration.SelfSignedSecurityHash = *CertHash;
    Client->SelfSignedValid = true;
    return QUIC_STATUS_SUCCESS;
}

size_t QUIC_IOCTL_BUFFER_SIZES[] =
{
    0,
    sizeof(QUIC_CERTIFICATE_HASH),
    SIZE_MAX,
    0
};

typedef union {
    struct {
        int Length;
        char Data;
    };
    QUIC_CERTIFICATE_HASH CertHash;
} QUIC_IOCTL_PARAMS;

static_assert(
    QUIC_PERF_MAX_IOCTL_FUNC_CODE + 1 == (sizeof(QUIC_IOCTL_BUFFER_SIZES) / sizeof(size_t)),
    "QUIC_IOCTL_BUFFER_SIZES must be kept in sync with the IOTCLs");

//
// Since the test is long running, we can't just wait in the Ioctl directly,
// otherwise we can't cancel. Instead, move the wait into a separate thread
// so the Ioctl returns into user mode.
//
QUIC_THREAD_CALLBACK(PerformanceWaitForStopThreadCb, Context)
{
    QUIC_DRIVER_CLIENT* Client = (QUIC_DRIVER_CLIENT*)Context;
    WDFREQUEST Request = Client->Request;

    char* LocalBuffer = nullptr;
    DWORD ReturnedLength = 0;
    QUIC_STATUS StopStatus;

    StopStatus =
        QuicMainStop(0);

    if (Client->Canceled) {
        QuicTraceLogInfo(
            PerformanceStopCancelled,
            "[perf] Performance Stop Cancelled");
        WdfRequestComplete(Request, STATUS_CANCELLED);
        return;
    }

    WdfRequestUnmarkCancelable(Request);

    NTSTATUS Status =
        WdfRequestRetrieveOutputBuffer(
            Request,
            (size_t)BufferCurrent + 1,
            (void**)&LocalBuffer,
            nullptr);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    QuicCopyMemory(LocalBuffer, Buffer, BufferCurrent);
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
        StopStatus,
        ReturnedLength);
}

void
QuicPerfCtlReadPrints(
    _In_ WDFREQUEST Request,
    _In_ QUIC_DRIVER_CLIENT* Client
    )
{
    QUIC_STATUS Status;
    QUIC_THREAD_CONFIG ThreadConfig;
    QuicZeroMemory(&ThreadConfig, sizeof(ThreadConfig));
    ThreadConfig.Name = "PerfWait";
    ThreadConfig.Callback = PerformanceWaitForStopThreadCb;
    ThreadConfig.Context = Client;
    Client->Request = Request;
    if (QUIC_FAILED(Status = QuicThreadCreate(&ThreadConfig, &Client->Thread))) {
        if (Client->Thread) {
            Client->Canceled = true;
            QuicEventSet(Client->StopEvent);
            QuicThreadWait(&Client->Thread);
            QuicThreadDelete(&Client->Thread);
            Client->Thread = nullptr;
        }
        WdfRequestCompleteWithInformation(
            Request,
            Status,
            0);
    } else {
        WdfRequestMarkCancelable(Request, QuicPerfCtlEvtIoCanceled);
    }
}

NTSTATUS
QuicPerfCtlStart(
    _In_ QUIC_DRIVER_CLIENT* Client,
    _In_ char* Arguments,
    _In_ int Length
    ) {
    char** Argv = new(std::nothrow) char* [Length];
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
            &Client->SelfSignedConfiguration);
    delete[] Argv;

    return Status;
}

VOID
QuicPerfCtlEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
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

    Client = QuicPerfCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicPerfCtlGetFileContext failed");
        goto Error;
    }

    //
    // Handle IOCTL for read
    //
    if (IoControlCode == IOCTL_QUIC_READ_DATA) {
        QuicPerfCtlReadPrints(
            Request,
            Client);
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
            "[ lib] Error, %u, %s.",
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

    if (IoControlCode != IOCTL_QUIC_SEC_CONFIG &&
        !Client->SelfSignedValid) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    switch (IoControlCode) {
    case IOCTL_QUIC_SEC_CONFIG:
        QUIC_FRE_ASSERT(Params != nullptr);
        Status =
            QuicPerfCtlSetSecurityConfig(
                Client,
                &Params->CertHash);
        break;
    case IOCTL_QUIC_RUN_PERF:
        Status =
            QuicPerfCtlStart(
                Client,
                &Params->Data,
                Params->Length);
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
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Queue);
}
