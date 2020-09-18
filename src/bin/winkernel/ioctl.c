/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    IOCTL interface for the MsQuic.sys driver.

--*/

#include "quic_platform.h"
#include "quic_trace.h"
#include "msquic.h"
#include "msquicp.h"

#ifdef QUIC_CLOG
#include "ioctl.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCountersExternal(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    );

DECLARE_CONST_UNICODE_STRING(QuicIoCtlDeviceName, L"\\Device\\msquic");
DECLARE_CONST_UNICODE_STRING(QuicIoCtlDeviceSymLink, L"\\DosDevices\\msquic");

typedef struct QUIC_DEVICE_EXTENSION {
    void* Reserved;
} QUIC_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DEVICE_EXTENSION, QuicIoCtlGetDeviceContext);

typedef struct QUIC_DRIVER_CLIENT {
    void* Reserved;
} QUIC_DRIVER_CLIENT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DRIVER_CLIENT, QuicIoCtlGetFileContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicIoCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE QuicIoCtlEvtIoQueueCanceled;
EVT_WDF_REQUEST_CANCEL QuicIoCtlEvtIoCanceled;

PAGEDX EVT_WDF_DEVICE_FILE_CREATE QuicIoCtlEvtFileCreate;
PAGEDX EVT_WDF_FILE_CLOSE QuicIoCtlEvtFileClose;
PAGEDX EVT_WDF_FILE_CLEANUP QuicIoCtlEvtFileCleanup;

WDFDEVICE QuicIoCtlDevice;
QUIC_DEVICE_EXTENSION* QuicIoCtlExtension;

_No_competing_thread_
INITCODE
NTSTATUS
QuicIoCtlInitialize(
    _In_ WDFDRIVER Driver
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWDFDEVICE_INIT DeviceInit = NULL;
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
    if (DeviceInit == NULL) {
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
            &QuicIoCtlDeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
        goto Error;
    }

    QuicTraceLogVerbose(
        IoControlInitialized,
        "[ioct] Control interface initialized");

    WDF_FILEOBJECT_CONFIG_INIT(
        &FileConfig,
        QuicIoCtlEvtFileCreate,
        QuicIoCtlEvtFileClose,
        QuicIoCtlEvtFileCleanup);
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

    DeviceContext = QuicIoCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));

    Status = WdfDeviceCreateSymbolicLink(Device, &QuicIoCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = QuicIoCtlEvtIoDeviceControl;
    QueueConfig.EvtIoCanceledOnQueue = QuicIoCtlEvtIoQueueCanceled;

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

    QuicIoCtlDevice = Device;
    QuicIoCtlExtension = DeviceContext;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(
        IoControlInitialized,
        "[ioct] Control interface initialized");

Error:

    if (DeviceInit) {
        WdfDeviceInitFree(DeviceInit);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicIoCtlUninitialize(
        void
    )
{
    QuicTraceLogVerbose(
        IoControlUninitializing,
        "[ioct] Control interface uninitializing");

    if (QuicIoCtlDevice != NULL) {
        NT_ASSERT(QuicIoCtlExtension != NULL);
        QuicIoCtlExtension = NULL;

        WdfObjectDelete(QuicIoCtlDevice);
        QuicIoCtlDevice = NULL;
    }

    QuicTraceLogVerbose(
        IoControlUninitialized,
        "[ioct] Control interface uninitialized");
}

PAGEDX
_Use_decl_annotations_
void
QuicIoCtlEvtFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Device);

    PAGED_CODE();

    KeEnterGuardedRegion();

    do {
        QUIC_DRIVER_CLIENT* Client = QuicIoCtlGetFileContext(FileObject);
        if (Client == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "NULL File context in FileCreate");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_DRIVER_CLIENT));

        QuicTraceLogInfo(
            IoControlClientCreated,
            "[ioct] Client %p created",
            Client);

    } while (FALSE);

    KeLeaveGuardedRegion();

    WdfRequestComplete(Request, Status);
}

PAGEDX
_Use_decl_annotations_
void
QuicIoCtlEvtFileClose(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(FileObject);
}

PAGEDX
_Use_decl_annotations_
void
QuicIoCtlEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();

    KeEnterGuardedRegion();

    QUIC_DRIVER_CLIENT* Client = QuicIoCtlGetFileContext(FileObject);
    if (Client != NULL) {
        QuicTraceLogInfo(
            IoControlClientCleaningUp,
            "[ioct] Client %p cleaning up",
            Client);
    }

    KeLeaveGuardedRegion();
}

VOID
QuicIoCtlEvtIoQueueCanceled(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
}

VOID
QuicIoCtlEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    WDFFILEOBJECT FileObject = NULL;
    QUIC_DRIVER_CLIENT* Client = NULL;
    uint8_t* OutputBuffer = NULL;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        Status = STATUS_NOT_SUPPORTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "IOCTL not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    if (IoControlCode != IOCTL_QUIC_PERFORMANCE_COUNTERS) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Invalid IOCTL");
        Status = STATUS_INVALID_PARAMETER;
        goto Error;
    }

    FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == NULL) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestGetFileObject failed");
        goto Error;
    }

    Client = QuicIoCtlGetFileContext(FileObject);
    if (Client == NULL) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicIoCtlGetFileContext failed");
        goto Error;
    }

    QuicTraceLogInfo(
        IoControlClientIoctl,
        "[ioct] Client %p executing IOCTL %u",
        Client,
        IoControlCode);

    if (OutputBufferLength < QUIC_PERF_COUNTER_MAX * sizeof(int64_t)) {
        //
        // Copy as many counters will fit completely in the buffer.
        //
        OutputBufferLength = (OutputBufferLength / sizeof(int64_t)) * sizeof(int64_t);
        if (OutputBufferLength == 0) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Error;
        }
    }
    else {
        OutputBufferLength = QUIC_PERF_COUNTER_MAX * sizeof(int64_t);
    }

    Status =
        WdfRequestRetrieveOutputBuffer(
            Request,
            OutputBufferLength,
            &OutputBuffer,
            NULL);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfRequestRetrieveOutputBuffer failed");
        goto Error;
    }

    QuicLibrarySumPerfCountersExternal(OutputBuffer, (uint32_t)OutputBufferLength);

Error:

    QuicTraceLogInfo(
        IoControlClientIoctlComplete,
        "[ioct] Client %p completing request, 0x%x",
        Client,
        Status);

    WdfRequestComplete(Request, Status);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Queue);
}
