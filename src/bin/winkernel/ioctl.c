/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    IOCTL interface for the MsQuic.sys driver.

--*/

#include "quic_platform.h"
#include "quic_trace.h"
#include "msquic.h"
#include "msquic_ioctl.h"

#ifdef QUIC_CLOG
#include "ioctl.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCountersExternal(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    );

DECLARE_CONST_UNICODE_STRING(QuicIoCtlDeviceName, L"\\Device\\" MSQUIC_DEVICE_NAME);
DECLARE_CONST_UNICODE_STRING(QuicIoCtlDeviceSymLink, L"\\DosDevices\\" MSQUIC_DEVICE_NAME);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicIoCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE QuicIoCtlEvtIoQueueCanceled;
EVT_WDF_REQUEST_CANCEL QuicIoCtlEvtIoCanceled;

WDFDEVICE QuicIoCtlDevice;

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
        WDF_NO_EVENT_CALLBACK,
        WDF_NO_EVENT_CALLBACK,
        WDF_NO_EVENT_CALLBACK);
    FileConfig.FileObjectClass = WdfFileObjectWdfCanUseFsContext2;
    WDF_OBJECT_ATTRIBUTES_INIT(&Attribs);
    WdfDeviceInitSetFileObjectConfig(
        DeviceInit,
        &FileConfig,
        &Attribs);

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
        WdfObjectDelete(QuicIoCtlDevice);
        QuicIoCtlDevice = NULL;
    }

    QuicTraceLogVerbose(
        IoControlUninitialized,
        "[ioct] Control interface uninitialized");
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

    if (OutputBufferLength < QUIC_PERF_COUNTER_MAX * sizeof(int64_t)) {
        //
        // Copy as many counters will fit completely in the buffer.
        //
        OutputBufferLength = (OutputBufferLength / sizeof(int64_t)) * sizeof(int64_t);
        if (OutputBufferLength == 0) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Error;
        }
    } else {
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

    WdfRequestCompleteWithInformation(Request, Status, OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(Queue);
}
