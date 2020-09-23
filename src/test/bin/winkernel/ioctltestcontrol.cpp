/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode IOCTL Interface Test Driver

--*/

#include <quic_platform.h>
#include <MsQuicTests.h>

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "ioctltestcontrol.cpp.clog.h"
#endif

#ifdef PRIVATE_LIBRARY
DECLARE_CONST_UNICODE_STRING(QuicIoctlTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME_PRIVATE "IOCTL");
DECLARE_CONST_UNICODE_STRING(QuicIoctlTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME_PRIVATE "IOCTL");
#else
DECLARE_CONST_UNICODE_STRING(QuicIoctlTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME "IOCTL");
DECLARE_CONST_UNICODE_STRING(QuicIoctlTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME "IOCTL");
#endif

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicIoctlTestCtlEvtIoDeviceControl;

WDFDEVICE QuicIoctlTestCtlDevice = nullptr;

_No_competing_thread_
INITCODE
NTSTATUS
QuicIoctlTestCtlInitialize(
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
            &QuicIoctlTestCtlDeviceName);
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

    Status =
        WdfDeviceCreateSymbolicLink(
            Device,
            &QuicIoctlTestCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = QuicIoctlTestCtlEvtIoDeviceControl;

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

    QuicIoctlTestCtlDevice = Device;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(
        TestControlInitialized,
        "[test] Control interface initialized");

Error:

    if (DeviceInit) {
        WdfDeviceInitFree(DeviceInit);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicIoctlTestCtlUninitialize(
    void
)
{
    QuicTraceLogVerbose(
        IoControlUninitializing,
        "[ioct] Control interface uninitializing");

    delete MsQuic;
    MsQuic = nullptr;

    if (QuicIoctlTestCtlDevice != NULL) {
        WdfObjectDelete(QuicIoctlTestCtlDevice);
        QuicIoctlTestCtlDevice = NULL;
    }

    QuicTraceLogVerbose(
        IoControlUninitialized,
        "[ioct] Control interface uninitialized");
}

VOID
QuicIoctlTestCtlEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        Status = STATUS_NOT_SUPPORTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "IOCTL not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    switch (IoControlCode) {
    case IOCTL_QUIC_TEST_IOCTL_INTERFACE_INITIALIZE_LIBRARY:
        if (MsQuic != nullptr) {
            Status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        MsQuic = new MsQuicApi;
        if (MsQuic == nullptr) {
            Status = STATUS_NO_MEMORY;
            break;
        }
        if (QUIC_FAILED(Status = MsQuic->GetInitStatus())) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "MsQuicOpen");
            goto Error;
        }
        break;
    case IOCTL_QUIC_TEST_IOCTL_INTERFACE_UNINITIALIZE_LIBRARY:
        delete MsQuic;
        MsQuic = nullptr;
        break;
    default:
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            IoGetFunctionCodeFromCtlCode(IoControlCode),
            "Invalid FunctionCode");
        break;
    }

Error:

    WdfRequestComplete(Request, Status);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(Queue);
}
