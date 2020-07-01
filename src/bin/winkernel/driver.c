/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Main entry point to the MsQuic.sys driver.

--*/

#include "quic_platform.h"
#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "driver.c.clog.h"
#endif

INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLoad(
    void
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUnload(
    void
    );

INITCODE DRIVER_INITIALIZE DriverEntry;
PAGEDX EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

INITCODE
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    A success status as determined by NT_SUCCESS macro, if successful.

--*/
{
    NTSTATUS Status;
    WDF_DRIVER_CONFIG Config;
    WDFDRIVER Driver;

    QuicPlatformSystemLoad(DriverObject, RegistryPath);

    MsQuicLibraryLoad();

    //
    // Create the WdfDriver Object.
    //
    WDF_DRIVER_CONFIG_INIT(&Config, NULL);
    Config.EvtDriverUnload = EvtDriverUnload;
    Config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    Config.DriverPoolTag = QUIC_POOL_TAG;

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
            "WdfDriverCreate");
        goto Error;
    }

Error:

    if (!NT_SUCCESS(Status)) {
        MsQuicLibraryUnload();
        QuicPlatformSystemUnload();
    }

    return Status;
}

PAGEDX
_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
EvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
/*++

Routine Description:

    EvtDriverUnload will clean up any resources that were allocated for this
    driver.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

--*/
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();
    MsQuicLibraryUnload();
    QuicPlatformSystemUnload();
}
