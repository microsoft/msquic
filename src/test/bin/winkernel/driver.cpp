/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Test Driver

--*/

#include <quic_platform.h>
#include <MsQuicTests.h>

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "driver.cpp.clog.h"
#endif

#define QUIC_TEST_TAG 'tsTQ' // QTst

EVT_WDF_DRIVER_UNLOAD QuicTestDriverUnload;

_No_competing_thread_
INITCODE
NTSTATUS
QuicTestCtlInitialize(
    _In_ WDFDRIVER Driver
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
QuicTestCtlUninitialize(
    );

void* __cdecl operator new (size_t Size) {
    return ExAllocatePoolWithTag(NonPagedPool, Size, QUIC_TEST_TAG);
}

void __cdecl operator delete (_In_opt_ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_TEST_TAG);
    }
}

void __cdecl operator delete (_In_opt_ void* Mem, _In_opt_ size_t) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_TEST_TAG);
    }
}

void* __cdecl operator new[] (size_t Size) {
    return ExAllocatePoolWithTag(NonPagedPool, Size, QUIC_TEST_TAG);
}

void __cdecl operator delete[] (_In_opt_ void* Mem) {
    if (Mem != nullptr) {
        ExFreePoolWithTag(Mem, QUIC_TEST_TAG);
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
    Config.EvtDriverUnload = QuicTestDriverUnload;
    Config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    Config.DriverPoolTag = QUIC_TEST_TAG;

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
    Status = QuicTestCtlInitialize(Driver);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicTestCtlInitialize failed");
        goto Error;
    }

    QuicTestInitialize();

    QuicTraceLogInfo(
        TestDriverStarted,
        "[test] Started");

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
QuicTestDriverUnload(
    _In_ WDFDRIVER Driver
    )
/*++

Routine Description:

    QuicTestDriverUnload will clean up any resources that were allocated for
    this driver.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

--*/
{
    UNREFERENCED_PARAMETER(Driver);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    QuicTestUninitialize();

    QuicTestCtlUninitialize();

    QuicTraceLogInfo(
        TestDriverStopped,
        "[test] Stopped");

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
}

