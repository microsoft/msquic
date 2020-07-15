/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Perf Driver

--*/

#include <quic_platform.h>

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "control.cpp.clog.h"
#endif

#include "quic_driver_run.h"

DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\quicperformance");
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\quicperformance");

typedef struct QUIC_DEVICE_EXTENSION {
    EX_PUSH_LOCK Lock;

    _Guarded_by_(Lock)
        LIST_ENTRY ClientList;
    ULONG ClientListSize;

} QUIC_DEVICE_EXTENSION;

_No_competing_thread_
INITCODE
NTSTATUS
QuicTestCtlInitialize(
    _In_ WDFDRIVER /*Driver*/
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    QUIC_EVENT A, B;

    QuicMain(0, nullptr, A, B);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
QuicTestCtlUninitialize(
)
{
}
