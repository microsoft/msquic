/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Performance Counter V2 API Interface for MsQuic.

--*/


//
// N.B. The Headers MUST be in this order to correctly compile
//
#include "quic_platform.h"
#include <wdm.h>
#include <ip2string.h>
#include "msquic.h"
#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "msquicpcw.c.clog.h"
#endif

static PPCW_REGISTRATION MsQuicPcwGlobal = NULL;
static BOOLEAN MsQuicGlobalCountersRegistered = FALSE;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCountersExternal(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MsQuicPcwGlobalCallback(
    _In_ PCW_CALLBACK_TYPE Type,
    _In_ PPCW_CALLBACK_INFORMATION Info,
    _In_opt_ PVOID Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING UnicodeName;
    PCW_DATA Data;

    UNREFERENCED_PARAMETER(Context);
    ASSERT(Context == NULL);

    RtlInitUnicodeString(&UnicodeName, L"default");

    switch (Type) {
    case PcwCallbackEnumerateInstances:
        Data.Data = NULL;
        Data.Size = QUIC_PERF_COUNTER_MAX * sizeof(int64_t);

        Status =
            PcwAddInstance(
                Info->CollectData.Buffer,
                &UnicodeName,
                0,
                1,
                &Data);
        break;
    case PcwCallbackCollectData:
        int64_t Buffer[QUIC_PERF_COUNTER_MAX];
        QuicLibrarySumPerfCountersExternal((uint8_t*)Buffer, sizeof(Buffer));

        Data.Data = Buffer;
        Data.Size = sizeof(Buffer);

        Status =
            PcwAddInstance(
                Info->CollectData.Buffer,
                &UnicodeName,
                0,
                1,
                &Data);
        break;
    }

    return Status;
}

_No_competing_thread_
INITCODE
NTSTATUS
MsQuicPcwStartup(
    void
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCW_REGISTRATION_INFORMATION RegInfo;

    PAGED_CODE();

    static const UNICODE_STRING Name = RTL_CONSTANT_STRING(L"QUIC Performance Diagnostics");
    static const PCW_COUNTER_DESCRIPTOR Descriptors[] = {
        { 0, 0, QUIC_PERF_COUNTER_CONN_CREATED * sizeof(int64_t), sizeof(int64_t)},
        { 1, 0, QUIC_PERF_COUNTER_CONN_CREATED * sizeof(int64_t), sizeof(int64_t)},
        { 2, 0, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL * sizeof(int64_t), sizeof(int64_t)},
        { 3, 0, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL * sizeof(int64_t), sizeof(int64_t)},
        { 4, 0, QUIC_PERF_COUNTER_CONN_APP_REJECT * sizeof(int64_t), sizeof(int64_t)},
        { 5, 0, QUIC_PERF_COUNTER_CONN_APP_REJECT * sizeof(int64_t), sizeof(int64_t)},
        { 6, 0, QUIC_PERF_COUNTER_CONN_RESUMED * sizeof(int64_t), sizeof(int64_t)},
        { 7, 0, QUIC_PERF_COUNTER_CONN_RESUMED * sizeof(int64_t), sizeof(int64_t)},
        { 8, 0, QUIC_PERF_COUNTER_CONN_ACTIVE * sizeof(int64_t), sizeof(int64_t)},
        { 9, 0, QUIC_PERF_COUNTER_CONN_CONNECTED * sizeof(int64_t), sizeof(int64_t)},
        { 10, 0, QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS * sizeof(int64_t), sizeof(int64_t)},
        { 11, 0, QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS * sizeof(int64_t), sizeof(int64_t)},
        { 12, 0, QUIC_PERF_COUNTER_CONN_NO_ALPN * sizeof(int64_t), sizeof(int64_t)},
        { 13, 0, QUIC_PERF_COUNTER_CONN_NO_ALPN * sizeof(int64_t), sizeof(int64_t)},
        { 14, 0, QUIC_PERF_COUNTER_STRM_ACTIVE * sizeof(int64_t), sizeof(int64_t)},
        { 15, 0, QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST * sizeof(int64_t), sizeof(int64_t)},
        { 16, 0, QUIC_PERF_COUNTER_PKTS_DROPPED * sizeof(int64_t), sizeof(int64_t)},
        { 17, 0, QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL * sizeof(int64_t), sizeof(int64_t)},
        { 18, 0, QUIC_PERF_COUNTER_UDP_RECV * sizeof(int64_t), sizeof(int64_t)},
        { 19, 0, QUIC_PERF_COUNTER_UDP_SEND * sizeof(int64_t), sizeof(int64_t)},
        { 20, 0, QUIC_PERF_COUNTER_UDP_RECV_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 21, 0, QUIC_PERF_COUNTER_UDP_SEND_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 22, 0, QUIC_PERF_COUNTER_UDP_RECV_EVENTS * sizeof(int64_t), sizeof(int64_t)},
        { 23, 0, QUIC_PERF_COUNTER_UDP_SEND_CALLS * sizeof(int64_t), sizeof(int64_t)},
        { 24, 0, QUIC_PERF_COUNTER_APP_SEND_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 25, 0, QUIC_PERF_COUNTER_APP_RECV_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 26, 0, QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 27, 0, QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 28, 0, QUIC_PERF_COUNTER_CONN_OPER_QUEUED * sizeof(int64_t), sizeof(int64_t)},
        { 29, 0, QUIC_PERF_COUNTER_CONN_OPER_COMPLETED * sizeof(int64_t), sizeof(int64_t)},
        { 30, 0, QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 31, 0, QUIC_PERF_COUNTER_WORK_OPER_QUEUED * sizeof(int64_t), sizeof(int64_t)},
        { 32, 0, QUIC_PERF_COUNTER_WORK_OPER_COMPLETED * sizeof(int64_t), sizeof(int64_t)},
        { 33, 0, QUIC_PERF_COUNTER_PATH_VALIDATED * sizeof(int64_t), sizeof(int64_t)},
        { 34, 0, QUIC_PERF_COUNTER_PATH_FAILURE * sizeof(int64_t), sizeof(int64_t)},
        { 35, 0, QUIC_PERF_COUNTER_SEND_STATELESS_RESET * sizeof(int64_t), sizeof(int64_t)},
        { 36, 0, QUIC_PERF_COUNTER_SEND_STATELESS_RETRY * sizeof(int64_t), sizeof(int64_t)},
    };

    RtlZeroMemory(&RegInfo, sizeof(RegInfo));
    RegInfo.Version = PCW_CURRENT_VERSION;
    RegInfo.Name = &Name;
    RegInfo.CounterCount = RTL_NUMBER_OF(Descriptors);
    RegInfo.Counters = (PCW_COUNTER_DESCRIPTOR*)Descriptors;
    RegInfo.Callback = MsQuicPcwGlobalCallback;
    RegInfo.CallbackContext = NULL;

    Status = PcwRegister(&MsQuicPcwGlobal, &RegInfo);
    if (NT_SUCCESS(Status)) {
        MsQuicGlobalCountersRegistered = TRUE;
    } else {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "PcwRegister");
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicPcwCleanup(
    void
    )
{
    if (MsQuicGlobalCountersRegistered) {
        PcwUnregister(MsQuicPcwGlobal);
        MsQuicGlobalCountersRegistered = FALSE;
    }
}
