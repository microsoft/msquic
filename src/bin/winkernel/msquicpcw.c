#include <wdm.h>
#include <ip2string.h>
#include "msquic.h"
#include "quic_platform_winkernel.h"

#pragma code_seg(push, "PAGE")

EXTERN_C DECLSPEC_SELECTANY PPCW_REGISTRATION MsQuicPcwGlobal = NULL;

EXTERN_C FORCEINLINE VOID
MsQuicPcwInitRegistrationInformationGlobal(
    __in_opt PPCW_CALLBACK Callback,
    __in_opt PVOID CallbackContext,
    __out PCW_REGISTRATION_INFORMATION* RegInfo
)
{
    static const UNICODE_STRING Name = RTL_CONSTANT_STRING(L"QUIC Performance Diagnostics");
    static const PCW_COUNTER_DESCRIPTOR Descriptors[] = {
        { 0, 0, QUIC_PERF_COUNTER_CONN_CREATED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_APP_REJECT * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_RESUMED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_ACTIVE * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_CONNECTED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_NO_ALPN * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_STRM_ACTIVE * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_PKTS_DROPPED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_RECV * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_SEND * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_RECV_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_SEND_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_RECV_EVENTS * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_UDP_SEND_CALLS * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_APP_SEND_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_APP_RECV_BYTES * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_OPER_QUEUED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_CONN_OPER_COMPLETED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_WORK_OPER_QUEUED * sizeof(int64_t), sizeof(int64_t)},
        { 0, 0, QUIC_PERF_COUNTER_WORK_OPER_COMPLETED * sizeof(int64_t), sizeof(int64_t)},
    };

    static_assert(sizeof(Descriptors) / sizeof(PCW_COUNTER_DESCRIPTOR) == QUIC_PERF_COUNTER_MAX, "Count must match");

    PAGED_CODE();

    RtlZeroMemory(RegInfo, sizeof(*RegInfo));
    RegInfo->Version = PCW_CURRENT_VERSION;
    RegInfo->Name = &Name;
    RegInfo->CounterCount = RTL_NUMBER_OF(Descriptors);
    RegInfo->Counters = (PCW_COUNTER_DESCRIPTOR*)Descriptors;
    RegInfo->Callback = Callback;
    RegInfo->CallbackContext = CallbackContext;
}

EXTERN_C FORCEINLINE NTSTATUS
MsQuicPcwRegisterGlobal(
    __in_opt PPCW_CALLBACK Callback,
    __in_opt PVOID CallbackContext
)
{
    PCW_REGISTRATION_INFORMATION RegInfo;

    PAGED_CODE();

    MsQuicPcwInitRegistrationInformationGlobal(Callback, CallbackContext, &RegInfo);

    return PcwRegister(&MsQuicPcwGlobal, &RegInfo);
}

EXTERN_C FORCEINLINE VOID
MsQuicPcwUnregisterGlobal(
    VOID
)
{
    PAGED_CODE();

    PcwUnregister(MsQuicPcwGlobal);
}

EXTERN_C __inline NTSTATUS
MsQuicPcwAddGlobal(
    __in PPCW_BUFFER Buffer,
    __in PCUNICODE_STRING Name,
    __in ULONG Id,
    __in_opt const void* Global
)
{
    PCW_DATA Data[1];

    PAGED_CODE();

    Data[0].Data = Global;
    Data[0].Size = QUIC_PERF_COUNTER_MAX * sizeof(int64_t);

    return PcwAddInstance(Buffer,
        Name,
        Id,
        1,
        Data);
}

#pragma code_seg(pop)

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


    UNREFERENCED_PARAMETER(Context);
    ASSERT(Context == NULL);

    RtlInitUnicodeString(&UnicodeName, L"default");

    switch (Type) {
    case PcwCallbackEnumerateInstances:
        Status =
            MsQuicPcwAddGlobal(
                Info->EnumerateInstances.Buffer,
                &UnicodeName,
                0,
                NULL);
        break;
    case PcwCallbackCollectData:
        int64_t Buffer[QUIC_PERF_COUNTER_MAX];
        QuicLibrarySumPerfCountersExternal((uint8_t*)Buffer, sizeof(Buffer));

        Status =
            MsQuicPcwAddGlobal(
                Info->CollectData.Buffer,
                &UnicodeName,
                0,
                Buffer);
        break;
        
    }

    return Status;
}

static BOOLEAN MsQuicGlobalCountersRegistered = FALSE;

_No_competing_thread_
INITCODE
NTSTATUS
MsQuicPcwStartup(
    void
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    Status = MsQuicPcwRegisterGlobal(MsQuicPcwGlobalCallback, NULL);
    if (NT_SUCCESS(Status)) {
        MsQuicGlobalCountersRegistered = TRUE;
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
        MsQuicPcwUnregisterGlobal();
        MsQuicGlobalCountersRegistered = FALSE;
    }
}

