/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Perf Helpers

--*/

#pragma once

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1 // For self-signed cert API
#endif

#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // For disabling encryption
#define QUIC_API_ENABLE_PREVIEW_FEATURES  1 // For CIBIR extension

#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_hashtable.h"
#include "quic_trace.h"
#include "msquic.hpp"
#include "msquichelper.h"

#ifndef _KERNEL_MODE
#include <stdlib.h>
#include <stdio.h>
#endif

#define PERF_ALPN                           "perf"
#define PERF_DEFAULT_PORT                   4433
#define PERF_DEFAULT_DISCONNECT_TIMEOUT     (10 * 1000)
#define PERF_DEFAULT_IDLE_TIMEOUT           (30 * 1000)
#define PERF_DEFAULT_CONN_FLOW_CONTROL      0x8000000
#define PERF_DEFAULT_STREAM_COUNT           10000
#define PERF_DEFAULT_SEND_BUFFER_SIZE       0x20000
#define PERF_DEFAULT_IO_SIZE                0x10000

#define PERF_MAX_THREAD_COUNT               128
#define PERF_MAX_REQUESTS_PER_SECOND        2000000 // best guess - must increase if we can do better

typedef enum TCP_EXECUTION_PROFILE {
    TCP_EXECUTION_PROFILE_LOW_LATENCY,
    TCP_EXECUTION_PROFILE_MAX_THROUGHPUT,
} TCP_EXECUTION_PROFILE;

extern QUIC_EXECUTION_PROFILE PerfDefaultExecutionProfile;
extern TCP_EXECUTION_PROFILE TcpDefaultExecutionProfile;
extern QUIC_CONGESTION_CONTROL_ALGORITHM PerfDefaultCongestionControl;
extern uint8_t PerfDefaultEcnEnabled;
extern uint8_t PerfDefaultQeoAllowed;
extern uint8_t PerfDefaultHighPriority;

extern CXPLAT_DATAPATH* Datapath;

extern
QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ CXPLAT_EVENT* StopEvent,
    _In_opt_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
    );

extern
QUIC_STATUS
QuicMainWaitForCompletion(
    );

extern
void
QuicMainFree(
    );

extern
uint32_t
QuicMainGetExtraDataLength(
    );

extern
void
QuicMainGetExtraData(
    _Out_writes_bytes_(Length) uint8_t* Data,
    _In_ uint32_t Length
    );

inline
const char*
TryGetTarget(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    const char* Target = nullptr;
    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "server", &Target);
    TryGetValue(argc, argv, "to", &Target);
    TryGetValue(argc, argv, "remote", &Target);
    TryGetValue(argc, argv, "peer", &Target);
    return Target;
}

#ifdef _KERNEL_MODE
extern volatile int BufferCurrent;
constexpr int BufferLength = 40 * 1024 * 1024;
extern char Buffer[BufferLength];
#endif // _KERNEL_MODE

inline
int
#ifndef _WIN32
 __attribute__((__format__(__printf__, 1, 2)))
#endif
WriteOutput(
    _In_z_ const char* format
    ...
    )
{
#ifndef _KERNEL_MODE
    va_list args;
    va_start(args, format);
    int rval = vprintf(format, args);
    va_end(args);
    return rval;
#else
    char Buf[512];
    char* BufEnd;
    va_list args;
    va_start(args, format);
    NTSTATUS Status = RtlStringCbVPrintfExA(Buf, sizeof(Buf), &BufEnd, nullptr, 0, format, args);
    va_end(args);

    if (Status == STATUS_INVALID_PARAMETER) {
        // Write error
        Status = RtlStringCbPrintfExA(Buf, sizeof(Buf), &BufEnd, nullptr, 0, "Invalid Format: %s\n", format);
        if (Status != STATUS_SUCCESS) {
            return 0;
        }
    }

    int Length = (int)(BufEnd - Buf);
    int End = InterlockedAdd((volatile LONG*)&BufferCurrent, Length);
    if (End > BufferLength) {
        return 0;
    }
    int Start = End - Length;
    CxPlatCopyMemory(Buffer + Start, Buf, Length);


    return Length;
#endif
}

inline
void
QuicPrintConnectionStatistics(
    _In_ const QUIC_API_TABLE* ApiTable,
    _In_ HQUIC Connection
    )
{
    QUIC_STATISTICS_V2 Stats;
    uint32_t StatsSize = sizeof(Stats);
    ApiTable->GetParam(Connection, QUIC_PARAM_CONN_STATISTICS_V2, &StatsSize, &Stats);
    WriteOutput(
        "Connection Statistics:\n"
        "  RTT                       %u us\n"
        "  MinRTT                    %u us\n"
        "  EcnCapable                %u\n"
        "  SendTotalPackets          %llu\n"
        "  SendSuspectedLostPackets  %llu\n"
        "  SendSpuriousLostPackets   %llu\n"
        "  SendCongestionCount       %u\n"
        "  SendEcnCongestionCount    %u\n"
        "  RecvTotalPackets          %llu\n"
        "  RecvReorderedPackets      %llu\n"
        "  RecvDroppedPackets        %llu\n"
        "  RecvDuplicatePackets      %llu\n"
        "  RecvDecryptionFailures    %llu\n",
        Stats.Rtt,
        Stats.MinRtt,
        Stats.EcnCapable,
        (unsigned long long)Stats.SendTotalPackets,
        (unsigned long long)Stats.SendSuspectedLostPackets,
        (unsigned long long)Stats.SendSpuriousLostPackets,
        Stats.SendCongestionCount,
        Stats.SendEcnCongestionCount,
        (unsigned long long)Stats.RecvTotalPackets,
        (unsigned long long)Stats.RecvReorderedPackets,
        (unsigned long long)Stats.RecvDroppedPackets,
        (unsigned long long)Stats.RecvDuplicatePackets,
        (unsigned long long)Stats.RecvDecryptionFailures);
}

inline
void
QuicPrintStreamStatistics(
    _In_ const QUIC_API_TABLE* ApiTable,
    _In_ HQUIC Stream
    )
{
    QUIC_STREAM_STATISTICS Stats = {0};
    uint32_t BufferLength = sizeof(Stats);
    ApiTable->GetParam(Stream, QUIC_PARAM_STREAM_STATISTICS, &BufferLength, &Stats);
    WriteOutput(
        "Stream Timings (flow blocked):\n"
        "  SCHEDULING:               %llu us\n"
        "  PACING:                   %llu us\n"
        "  AMPLIFICATION_PROT:       %llu us\n"
        "  CONGESTION_CONTROL:       %llu us\n"
        "  CONN_FLOW_CONTROL:        %llu us\n"
        "  STREAM_ID_FLOW_CONTROL:   %llu us\n"
        "  STREAM_FLOW_CONTROL:      %llu us\n"
        "  APP:                      %llu us\n",
        (unsigned long long)Stats.ConnBlockedBySchedulingUs,
        (unsigned long long)Stats.ConnBlockedByPacingUs,
        (unsigned long long)Stats.ConnBlockedByAmplificationProtUs,
        (unsigned long long)Stats.ConnBlockedByCongestionControlUs,
        (unsigned long long)Stats.ConnBlockedByFlowControlUs,
        (unsigned long long)Stats.StreamBlockedByIdFlowControlUs,
        (unsigned long long)Stats.StreamBlockedByFlowControlUs,
        (unsigned long long)Stats.StreamBlockedByAppUs);
}
