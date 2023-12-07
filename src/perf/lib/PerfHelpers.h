/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic API Perf Helpers

--*/

#pragma once

#ifdef QUIC_CLOG
#include "PerfHelpers.h.clog.h"
#endif

#ifndef _KERNEL_MODE
#define QUIC_TEST_APIS 1 // For self-signed cert API
#endif

#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // For disabling encryption
#define QUIC_API_ENABLE_PREVIEW_FEATURES  1 // For CIBIR extension

#include "quic_platform.h"
#include "quic_trace.h"
#include "msquic.hpp"
#include "msquichelper.h"
#include "quic_hashtable.h"
#include "Tcp.h"

#ifndef _KERNEL_MODE
#include <stdlib.h>
#include <stdio.h>
#endif

extern
QUIC_STATUS
QuicMainStart(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ CXPLAT_EVENT* StopEvent,
    _In_ const QUIC_CREDENTIAL_CONFIG* SelfSignedCredConfig
    );

extern
void
QuicMainStop(
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
QUIC_STATUS
QuicMainGetExtraData(
    _Out_writes_bytes_(Length) uint8_t* Data,
    _In_ uint32_t Length
    );

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
    char Buf[256];
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
    QUIC_STATISTICS_V2 Statistics;
    uint32_t StatsSize = sizeof(Statistics);
    if (QUIC_SUCCEEDED(
        ApiTable->GetParam(
            Connection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &StatsSize,
            &Statistics))) {
        WriteOutput(
            "[conn][%p] STATS: EcnCapable=%u RTT=%u us SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu SendCongestionCount=%u SendEcnCongestionCount=%u RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu\n",
            Connection,
            Statistics.EcnCapable,
            Statistics.Rtt,
            (unsigned long long)Statistics.SendTotalPackets,
            (unsigned long long)Statistics.SendSuspectedLostPackets,
            (unsigned long long)Statistics.SendSpuriousLostPackets,
            Statistics.SendCongestionCount,
            Statistics.SendEcnCongestionCount,
            (unsigned long long)Statistics.RecvTotalPackets,
            (unsigned long long)Statistics.RecvReorderedPackets,
            (unsigned long long)Statistics.RecvDroppedPackets,
            (unsigned long long)Statistics.RecvDuplicatePackets,
            (unsigned long long)Statistics.RecvDecryptionFailures);
    }
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
    WriteOutput("Flow blocked timing:\n");
    WriteOutput("SCHEDULING:             %llu us\n",
        (unsigned long long)Stats.ConnBlockedBySchedulingUs);
    WriteOutput("PACING:                 %llu us\n",
        (unsigned long long)Stats.ConnBlockedByPacingUs);
    WriteOutput("AMPLIFICATION_PROT:     %llu us\n",
        (unsigned long long)Stats.ConnBlockedByAmplificationProtUs);
    WriteOutput("CONGESTION_CONTROL:     %llu us\n",
        (unsigned long long)Stats.ConnBlockedByCongestionControlUs);
    WriteOutput("CONN_FLOW_CONTROL:      %llu us\n",
        (unsigned long long)Stats.ConnBlockedByFlowControlUs);
    WriteOutput("STREAM_ID_FLOW_CONTROL: %llu us\n",
        (unsigned long long)Stats.StreamBlockedByIdFlowControlUs);
    WriteOutput("STREAM_FLOW_CONTROL:    %llu us\n",
        (unsigned long long)Stats.StreamBlockedByFlowControlUs);
    WriteOutput("APP:                    %llu us\n",
        (unsigned long long)Stats.StreamBlockedByAppUs);
}
