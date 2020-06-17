/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

BOOLEAN QjEndCxn = FALSE;

const char* PacktTypeQLogStr[] = {
    "version_negotiation",
    "initial",
    "0RTT",
    "handshake",
    "retry",
    "1RTT"
};

void __cdecl FreeCxn(_In_opt_ void* Mem);
OBJECT_SET Cxns = {FreeCxn, 0};

int __cdecl CompareCxnAgeFn(const void* Cxn1, const void* Cxn2)
{
    CXN* a = (*((CXN**)Cxn1));
    CXN* b = (*((CXN**)Cxn2));
    ULONG64 age1 = a->FinalTimestamp - a->InitialTimestamp;
    ULONG64 age2 = b->FinalTimestamp - b->InitialTimestamp;
    return (age1 > age2) ? -1 : ((age1 == age2) ? 0 : 1);
}

int __cdecl CompareCxnCpuActiveFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->SchedulingStats[QUIC_SCHEDULE_PROCESSING].TotalCpuTime;
    ULONG64 b = (*((CXN**)Cxn2))->SchedulingStats[QUIC_SCHEDULE_PROCESSING].TotalCpuTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareCxnCpuQueuedFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->SchedulingStats[QUIC_SCHEDULE_QUEUED].TotalCpuTime;
    ULONG64 b = (*((CXN**)Cxn2))->SchedulingStats[QUIC_SCHEDULE_QUEUED].TotalCpuTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareCxnCpuIdleFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->SchedulingStats[QUIC_SCHEDULE_IDLE].TotalCpuTime;
    ULONG64 b = (*((CXN**)Cxn2))->SchedulingStats[QUIC_SCHEDULE_IDLE].TotalCpuTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareCxnTxFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->BytesSent;
    ULONG64 b = (*((CXN**)Cxn2))->BytesSent;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareCxnRxFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->BytesReceived;
    ULONG64 b = (*((CXN**)Cxn2))->BytesReceived;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareCxnShutdownTimeFn(const void* Cxn1, const void* Cxn2)
{
    ULONG64 a = (*((CXN**)Cxn1))->ShutdownTimestamp;
    ULONG64 b = (*((CXN**)Cxn2))->ShutdownTimestamp;
    return (a < b) ? -1 : ((a == b) ? 0 : 1);
}

int (__cdecl * CxnSortFns[])(const void *, const void *) = {
    NULL,
    CompareCxnAgeFn,
    CompareCxnCpuActiveFn,
    CompareCxnCpuQueuedFn,
    CompareCxnCpuIdleFn,
    CompareCxnTxFn,
    CompareCxnRxFn,
    NULL,
    CompareCxnShutdownTimeFn
};

void
QjCxnEventStart(
    _In_ CXN* Cxn,
    _In_ PEVENT_RECORD ev,
    _In_z_ const char* category,
    _In_z_ const char* event
    )
{
    QjArrayArrayStart(Qj);
    QjArrayWriteInt(Qj, NS100_TO_US(ev->EventHeader.TimeStamp.QuadPart - Cxn->InitialTimestamp) / 1000);
    QjArrayWriteString(Qj, category);
    QjArrayWriteString(Qj, event);
    // Caller writes 'data'
}

void
QjCxnEventEnd(
    void
    )
{
    QjArrayEnd(Qj);
}

CXN*
NewCxn(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_CONNECTION* EvData = (QUIC_EVENT_DATA_CONNECTION*)ev->UserData;

    // Move the old CXN out of the set if this pointer is being reused.
    CXN* Cxn = (CXN*)ObjectSetRemoveActive(&Cxns, EvData->CxnPtr);
    if (Cxn != NULL) {
        Cxn->Destroyed = TRUE;
    }

    Cxn = malloc(sizeof(CXN));
    if (Cxn == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Cxn, 0, sizeof(*Cxn));
    Cxn->Id = Cxns.NextId++;
    Cxn->Ptr = EvData->CxnPtr;
    Cxn->ShutdownTimestamp = ULLONG_MAX;
    Cxn->CorrelationId = ULLONG_MAX;
    Cxn->IsServer = TRI_UNKNOWN;
    Cxn->HandshakeStarted = TRI_UNKNOWN;
    Cxn->HandshakeCompleted = TRI_UNKNOWN;
    Cxn->Shutdown = TRI_UNKNOWN;
    Cxn->InitialProcessor = UCHAR_MAX;
    Cxn->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    for (int i = 0; i < QUIC_SCHEDULE_MAX; ++i) {
        InitCpuTime(&Cxn->SchedulingStats[i]);
    }
    ObjectSetAddActive(&Cxns, (OBJECT*)Cxn);
    if (Qj && Cmd.SelectedId == Cxn->Id) {
        if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnCreated ||
            GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnRundown) {
            Cxn->IsServer = EvData->Created.IsServer ? TRI_TRUE : TRI_FALSE;
        }
        QjArrayObjectStart(Qj);
        QjObjectStart(Qj, "vantage_point");
        switch (Cxn->IsServer) {
            case TRI_FALSE: QjWriteString(Qj, "type", "CLIENT"); break;
            case TRI_TRUE:  QjWriteString(Qj, "type", "SERVER"); break;
            default:        QjWriteString(Qj, "type", "UNKNOWN"); break;
        }
        QjObjectEnd(Qj);
        QjObjectStart(Qj, "common_fields");
        if (Cxn->CorrelationId != ULLONG_MAX) {
            QjWriteStringInt(Qj, "group_id", Cxn->CorrelationId);
        }
        // protocol_type ?
        // reference_time ?
        QjObjectEnd(Qj);
        QjArrayStart(Qj, "event_fields");
        QjArrayWriteString(Qj, "relative_time");
        QjArrayWriteString(Qj, "CATEGORY");
        QjArrayWriteString(Qj, "EVENT_TYPE");
        QjArrayWriteString(Qj, "DATA");
        QjArrayEnd(Qj);
        QjArrayStart(Qj, "events");
        QjEndCxn = TRUE;
    }
    return Cxn;
}

void
__cdecl
FreeCxn(
    _In_opt_ void* Mem
    )
{
    if (Mem != NULL) {
        CXN* Cxn = (CXN*)Mem;
        while (Cxn->SrcCids) {
            CID* Cid = Cxn->SrcCids;
            Cxn->SrcCids = Cxn->SrcCids->Next;
            free(Cid);
        }
        while (Cxn->DestCids) {
            CID* Cid = Cxn->DestCids;
            Cxn->DestCids = Cxn->DestCids->Next;
            free(Cid);
        }
        free(Cxn);
    }
}

CXN* GetCxnFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_CONNECTION* EvData = (QUIC_EVENT_DATA_CONNECTION*)ev->UserData;

    CXN* Cxn;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnCreated) {
        Cxn = NewCxn(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnDestroyed) {
        Cxn = (CXN*)ObjectSetRemoveActive(&Cxns, EvData->CxnPtr);
    } else {
        Cxn = (CXN*)ObjectSetGetActive(&Cxns, EvData->CxnPtr);
    }

    if (Cxn == NULL) {
        Cxn = NewCxn(ev);
    }

    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnCreated ||
        GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnRundown) {
        Cxn->CorrelationId = EvData->Created.CorrelationId;
        Cxn->IsServer = EvData->Created.IsServer ? TRI_TRUE : TRI_FALSE;
        Cxn->HandshakeStarted = TRI_FALSE;
        Cxn->HandshakeCompleted = TRI_FALSE;
        Cxn->Shutdown = TRI_FALSE;
        Cxn->InitialProcessor = ev->BufferContext.ProcessorNumber;
    }

    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicConnDestroyed) {
        Cxn->Destroyed = TRUE;
    }

    Cxn->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    if (ev->BufferContext.ProcessorNumber < 64) {
        Cxn->ProcessorBitmap |= (1ull << ev->BufferContext.ProcessorNumber);
        if (Cxn->Worker != NULL && ev->EventHeader.ThreadId == Cxn->Worker->ThreadId) {
            Cxn->Worker->ProcessorBitmap |= (1ull << ev->BufferContext.ProcessorNumber);
        }
    } else {
        printf("WARNING: More than 64 cores not supported by tool!\n");
    }

    return Cxn;
}

CXN* GetCxnFromTlsEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_TLS* EvData = (QUIC_EVENT_DATA_TLS*)ev->UserData;

    CXN* Cxn;
    if ((Cxn = (CXN*)ObjectSetGetActive(&Cxns, EvData->CxnPtr)) == NULL) {
        Cxn = NewCxn(ev);
    }

    if (Cxn != NULL) {
        Cxn->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        if (ev->BufferContext.ProcessorNumber < 64) {
            Cxn->ProcessorBitmap |= (1ull << ev->BufferContext.ProcessorNumber);
            if (Cxn->Worker != NULL && ev->EventHeader.ThreadId == Cxn->Worker->ThreadId) {
                Cxn->Worker->ProcessorBitmap |= (1ull << ev->BufferContext.ProcessorNumber);
            }
        } else {
            printf("WARNING: More than 64 cores not supported by tool!\n");
        }
    }

    return Cxn;
}

const char* CxnShortState(_In_ CXN* Cxn)
{
    if (Cxn->Shutdown == TRI_TRUE) {
        return " SHUTDOWN";
    } else if (Cxn->HandshakeCompleted == TRI_TRUE) {
        return "  CONNECT";
    } else if (Cxn->HandshakeStarted == TRI_TRUE) {
        return "HANDSHAKE";
    } else if (Cxn->HandshakeStarted == TRI_FALSE) {
        return "  CREATED";
    }
    return "  UNKNOWN";
}

/*
    ID     State        Age     Active      Queue       Idle         TX         RX                  Local                 Remote             Source        Destination
                       (us)       (us)       (us)       (us)        (B)        (B)                     IP                     IP                CID                CID
     1   CONNECT      10262       3449        253       6540       3417       2977      10.228.101.54:443   10.228.101.148:50276   980539EF482B15CE   0081ACA53BAA3777
     2   CONNECT       4871       2777        116       1962       2031       2977      10.228.101.54:443   10.228.101.148:50277   E5865654E08FD767   0042CA1037EA0C0B
     3   CONNECT       5241       2669        128       2427       2031       2977      10.228.101.54:443   10.228.101.148:50278   1AE746C27E748386   0043E62A8B8EBB8C
     4   CONNECT       5453       2831        225       2378       2031       2977      10.228.101.54:443   10.228.101.148:50279   426834ED9F012754   00C437DB702918BE
     5   CONNECT       5213       2693        120       2383       2031       2977      10.228.101.54:443   10.228.101.148:50280   4BA9AD36454BE269   0085C40BDABF7C09
     6   CONNECT       4646       2757        142       1728       2031       2977      10.228.101.54:443   10.228.101.148:50281   D74ACAB3ADA763FE   0006FB7E2933A165
     7   CONNECT       5563       2744        147       2654       2031       2977      10.228.101.54:443   10.228.101.148:50282   220B2401DA530AFC   0047429971FD0421
     8   CONNECT       5626       2764        158       2689       2031       2977      10.228.101.54:443   10.228.101.148:50283   DDAC7AB527FA87E8   00C8B6293C55ED5F
     9   CONNECT       5444       2730        162       2536       2031       2977      10.228.101.54:443   10.228.101.148:50284   75CDBEF0873D20C9   0049D58DD89A0F4F
    10   CONNECT       5316       2527        138       2634       2031       2977      10.228.101.54:443   10.228.101.148:50285   A24ED01EB3B5B306   008AA39BA9D4D97E
*/

void OutputCxnOneLineSummary(_In_ CXN* Cxn)
{
    if (++Trace.OutputLineCount > Cmd.MaxOutputLines) {
        return;
    }

    const char* FormatStr = "%6lu %s %10llu %10llu %10llu %10llu %10llu %10llu %22s %22s %18s %18s\n";
    const char* FormatCsvStr = "%lu,%s,%llu,%llu,%llu,%llu,%llu,%llu,%s,%s,%s,%s\n";

    if (!Cmd.FormatCSV && ((Trace.OutputLineCount-1) % 10) == 0) {
        if (Trace.OutputLineCount != 1) printf("\n");
        printf("    ID     State        Age     Active      Queue       Idle         TX         RX                  Local                 Remote             Source        Destination\n");
        printf("                       (us)       (us)       (us)       (us)        (B)        (B)                     IP                     IP                CID                CID\n");
    }

    ULONG64 Age = NS100_TO_US(Cxn->FinalTimestamp - Cxn->InitialTimestamp);

    char LocalAddrStr[INET6_ADDRSTRLEN];
    AddrToString(&Cxn->LocalAddress, LocalAddrStr);
    char RemoteAddrStr[INET6_ADDRSTRLEN];
    AddrToString(&Cxn->RemoteAddress, RemoteAddrStr);

    char SrcCidStr[QUIC_CID_MAX_STR_LEN] = "UNKNOWN";
    if (Cxn->SrcCids != NULL) {
        CidToString(Cxn->SrcCids->Length, Cxn->SrcCids->Buffer, SrcCidStr);
    }
    char DestCidStr[QUIC_CID_MAX_STR_LEN] = "UNKNOWN";
    if (Cxn->DestCids != NULL) {
        CidToString(Cxn->DestCids->Length, Cxn->DestCids->Buffer, DestCidStr);
    }

    printf(
        Cmd.FormatCSV ? FormatCsvStr : FormatStr,
        Cxn->Id, CxnShortState(Cxn), Age,
        Cxn->SchedulingStats[QUIC_SCHEDULE_PROCESSING].TotalCpuTime,
        Cxn->SchedulingStats[QUIC_SCHEDULE_QUEUED].TotalCpuTime,
        Cxn->SchedulingStats[QUIC_SCHEDULE_IDLE].TotalCpuTime,
        Cxn->BytesSent, Cxn->BytesReceived,
        LocalAddrStr, RemoteAddrStr,
        SrcCidStr, DestCidStr);
}

/*
  Time      TX      RX    Rtt   Cong    InFlight        Cwnd       TxBuf         SFC         CFC    SsThresh  CubicK  CubicWinMax   StrmSndWnd
  (ms)  (mbps)  (mbps)   (ms)  Event         (B)         (B)         (B)         (B)         (B)         (B)    (ms)          (B)          (B)
     0       0       0    100      0           0       12800           0           0           0           0       0            0            0
    28      86       0      2      0      133724      134097      434320           0  4294967295  4294967295       0            0            0
    54     203       0      5      0      363654      534954     1429299      139028  4294967295  4294967295       0            0            0
    79     188       0      6      0      446016     1011018     2719776      611381  4294967295  4294967295       0            0            0
   105     188       0      6      0       62908     2013696     2287325           0  4294967295  4294967295       0            0            0
   131     343       0      7      0     1108416     2013696     2897186      575268  4294967295  4294967295       0            0            0
   156     311       0      9      0      915584     2240384     2838345     1108733  4294967295  4294967295       0            0            0
   182     279       0      9      0      752192     2252160     2922883     1359809  4294967295  4294967295       0            0            0
   210     324       0     13      0     1152576     2252160     3051800      639758  4294967295  4294967295       0            0            0
   235     291       0     11      0      522560     2328704     3066292      849013  4294967295  4294967295       0            0            0
*/

void OutputCxnTputSample(_In_ CXN* Cxn)
{
    if (Cxn->LastTraceSampleTimestamp + Cmd.OutputResolution >= Cxn->FinalTimestamp) {
        return;
    }

    if (++Trace.OutputLineCount > Cmd.MaxOutputLines) {
        return;
    }

    ULONG64 ElapsedUs = NS100_TO_US(Cxn->FinalTimestamp - Cxn->LastTraceSampleTimestamp);
    Cxn->LastTraceSampleTimestamp = Cxn->FinalTimestamp;

    if (!Cmd.FormatCSV) {

        if ((Trace.OutputLineCount-1 % 10) == 0) {
            if (Trace.OutputLineCount != 1) printf("\n");
            printf("  Time      TX      RX    Rtt   Cong    InFlight        Cwnd       TxBuf         SFC         CFC    SsThresh  CubicK  CubicWinMax   StrmSndWnd\n");
            printf("  (ms)  (mbps)  (mbps)   (ms)  Event         (B)         (B)         (B)         (B)         (B)         (B)    (ms)          (B)          (B)\n");
        }

        const char* FormatStr = "%6u %7u %7u %6u %6u %11u %11u %11u %11u %11u %11u %7u %12u %12u\n";
        printf(
            FormatStr,
            (ULONG)NS100_TO_MS(Cxn->FinalTimestamp - Cxn->InitialTimestamp),
            (ULONG)(8 * (Cxn->BytesSent - Cxn->LastBytesSent) / ElapsedUs),
            (ULONG)(8 * (Cxn->BytesReceived - Cxn->LastBytesReceived) / ElapsedUs),
            US_TO_MS(Cxn->SmoothedRtt),
            Cxn->CongestionEvents,
            Cxn->BytesInFlight,
            Cxn->CongestionWindow,
            CAP_TO_32(Cxn->TxBufBytes),
            CAP_TO_32(Cxn->StreamFlowAvailable),
            CAP_TO_32(Cxn->ConnFlowAvailable),
            Cxn->SlowStartThreshold,
            Cxn->CubicK,
            Cxn->CubicWindowMax,
            Cxn->StreamSendWindow
            );

    } else {
        const char* FormatStr = "%llu,%llu,%llu,%u,%u,%u,%u,%llu,%llu,%llu,%u,%u,%u,%u\n";
        printf(
            FormatStr,
            NS100_TO_MS(Cxn->FinalTimestamp - Cxn->InitialTimestamp),
            8 * (Cxn->BytesSent - Cxn->LastBytesSent) / ElapsedUs,
            8 * (Cxn->BytesReceived - Cxn->LastBytesReceived) / ElapsedUs,
            US_TO_MS(Cxn->SmoothedRtt),
            Cxn->CongestionEvents,
            Cxn->BytesInFlight,
            Cxn->CongestionWindow,
            Cxn->TxBufBytes,
            Cxn->StreamFlowAvailable,
            Cxn->ConnFlowAvailable,
            Cxn->SlowStartThreshold,
            Cxn->CubicK,
            Cxn->CubicWindowMax,
            Cxn->StreamSendWindow
            );
    }

    Cxn->LastBytesSent = Cxn->BytesSent;
    Cxn->LastBytesReceived = Cxn->BytesReceived;
    Cxn->SampleInRecovery = Cxn->InRecovery;
    Cxn->CongestionEvents = 0;
}

/*
CONNECTION    1CBF79F6240

  CorrelationId  8
  IsServer       FALSE
  Age            2237.843 ms
  LocalAddr      127.0.0.1:59681
  RemoteAddr     127.0.0.1:59680
  SrcCids        null
  DestCids       DE01F0BA9EB362D3
                 DEA4F0340DD551C2
  State          Shutdown (app) err=1 (rem=0)

  Streams        1CBF76FD590 (#0) (id 46)

  InitalProc     5
  Worker         1CBF76F2650 (id 78)

  CPU
    Processors   0xFFE
    Processing   2.31 s (avg 3.615 ms, min 0 us, max 14.446 ms)
    Queued       11.385 ms (avg 20 us, min 0 us, max 243 us)
    Idle         193.892 ms (avg 515 us, min 1 us, max 6.963 ms)

  RTT            1.890 ms
  TX             103070731 bytes
  RX             102041922 bytes
  CcEvents       8 | 0 (persistent)
*/

void OutputCxnSummary(_In_ CXN* Cxn)
{
    char LocalAddrStr[INET6_ADDRSTRLEN];
    char RemoteAddrStr[INET6_ADDRSTRLEN];
    ULONG64 Age = NS100_TO_US(Cxn->FinalTimestamp - Cxn->InitialTimestamp);

    AddrToString(&Cxn->LocalAddress, LocalAddrStr);
    AddrToString(&Cxn->RemoteAddress, RemoteAddrStr);

    char StateStr[64] = "Unknown";
    if (Cxn->Shutdown == TRI_TRUE) {
        if (Cxn->ShutdownIsApp) {
            sprintf_s(StateStr, sizeof(StateStr), "Shutdown (app) err=%llu (rem=%hu)",
                Cxn->ShutdownErrorCode, (UINT16)Cxn->ShutdownIsRemote);
        } else {
            if (Cxn->ShutdownIsQuicStatus) {
                sprintf_s(StateStr, sizeof(StateStr), "Shutdown status=%u (rem=%hu)",
                    (UINT32)Cxn->ShutdownErrorCode, (UINT16)Cxn->ShutdownIsRemote);
            } else {
                sprintf_s(StateStr, sizeof(StateStr), "Shutdown %s (%llu) (rem=%hu)",
                    QuicErrorToString(Cxn->ShutdownErrorCode),
                    Cxn->ShutdownErrorCode, (UINT16)Cxn->ShutdownIsRemote);
            }
        }
    } else if (Cxn->HandshakeCompleted == TRI_TRUE) {
        strcpy_s(StateStr, sizeof(StateStr), "Connected");
    } else if (Cxn->HandshakeStarted == TRI_TRUE) {
        strcpy_s(StateStr, sizeof(StateStr), "Handshake");
    } else if (Cxn->HandshakeStarted == TRI_FALSE) {
        strcpy_s(StateStr, sizeof(StateStr), "Created");
    }

    printf(
        "\n" \
        "CONNECTION    %llX\n" \
        "\n" \
        "  CorrelationId  %llu\n" \
        "  IsServer       %s\n" \
        "  Age            %llu.%llu ms\n" \
        "  LocalAddr      %s\n" \
        "  RemoteAddr     %s\n",
        Cxn->Ptr,
        Cxn->CorrelationId,
        TriStateToString(Cxn->IsServer),
        Age / 1000, Age % 1000,
        LocalAddrStr,
        RemoteAddrStr);

    printf("  SrcCids        ");
    if (Cxn->SrcCids == NULL) {
        printf("UNKNOWN\n");
    } else {
        CID* Cid = Cxn->SrcCids;
        char CidStr[QUIC_CID_MAX_STR_LEN];
        while (Cid) {
            CidToString(Cid->Length, Cid->Buffer, CidStr);
            printf(CidStr);
            if (Cid->Next) {
                printf("\n                 ");
            }
            Cid = Cid->Next;
        }
        printf("\n");
    }

    printf("  DestCids       ");
    if (Cxn->DestCids == NULL) {
        printf("UNKNOWN\n");
    } else {
        CID* Cid = Cxn->DestCids;
        char CidStr[QUIC_CID_MAX_STR_LEN];
        while (Cid) {
            CidToString(Cid->Length, Cid->Buffer, CidStr);
            printf(CidStr);
            if (Cid->Next) {
                printf("\n                 ");
            }
            Cid = Cid->Next;
        }
        printf("\n");
    }

    printf(
        "  State          %s\n",
        StateStr);

    printf(
        "\n" \
        "  Streams        ");
    if (Cxn->Streams == NULL) {
        printf("EMPTY\n");
    } else {
        STREAM* Stream = Cxn->Streams;
        while (Stream) {
            printf("%llX (#%llu) (id %u)\n                 ",
                Stream->Ptr,
                Stream->StreamId,
                Stream->Id);
            Stream = Stream->Next;
        }
    }

    printf(
        "\n" \
        "  InitalProc     %u\n" \
        "  Worker         %llX (id %u)\n"
        "\n" \
        "  CPU\n" \
        "    Processors   0x%llX\n",
        (ULONG)Cxn->InitialProcessor,
        Cxn->WorkerPtr,
        Cxn->Worker == NULL ? 0 : Cxn->Worker->Id,
        Cxn->ProcessorBitmap);

    printf("    Processing   "); PrintCpuTime(&Cxn->SchedulingStats[QUIC_SCHEDULE_PROCESSING]);
    printf("    Queued       "); PrintCpuTime(&Cxn->SchedulingStats[QUIC_SCHEDULE_QUEUED]);
    printf("    Idle         "); PrintCpuTime(&Cxn->SchedulingStats[QUIC_SCHEDULE_IDLE]);

    printf(
        "\n" \
        "  RTT            %u.%u ms\n" \
        "  TX             %llu bytes\n" \
        "  RX             %llu bytes\n" \
        "  CcEvents       %u | %u (persistent)\n",
        Cxn->SmoothedRtt / 1000, Cxn->SmoothedRtt % 1000,
        Cxn->BytesSent,
        Cxn->BytesReceived,
        Cxn->CongestionEvents, Cxn->PersistentCongestionEvents);
}

void
ConnEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    QUIC_EVENT_DATA_CONNECTION* EvData = (QUIC_EVENT_DATA_CONNECTION*)ev->UserData;

    CXN* Cxn = GetCxnFromEvent(ev);
    *ObjectId = Cxn->Id;

    BOOLEAN TputEvent = Cmd.Command == COMMAND_CONN_TPUT && Cmd.SelectedId == Cxn->Id;
    BOOLEAN QueueEvent = Cmd.Command == COMMAND_WORKER_QUEUE && Cxn->Worker != NULL && Cxn->Worker->Id == Cmd.SelectedId;
    BOOLEAN QlogEvent = Qj != NULL && Cmd.SelectedId == Cxn->Id;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicConnDestroyed: {
        if (Cxn->IsServer != TRI_UNKNOWN &&
            Cxn->HandshakeCompleted == TRI_UNKNOWN) {
            // We got the begin event and end event, but no handshake completed event.
            Cxn->HandshakeCompleted = TRI_FALSE;
        }
        if (Cxn->Worker != NULL) {
            Cxn->Worker->CxnCount--;
        }
        break;
    }
    case EventId_QuicConnHandshakeComplete: {
        Cxn->HandshakeStarted = TRI_TRUE;
        Cxn->HandshakeCompleted = TRI_TRUE;
        break;
    }
    case EventId_QuicConnScheduleState: {
        if (Cxn->Worker == NULL) {
            Cxn->Worker = GetWorkerFromThreadId(ev->EventHeader.ThreadId);
            if (Cxn->Worker != NULL) {
                Cxn->WorkerPtr = Cxn->Worker->Ptr;
                Cxn->Worker->TotalCxnCount++;
                Cxn->Worker->CxnCount++;
                QueueEvent =
                    Cmd.Command == COMMAND_WORKER_QUEUE && Cxn->Worker->Id == Cmd.SelectedId;
            }
        }
        Trace.HasSchedulingEvents = TRUE;
        ULONG64 EventTime = ev->EventHeader.TimeStamp.QuadPart;
        if (Cxn->ScheduleStateTimestamp != 0) {
            if (EvData->ScheduleState.State == QUIC_SCHEDULE_QUEUED) {
                if (Cxn->Worker != NULL) {
                    Cxn->Worker->CxnQueueCount++;
                }
            } else if (EvData->ScheduleState.State == QUIC_SCHEDULE_PROCESSING) {
                if (Cxn->Worker != NULL) {
                    Cxn->Worker->CxnQueueCount--;
                }
            }
            AddCpuTime(
                &Cxn->SchedulingStats[Cxn->ScheduleState],
                NS100_TO_US(EventTime - Cxn->ScheduleStateTimestamp));
            if (Cxn->Worker != NULL) {
                AddCpuTime(
                    &Cxn->Worker->SchedulingStats[Cxn->ScheduleState],
                    NS100_TO_US(EventTime - Cxn->ScheduleStateTimestamp));
            }
            if (QueueEvent && EvData->ScheduleState.State == QUIC_SCHEDULE_PROCESSING) {
                OutputWorkerQueueSample(
                    Cxn->Worker, EventTime, NS100_TO_US(EventTime - Cxn->ScheduleStateTimestamp));
            }
        }
        Cxn->ScheduleStateTimestamp = EventTime;
        Cxn->ScheduleState = EvData->ScheduleState.State;
        break;
    }
    case EventId_QuicConnLocalAddrAdded: {
        Cxn->LocalAddress = EvData->LocalAddrAdd.Addr;
        break;
    }
    case EventId_QuicConnRemoteAddrAdded: {
        Cxn->RemoteAddress = EvData->RemoteAddrAdd.Addr;
        break;
    }
    case EventId_QuicConnAssignWorker: {
        if (Cxn->Worker != NULL) {
            Cxn->Worker->CxnCount--;
        }
        Cxn->WorkerPtr = EvData->AssignWorker.WorkerPtr;
        Cxn->Worker = (WORKER*)ObjectSetGetActive(&Workers, Cxn->WorkerPtr);
        if (Cxn->Worker != NULL) {
            Cxn->Worker->TotalCxnCount++;
            Cxn->Worker->CxnCount++;
        }
        break;
    }
    case EventId_QuicConnHandshakeStart: {
        Cxn->HandshakeStarted = TRI_TRUE;
        Cxn->HandshakeCompleted = TRI_FALSE;
        break;
    }
    case EventId_QuicConnRegisterSession: {
        Cxn->SessionPtr = EvData->RegisterSession.SessionPtr;
        break;
    }
    case EventId_QuicConnTransportShutdown: {
        Cxn->Shutdown = TRI_TRUE;
        Cxn->ShutdownTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        Cxn->ShutdownIsApp = FALSE;
        Cxn->ShutdownErrorCode = EvData->TransportShutdown.ErrorCode;
        Cxn->ShutdownIsRemote = EvData->TransportShutdown.IsRemoteShutdown;
        Cxn->ShutdownIsQuicStatus = EvData->TransportShutdown.IsQuicStatus;
        break;
    }
    case EventId_QuicConnAppShutdown: {
        Cxn->Shutdown = TRI_TRUE;
        Cxn->ShutdownTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        Cxn->ShutdownIsApp = TRUE;
        Cxn->ShutdownErrorCode = EvData->AppShutdown.ErrorCode;
        Cxn->ShutdownIsRemote = EvData->AppShutdown.IsRemoteShutdown;
        Cxn->ShutdownIsQuicStatus = FALSE;
        break;
    }
    case EventId_QuicConnOutFlowStats: {
        Trace.HasDatapathEvents = TRUE;
        Cxn->BytesSent = EvData->OutFlowStats.BytesSent;
        Cxn->BytesInFlight = EvData->OutFlowStats.BytesInFlight;
        Cxn->CongestionWindow = EvData->OutFlowStats.CongestionWindow;
        Cxn->TxBufBytes = EvData->OutFlowStats.PostedBytes;
        Cxn->SmoothedRtt = EvData->OutFlowStats.SmoothedRtt;
        Cxn->ConnFlowAvailable = EvData->OutFlowStats.ConnectionFlowControl;
        if (TputEvent) {
            OutputCxnTputSample(Cxn);
        }
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "RECOVERY", "METRIC_UPDATE");
            QjArrayObjectStart(Qj);
            QjWriteInt(Qj, "cwnd", Cxn->CongestionWindow);
            QjWriteInt(Qj, "bytes_in_flight", Cxn->BytesInFlight);
            QjWriteInt(Qj, "smoothed_rtt", Cxn->SmoothedRtt / 1000);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnCubic: {
        Trace.HasDatapathEvents = TRUE;
        Cxn->SlowStartThreshold = EvData->Cubic.SlowStartThreshold;
        Cxn->CubicK = EvData->Cubic.K;
        Cxn->CubicWindowMax = EvData->Cubic.WindowMax;
        if (TputEvent) {
            OutputCxnTputSample(Cxn);
        }
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "RECOVERY", "METRIC_UPDATE");
            QjArrayObjectStart(Qj);
            QjWriteStringInt(Qj, "ssthresh", Cxn->SlowStartThreshold);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnInFlowStats: {
        Trace.HasDatapathEvents = TRUE;
        Cxn->BytesReceived = EvData->InFlowStats.BytesRecv;
        if (TputEvent) {
            OutputCxnTputSample(Cxn);
        }
        break;
    }
    case EventId_QuicConnCongestion: {
        Cxn->CongestionEvents++;
        Cxn->InRecovery = TRUE;
        // The trace sample is considered "in recovery" if we are in recovery
        // at any point during the trace sample. We reset Cxn->SampleInRecovery
        // at the end of the trace sample.
        Cxn->SampleInRecovery = TRUE;
        if (TputEvent) {
            OutputCxnTputSample(Cxn);
        }
        break;
    }
    case EventId_QuicConnPersistentCongestion: {
        Cxn->PersistentCongestionEvents++;
        break;
    }
    case EventId_QuicConnRecoveryExit: {
        Cxn->InRecovery = FALSE;
        break;
    }
    case EventId_QuicConnSourceCidAdded: {
        CID* NewCid = malloc(sizeof(CID) + EvData->SourceCidAdd.CidLength);
        memcpy(NewCid->Buffer, EvData->SourceCidAdd.Cid, EvData->SourceCidAdd.CidLength);
        NewCid->Length = EvData->SourceCidAdd.CidLength;
        NewCid->Next = Cxn->SrcCids;
        Cxn->SrcCids = NewCid;
        break;
    }
    case EventId_QuicConnDestCidAdded: {
        CID* NewCid = malloc(sizeof(CID) + EvData->DestCidAdd.CidLength);
        memcpy(NewCid->Buffer, EvData->DestCidAdd.Cid, EvData->DestCidAdd.CidLength);
        NewCid->Length = EvData->DestCidAdd.CidLength;
        NewCid->Next = Cxn->DestCids;
        Cxn->DestCids = NewCid;
        break;
    }
    case EventId_QuicConnError:
    case EventId_QuicConnErrorStatus: {
        Cxn->ErrorCount++;
        break;
    }
    case EventId_QuicConnStatistics: {
        Cxn->BytesSent = EvData->Stats.SendTotalBytes;
        Cxn->BytesReceived = EvData->Stats.RecvTotalBytes;
        Cxn->CongestionEvents = EvData->Stats.CongestionCount;
        Cxn->PersistentCongestionEvents = EvData->Stats.PersistentCongestionCount;
        Cxn->SmoothedRtt = EvData->Stats.SmoothedRtt;
        Cxn->StatsProcessed = TRUE;
        break;
    }
    case EventId_QuicConnPacketSent: {
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "TRANSPORT", "PACKET_SENT");
            QjArrayObjectStart(Qj);
            QjWriteString(Qj, "type", PacktTypeQLogStr[EvData->PacketSent.Type]);
            QjObjectStart(Qj, "header");
            QjWriteStringInt(Qj, "packet_number", EvData->PacketSent.Number);
            QjWriteInt(Qj, "packet_size", EvData->PacketSent.Length);
            QjObjectEnd(Qj);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnPacketRecv: {
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "TRANSPORT", "PACKET_RECEIVED");
            QjArrayObjectStart(Qj);
            QjWriteString(Qj, "type", PacktTypeQLogStr[EvData->PacketRecv.Type]);
            QjObjectStart(Qj, "header");
            QjWriteStringInt(Qj, "packet_number", EvData->PacketRecv.Number);
            QjWriteInt(Qj, "packet_size", EvData->PacketRecv.Length);
            QjObjectEnd(Qj);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnPacketLost: {
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "RECOVERY", "PACKET_LOST");
            QjArrayObjectStart(Qj);
            QjWriteString(Qj, "type", PacktTypeQLogStr[EvData->PacketLost.Type]);
            QjWriteStringInt(Qj, "packet_number", EvData->PacketLost.Number);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnPacketACKed: {
        if (QlogEvent) {
            QjCxnEventStart(Cxn, ev, "RECOVERY", "PACKET_ACKNOWLEDGED");
            QjArrayObjectStart(Qj);
            QjWriteString(Qj, "type", PacktTypeQLogStr[EvData->PacketACKed.Type]);
            QjWriteStringInt(Qj, "packet_number", EvData->PacketRecv.Number);
            QjObjectEnd(Qj);
            QjCxnEventEnd();
        }
        break;
    }
    case EventId_QuicConnOutFlowStreamStats: {
        Trace.HasDatapathEvents = TRUE;
        Cxn->StreamFlowAvailable = EvData->OutFlowStreamStats.StreamFlowControl;
        Cxn->StreamSendWindow = EvData->OutFlowStreamStats.StreamSendWindow;
        if (TputEvent) {
            OutputCxnTputSample(Cxn);
        }
        break;
    }
    case EventId_QuicConnPacketStats: {
        Cxn->SentPackets = EvData->PacketStats.SendTotalPackets;
        Cxn->LostPackets =
            EvData->PacketStats.SendSuspectedLostPackets - EvData->PacketStats.SendSpuriousLostPackets;
        Cxn->ReceivedPackets = EvData->PacketStats.RecvTotalPackets;
        Cxn->DroppedPackets = EvData->PacketStats.RecvDroppedPackets;
        Cxn->StatsProcessed = TRUE;
        break;
    }
    }

    if (Cmd.Command == COMMAND_CONN_TRACE && Cmd.SelectedId == Cxn->Id) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Cxn->InitialTimestamp;
    } else if(Cmd.Command == COMMAND_WORKER_TRACE && Cxn->Worker != NULL && Cxn->Worker->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Cxn->Worker->InitialTimestamp;
    }
}

void
TlsEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    CXN* Cxn = GetCxnFromTlsEvent(ev);
    *ObjectId = Cxn->Id;

    if (Cmd.Command == COMMAND_CONN_TRACE && Cmd.SelectedId == Cxn->Id) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Cxn->InitialTimestamp;
    } else if(Cmd.Command == COMMAND_WORKER_TRACE && Cxn->Worker != NULL && Cxn->Worker->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Cxn->Worker->InitialTimestamp;
    }

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicTlsError:
    case EventId_QuicTlsErrorStatus: {
        Cxn->ErrorCount++;
        break;
    }
    }
}

void ExecuteCxnCommand(void)
{
    if (Cxns.NextId == 1) {
        printf("No connections found in the trace!\n");
        return;
    }

    if (Cmd.Command != COMMAND_CONN_TRACE &&
        Cmd.MaxOutputLines == ULONG_MAX) {
        Cmd.MaxOutputLines = 100; // By default don't log too many lines
    }

    if (Cmd.SelectedId == 0) {
        // Sort the connections in the requested order and cache the first
        // connection's ID for additional output.
        CXN** CxnArray = (CXN**)ObjectSetSort(&Cxns, CxnSortFns[Cmd.Sort]);

        if (Cmd.CidLength != 0) {
            for (ULONG i = 1; i < Cxns.NextId; i++) {
                CXN* Cxn = CxnArray[i];
                CID* Cid = Cxn->SrcCids;
                while (Cid) {
                    if (Cid->Length == Cmd.CidLength &&
                        memcmp(Cid->Buffer, Cmd.Cid, Cid->Length) == 0) {
                        if (Cmd.SelectedId == 0) {
                            Cmd.SelectedId = Cxn->Id;
                        }
                        if (Cmd.Command == COMMAND_CONN_LIST) {
                            OutputCxnOneLineSummary(Cxn);
                        }
                        break;
                    }
                    Cid = Cid->Next;
                }
                Cid = Cxn->DestCids;
                while (Cid) {
                    if (Cid->Length == Cmd.CidLength &&
                        memcmp(Cid->Buffer, Cmd.Cid, Cid->Length) == 0) {
                        if (Cmd.SelectedId == 0) {
                            Cmd.SelectedId = Cxn->Id;
                        }
                        if (Cmd.Command == COMMAND_CONN_LIST) {
                            OutputCxnOneLineSummary(Cxn);
                        }
                        break;
                    }
                    Cid = Cid->Next;
                }
                if (Cmd.Command != COMMAND_CONN_LIST && Cmd.SelectedId != 0) {
                    break;
                }
            }

        } else {
            Cmd.SelectedId = CxnArray[1]->Id;
            if (Cmd.Command == COMMAND_CONN_LIST) {
                for (ULONG i = 1; i < Cxns.NextId; i++) {
                    CXN* Cxn = CxnArray[i];
                    if (Cmd.Filter & FILTER_DISCONNECT && !CxnWasDisconnected(Cxn)) {
                        continue;
                    }
                    OutputCxnOneLineSummary(Cxn);
                }
            }
        }

        free(CxnArray);

        if (Cmd.Command != COMMAND_CONN && Cmd.Command != COMMAND_CONN_LIST) {
            // Reprocess the trace now that we have the ID needed for output.
            RunProcessTrace();
        }
    }

    if (Cmd.Command == COMMAND_CONN) {
        CXN* Cxn = (CXN*)ObjectSetGetId(&Cxns, Cmd.SelectedId);
        if (Cxn != NULL) {
            OutputCxnSummary(Cxn);
        } else {
            printf("Failed to get id = %u\n", Cmd.SelectedId);
        }
    }

    if (QjEndCxn) {
        QjArrayEnd(Qj);
        QjObjectEnd(Qj);
        printf("Wrote 'conn.qlog'\n");
    }
}
