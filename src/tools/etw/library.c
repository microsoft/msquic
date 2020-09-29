/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

API_STATS ApiStats[QUIC_API_COUNT] = {0};

void ExecuteSummaryCommand(void)
{
    const char* FormatStr =
        "\n" \
        "TRACE FILE\n" \
        "\n" \
        "  ProcessEtl  %llu.%llu s\n" \
        "  ElapsedTime %llu.%llu s\n" \
        "  Events      %llu\n" \
        ;

    ULONG64 ElapsedTime = US_TO_MS(NS100_TO_US(Trace.StopTimestamp - Trace.StartTimestamp));

    printf(
        FormatStr,
        Trace.ProcessedMs / 1000, Trace.ProcessedMs % 1000,
        ElapsedTime / 1000, ElapsedTime % 1000,
        Trace.EventCount);

    for (UINT32 i = 0 ;i < ARRAYSIZE(EventCounts); ++i) {
        printf("    %s  %llu\n", EventCounts[i].Name, Trace.EventTypeCount[i]);
        if (Cmd.Verbose) {
            for (USHORT j = 0; j < EventCounts[i].Length; j++) {
                if (EventCounts[i].Counts[j] != 0) {
                    printf("      %.2u:           %llu\n", j, EventCounts[i].Counts[j]);
                }
            }
        }
    }

    printf("  Api Calls   %llu\n", Trace.ApiCallCount);
    if (Cmd.Verbose) {
        for (UINT32 i = 0 ;i < ARRAYSIZE(ApiStats); ++i) {
            if (ApiStats[i].Count != 0) {
                printf("    %-18s  %u\n", ApiTypeStr[i], ApiStats[i].Count);
            }
        }
    }

    const char* FormatStr2 =
        "  Objects\n" \
        "    Registration  --\n" \
        "    Worker        %u\n" \
        "    Configuration --\n" \
        "    Listener      %u\n" \
        "    Connection    %u\n" \
        "    Stream        %u\n" \
        "    Binding       %u\n" \
        ;

    printf(
        FormatStr2,
        Workers.NextId - 1,
        Listeners.NextId - 1,
        Cxns.NextId - 1,
        Streams.NextId - 1,
        Bindings.NextId - 1
        );
}

#define UNHEALTHY_QUEUE_DELAY_US            (25 * 1000)
#define MOSTLY_IDLE_PROCESSING_PERCENT      (5)
#define REALLY_ACTIVE_PROCESSING_PERCENT    (80)

void ExecuteReportCommand(void)
{
    ULONG64 ElapsedTime = NS100_TO_US(Trace.StopTimestamp - Trace.StartTimestamp);
    printf("\nREPORT (Elapsed time: "); PrintTimeUs(ElapsedTime); printf(")\n\n");

    if (Workers.NextId == 1) {
        printf("No workers found.\n");

    } else if (!Trace.HasSchedulingEvents) {
        printf("No scheduling events to calculate worker statistics.\n\n");

    } else {

        printf("WORKERS (%u)\n\n", Workers.NextId - 1);

        WORKER** AllWorkers = (WORKER**)ObjectSetSort(&Workers, NULL);

        ULONG UnhealthyWorkers = 0;
        ULONG MostlyIdleWorkers = 0;
        ULONG ReallyActiveWorkers = 0;

        for (ULONG i = 1; i < Workers.NextId; ++i) {
            WORKER* Worker = AllWorkers[i];
            ElapsedTime = NS100_TO_US(Worker->FinalTimestamp - Worker->InitialTimestamp);
            ULONG AvgQueueDelay =
                AvgCpuTime(&Worker->SchedulingStats[QUIC_SCHEDULE_QUEUED]);
            if (AvgQueueDelay >= UNHEALTHY_QUEUE_DELAY_US) {
                UnhealthyWorkers++;
            }
            ULONG ActivePercent =
                ElapsedTime == 0 ?
                    0 : (ULONG)((100 * Worker->SchedulingStats[QUIC_SCHEDULE_PROCESSING].TotalCpuTime) / ElapsedTime);
            if (ActivePercent <= MOSTLY_IDLE_PROCESSING_PERCENT) {
                MostlyIdleWorkers++;
            } else if (ActivePercent >= REALLY_ACTIVE_PROCESSING_PERCENT) {
                ReallyActiveWorkers++;
            }
        }

        if (UnhealthyWorkers == 0) {
            printf("  All workers healthy.\n");
        } else {
            printf("  %u workers unhealthy.\n  {", UnhealthyWorkers);
            UnhealthyWorkers = 0;
            for (ULONG i = 1; i < Workers.NextId; ++i) {
                WORKER* Worker = AllWorkers[i];
                ULONG AvgQueueDelay =
                    AvgCpuTime(&Worker->SchedulingStats[QUIC_SCHEDULE_QUEUED]);
                if (AvgQueueDelay > UNHEALTHY_QUEUE_DELAY_US) {
                    if (UnhealthyWorkers != 0) {
                        printf(", ");
                    }
                    printf("#%u", Worker->Id);
                    UnhealthyWorkers++;
                }
            }
            printf("}\n");
        }

        printf("  %u workers mostly idle.\n", MostlyIdleWorkers);
        printf("  %u workers really active.\n", ReallyActiveWorkers);

        printf("\n");
        free(AllWorkers);
    }

    if (Cxns.NextId == 1) {
        printf("No connections found.\n");
        return;
    }

    printf("CONNECTIONS (%u)\n\n", Cxns.NextId - 1);

    CXN** AllCxns = (CXN**)ObjectSetSort(&Cxns, NULL);

    ULONG StillActiveCxns = 0;
    ULONG TransportShutdownCxns = 0; // TODO - Includes things like idle timeout, which isn't necessarily bad.
    ULONG AppNonZeroShutdownCxns = 0;
    ULONG SuccessAppShutdownCxns = 0;
    ULONG UnknownShutdownCxns = 0;
    ULONG CxnsWithErrors = 0;
    ULONG CxnsFailedHandshake = 0;
    ULONG CxnsWithStats = 0;

    ULONG64 TotalCongEvents = 0;
    ULONG64 TotalPerCongEvents = 0;
    ULONG64 TotalSentPackets = 0;
    ULONG64 TotalLostPackets = 0;
    ULONG64 TotalReceivedPackets = 0;
    ULONG64 TotalDroppedPackets = 0;

    for (ULONG i = 1; i < Cxns.NextId; ++i) {
        CXN* Cxn = AllCxns[i];

        if (Cxn->StatsProcessed) {
            CxnsWithStats++;
        }

        TotalCongEvents += Cxn->CongestionEvents;
        TotalPerCongEvents += Cxn->PersistentCongestionEvents;
        TotalSentPackets += Cxn->SentPackets;
        TotalLostPackets += Cxn->LostPackets;
        TotalReceivedPackets += Cxn->ReceivedPackets;
        TotalDroppedPackets += Cxn->DroppedPackets;

        if (Cxn->Shutdown != TRI_TRUE) {
            if (Cxn->Destroyed) {
                UnknownShutdownCxns++;
            } else {
                StillActiveCxns++;
            }
        } else {
            if (Cxn->ShutdownIsApp) {
                if (Cxn->ShutdownErrorCode == 0) {
                    SuccessAppShutdownCxns++;
                } else {
                    AppNonZeroShutdownCxns++;
                }
            } else {
                TransportShutdownCxns++;
            }
        }
        if (Cxn->ErrorCount != 0) {
            CxnsWithErrors++;
        }
        if (Cxn->HandshakeCompleted == TRI_FALSE) {
            CxnsFailedHandshake++;
        }
    }

    if (StillActiveCxns == 0) {
        printf("  No active connections.\n");
    } else {
        printf("  %u connections stil active.\n", StillActiveCxns);
    }

    if (CxnsWithErrors != 0) {
        printf("\n  %u connections encountered errors.\n", CxnsWithErrors);
    }

    if (CxnsFailedHandshake != 0) {
        printf("\n  %u connections failed the handshake.\n", CxnsFailedHandshake);
    }

    printf("\n");
    if (SuccessAppShutdownCxns != 0) {
        printf("  %u connections successfully shutdown by the app.\n", SuccessAppShutdownCxns);
    }
    if (AppNonZeroShutdownCxns != 0) {
        printf("  %u connections errored by the app.\n", AppNonZeroShutdownCxns);
    }
    if (TransportShutdownCxns != 0) {
        printf("  %u connections shutdown by the transport.\n", TransportShutdownCxns);
    }

    printf("\n");
    if (CxnsWithStats == 0) {
        printf("  WARNING - No connection statistics events found.\n\n");
    }

    printf("  %llu total congestion events.\n", TotalCongEvents);
    printf("  %llu total persistent congestion events.\n\n", TotalPerCongEvents);

    printf("  %llu total packets sent.\n", TotalSentPackets);
    printf("  %llu total packets lost.\n\n", TotalLostPackets);

    printf("  %llu total packets received.\n", TotalReceivedPackets);
    printf("  %llu total packets dropped.\n", TotalDroppedPackets);

    free(AllCxns);
}

void
LibraryEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    QUIC_EVENT_DATA_GLOBAL* EvData = (QUIC_EVENT_DATA_GLOBAL*)ev->UserData;

    UNREFERENCED_PARAMETER(ObjectId);
    UNREFERENCED_PARAMETER(TraceEvent);
    UNREFERENCED_PARAMETER(InitialTimestamp);

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicApiEnter:
        Trace.ApiCallCount++;
        ApiStats[EvData->ApiEnter.Type].Count++;
        break;
    case EventId_QuicApiExit:
        break;
    case EventId_QuicApiExitStatus:
        break;
    case EventId_QuicApiWaitOperation:
        break;
    case EventId_QuicPerfCountersRundown:
        break;
    }
}
