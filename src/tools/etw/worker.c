/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

OBJECT_SET Workers = {0};

int __cdecl CompareWorkerAgeFn(const void* Wrk1, const void* Wrk2)
{
    WORKER* a = (*((WORKER**)Wrk1));
    WORKER* b = (*((WORKER**)Wrk2));
    ULONG64 age1 = a->FinalTimestamp - a->InitialTimestamp;
    ULONG64 age2 = b->FinalTimestamp - b->InitialTimestamp;
    return (age1 > age2) ? -1 : ((age1 == age2) ? 0 : 1);
}

int __cdecl CompareWorkerCpuActiveFn(const void* Wrk1, const void* Wrk2)
{
    ULONG64 a = (*((WORKER**)Wrk1))->TotalActiveTime;
    ULONG64 b = (*((WORKER**)Wrk2))->TotalActiveTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareWorkerCpuQueuedFn(const void* Wrk1, const void* Wrk2)
{
    ULONG64 a = (*((WORKER**)Wrk1))->SchedulingStats[QUIC_SCHEDULE_QUEUED].TotalCpuTime;
    ULONG64 b = (*((WORKER**)Wrk2))->SchedulingStats[QUIC_SCHEDULE_QUEUED].TotalCpuTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareWorkerCpuIdleFn(const void* Wrk1, const void* Wrk2)
{
    ULONG64 a = (*((WORKER**)Wrk1))->SchedulingStats[QUIC_SCHEDULE_IDLE].TotalCpuTime;
    ULONG64 b = (*((WORKER**)Wrk2))->SchedulingStats[QUIC_SCHEDULE_IDLE].TotalCpuTime;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int __cdecl CompareWorkerCxnCountFn(const void* Wrk1, const void* Wrk2)
{
    ULONG64 a = (*((WORKER**)Wrk1))->TotalCxnCount;
    ULONG64 b = (*((WORKER**)Wrk2))->TotalCxnCount;
    return (a > b) ? -1 : ((a == b) ? 0 : 1);
}

int (__cdecl * WorkerSortFns[])(const void *, const void *) = {
    NULL,
    CompareWorkerAgeFn,
    CompareWorkerCpuActiveFn,
    CompareWorkerCpuQueuedFn,
    CompareWorkerCpuIdleFn,
    NULL,
    NULL,
    CompareWorkerCxnCountFn,
    NULL
};

WORKER*
NewWorker(
    _In_ PEVENT_RECORD ev
    )
{
    QUIC_EVENT_DATA_WORKER* EvData = (QUIC_EVENT_DATA_WORKER*)ev->UserData;

    // Move the old worker out of the set if this pointer is being reused.
    (void)ObjectSetRemoveActive(&Workers, EvData->WorkerPtr);

    WORKER* Worker = malloc(sizeof(WORKER));
    if (Worker == NULL) {
        printf("out of memory\n");
        exit(1);
    }
    memset(Worker, 0, sizeof(*Worker));
    Worker->Id = Workers.NextId++;
    Worker->Ptr = EvData->WorkerPtr;
    Worker->InitialTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    Worker->IsIdle = TRUE;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicWorkerCreated) {
        Worker->IdealProcessor = EvData->Created.IdealProcessor;
        Worker->OwnerPtr = EvData->Created.OwnerPtr;
    } else {
        Worker->IdealProcessor = UCHAR_MAX;
        Worker->OwnerPtr = ULLONG_MAX;
    }
    ObjectSetAddActive(&Workers, (OBJECT*)Worker);
    return Worker;
}

WORKER* GetWorkerFromEvent(PEVENT_RECORD ev)
{
    QUIC_EVENT_DATA_WORKER* EvData = (QUIC_EVENT_DATA_WORKER*)ev->UserData;

    WORKER* Worker;
    if (GetEventId(ev->EventHeader.EventDescriptor.Id) == EventId_QuicWorkerCreated) {
        Worker = NewWorker(ev);
    } else if (GetEventId(ev->EventHeader.EventDescriptor.Id)== EventId_QuicWorkerStop) {
        Worker = (WORKER*)ObjectSetRemoveActive(&Workers, EvData->WorkerPtr);
    } else {
        if ((Worker = (WORKER*)ObjectSetGetActive(&Workers, EvData->WorkerPtr)) == NULL) {
            Worker = NewWorker(ev);
        }
    }

    if (Worker != NULL) {
        Worker->FinalTimestamp = ev->EventHeader.TimeStamp.QuadPart;

        if (Worker->ThreadId == 0 &&
            GetEventId(ev->EventHeader.EventDescriptor.Id) != EventId_QuicWorkerCreated) {
            Worker->ThreadId = ev->EventHeader.ThreadId;
        }

        if (ev->BufferContext.ProcessorNumber < 64) {
            if (ev->EventHeader.ThreadId == Worker->ThreadId) {
                Worker->ProcessorBitmap |= (1ull << ev->BufferContext.ProcessorNumber);
            }
        } else {
            printf("WARNING: More than 64 cores not supported by tool!\n");
        }
    }

    return Worker;
}

_Ret_maybenull_
WORKER*
GetWorkerFromThreadId(
    _In_ ULONG ThreadId
    )
{
    CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    CxPlatHashtableEnumerateBegin(Workers.Active, &Enumerator);
    for (;;) {
        Entry = CxPlatHashtableEnumerateNext(Workers.Active, &Enumerator);
        if (Entry == NULL) {
            CxPlatHashtableEnumerateEnd(Workers.Active, &Enumerator);
            break;
        }
        WORKER* Worker = CONTAINING_RECORD(Entry, WORKER, ActiveEntry);
        if (Worker->ThreadId != 0 &&
            Worker->ThreadId == ThreadId) {
            CxPlatHashtableEnumerateEnd(Workers.Active, &Enumerator);
            return Worker;
        }
    }

    return NULL;
}

/*
    ID Thread  Proc   Conns        Age     Active ConnActive
                                  (us)       (us)       (us)
     8   04B8   255       0    6373234     516364          0
     7   09E4   255       0    6413376     431141          0
     4   05E8   255       0    6422865     393815          0
     9   0EB0   255       0    6413312     385949          0
     1   190C   255       0    6421716     379932          0
    18   048C   255       0    6311440     374162          0
    26   1D60   255       0    6288250     367234          0
     6   1C1C   255       0    6405863     360289          0
    15   1BAC   255       0    6303682     359943          0
    10   1654   255       0    6404274     357367          0
*/

void OutputWorkerOneLineSummary(_In_ WORKER* Worker)
{
    if (++Trace.OutputLineCount > Cmd.MaxOutputLines) {
        return;
    }

    const char* FormatStr = "%6lu   %.4X %5u %7u %10llu %10llu %10llu\n";
    const char* FormatCsvStr = "%lu,%lu,%u,%u,%llu,%llu,%llu\n";

    if (!Cmd.FormatCSV && ((Trace.OutputLineCount-1) % 10) == 0) {
        if (Trace.OutputLineCount != 1) printf("\n");
        printf("    ID Thread  Proc   Conns        Age     Active ConnActive\n");
        printf("                                  (us)       (us)       (us)\n");
    }

    ULONG64 Age = NS100_TO_US(Worker->FinalTimestamp - Worker->InitialTimestamp);
    printf(
        Cmd.FormatCSV ? FormatCsvStr : FormatStr,
        Worker->Id,
        Worker->ThreadId,
        (ULONG)Worker->IdealProcessor,
        Worker->TotalCxnCount,
        Age,
        NS100_TO_US(Worker->TotalActiveTime),
        Worker->SchedulingStats[QUIC_SCHEDULE_PROCESSING].TotalCpuTime);
}

/*
WORKER        0x23EFE261420

  ThreadId    3B1C
  IdealProc   0

  Owner       0x23EFE261350
  Connections 6

  Age         6.373 s
  Active      516.364 ms
  CPU
    Processors  0x5FF
    Processing  22.933 ms (avg 416 us, min 0 us, max 3.266 ms)
    Queued      2.243 ms (avg 40 us, min 0 us, max 359 us)
    Idle        39.597 ms (avg 791 us, min 0 us, max 5.264 ms)
*/

void OutputWorkerSummary(_In_ WORKER* Worker)
{
    ULONG64 Age = NS100_TO_US(Worker->FinalTimestamp - Worker->InitialTimestamp);

    printf(
        "\n" \
        "WORKER        0x%llX\n" \
        "\n" \
        "  ThreadId    %.4X\n" \
        "  IdealProc   %u\n" \
        "\n" \
        "  Owner       0x%llX\n" \
        "  Connections %u\n" \
        "\n",
        Worker->Ptr,
        Worker->ThreadId,
        (ULONG)Worker->IdealProcessor,
        Worker->OwnerPtr,
        Worker->TotalCxnCount);

    printf("  Age         "); PrintTimeUs(Age); printf("\n");
    printf("  Active      "); PrintTimeUs(NS100_TO_US(Worker->TotalActiveTime)); printf("\n");
    printf(
        "  CPU\n" \
        "    Processors  0x%llX\n",
        Worker->ProcessorBitmap);

    printf("    Processing  "); PrintCpuTime(&Worker->SchedulingStats[QUIC_SCHEDULE_PROCESSING]);
    printf("    Queued      "); PrintCpuTime(&Worker->SchedulingStats[QUIC_SCHEDULE_QUEUED]);
    printf("    Idle        "); PrintCpuTime(&Worker->SchedulingStats[QUIC_SCHEDULE_IDLE]);
}

/*
       Time  QueueDelay  CxnProcess
       (ms)        (us)        (us)
     186292           8           0
     186310           4           0
     186331           4           0
     186356           4           0
     186377           4           0
     187038         648           0
     224881        1745           0
     230403          51           0
     254380          33           0
*/

void
OutputWorkerQueueSample(
    _In_ WORKER* Worker,
    _In_ ULONG64 NewTimeStamp,
    _In_ ULONG64 NewQueueDelay
    )
{
    Worker->SampleCount++;
    Worker->QueueDelaySamples += NewQueueDelay;
    if (Worker->LastQueueSampleTimestamp != 0) {
        Worker->CxnProcessSamples += NS100_TO_US(NewTimeStamp - Worker->LastQueueSampleTimestamp);
    }
    Worker->LastQueueSampleTimestamp = NewTimeStamp;

    if (Worker->LastQueueOutputTimestamp + Cmd.OutputResolution >= NewTimeStamp) {
        return;
    }

    if (++Trace.OutputLineCount <= Cmd.MaxOutputLines) {
        if (!Cmd.FormatCSV && ((Trace.OutputLineCount-1) % 10) == 0) {
            if (Trace.OutputLineCount != 1) printf("\n");
            printf("       Time  CxnCount  QueueLen  QueueDelay  CxnProcess\n");
            printf("       (ms)                            (us)        (us)\n");
        }
        printf(
            Cmd.FormatCSV ? "%llu,%u,%u,%llu,%llu\n" : "%11llu %9u %9u %11llu %11llu\n",
            NS100_TO_MS(NewTimeStamp - Worker->InitialTimestamp),
            Worker->CxnCount,
            Worker->CxnQueueCount,
            Worker->QueueDelaySamples / Worker->SampleCount,
            Worker->CxnProcessSamples / Worker->SampleCount);
    }

    Worker->SampleCount = 0;
    Worker->QueueDelaySamples = 0;
    Worker->CxnProcessSamples = 0;
    Worker->LastQueueOutputTimestamp = NewTimeStamp;
}

void
WorkerEventCallback(
    _In_ PEVENT_RECORD ev,
    _Out_ ULONG* ObjectId,
    _Out_ BOOLEAN* TraceEvent,
    _Out_ ULONG64* InitialTimestamp
    )
{
    WORKER* Worker = GetWorkerFromEvent(ev);
    *ObjectId = Worker->Id;

    QUIC_EVENT_DATA_WORKER* EvData = (QUIC_EVENT_DATA_WORKER*)ev->UserData;

    if (Cmd.Command == COMMAND_WORKER_TRACE && Worker->Id == Cmd.SelectedId) {
        *TraceEvent = TRUE;
        *InitialTimestamp = Worker->InitialTimestamp;
    }

    BOOLEAN QueueEvent = Cmd.Command == COMMAND_WORKER_QUEUE && Worker->Id == Cmd.SelectedId;

    switch (GetEventId(ev->EventHeader.EventDescriptor.Id)) {
    case EventId_QuicWorkerStart: {
        Worker->StartTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        break;
    }
    case EventId_QuicWorkerStop: {
        Worker->StopTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        break;
    }
    case EventId_QuicWorkerActivityStateUpdated: {
        if (!EvData->ActivityStateUpdated.IsActive) {
            if (Worker->LastActiveTimestamp != 0) {
                Worker->TotalActiveTime +=
                    ev->EventHeader.TimeStamp.QuadPart - Worker->LastActiveTimestamp;
            }
            Worker->IsIdle = TRUE;
            if (QueueEvent) {
                OutputWorkerQueueSample(Worker, ev->EventHeader.TimeStamp.QuadPart, 0);
            }
            Worker->LastQueueSampleTimestamp = 0;
        } else {
            Worker->LastActiveTimestamp = ev->EventHeader.TimeStamp.QuadPart;
        }
        break;
    }
    }
}

void ExecuteWorkerCommand(void)
{
    if (Workers.NextId == 1) {
        printf("No workers found in the trace!\n");
        return;
    }

    if (Cmd.Command != COMMAND_WORKER_TRACE && Cmd.Command != COMMAND_WORKER_QUEUE &&
        Cmd.MaxOutputLines == ULONG_MAX) {
        Cmd.MaxOutputLines = 100; // By default don't log too many lines
    }

    if (Cmd.SelectedId == 0) {
        // Sort the connections in the requested order and cache the first
        // connection's ID for additional output.
        WORKER** WorkerArray = (WORKER**)ObjectSetSort(&Workers, WorkerSortFns[Cmd.Sort]);
        Cmd.SelectedId = WorkerArray[1]->Id;

        for (ULONG i = 1; i < Workers.NextId; i++) {
            WORKER* Worker = WorkerArray[i];
            if (Cmd.Command == COMMAND_WORKER_LIST) {
                OutputWorkerOneLineSummary(Worker);
            }
        }
        free(WorkerArray);

        if (Cmd.Command != COMMAND_WORKER_LIST) {
            // Reprocess the trace now that we have the ID needed for output.
            RunProcessTrace();
        }
    }

    if (Cmd.Command == COMMAND_WORKER) {
        WORKER* Worker = (WORKER*)ObjectSetGetId(&Workers, Cmd.SelectedId);
        if (Worker != NULL) {
            OutputWorkerSummary(Worker);
        } else {
            printf("Failed to get id = %u\n", Cmd.SelectedId);
        }
    }
}
