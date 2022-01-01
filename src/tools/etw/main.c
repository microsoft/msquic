/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quicetw.h"

#define USAGE \
"QUIC Trace Analyzer\n" \
"\n" \
"quicetw <f.etl> [options] [command]\n" \
"quicetw --local [options] [command]\n" \
"\n" \
"Options:\n" \
"  --man, File path to tracing manifest to use or 'sdxroot' to load from %%SDXROOT%%.\n" \
"  --csv, Outputs in comma separated vector format\n" \
"\n" \

#define USAGE_PART2 \
"General Commands:\n" \
"  --help [command], Shows the help text\n" \
"  --summary, Shows general event/file information\n" \
"  --report, Generates a report of the system in the trace\n" \
"  --trace, Converts all ETW logs to text\n" \
"\n" \
"Connection Commands:\n" \
"  --conn [--sort <type>|--filter <type>|--id <num>|--cid <bytes>]\n" \
"  --conn_list [--sort <type>|--filter <type>|--cid <bytes>] [--top <num>]\n" \
"  --conn_tput [--sort <type>|--filter <type>|--id <num>|--cid <bytes>] [--reso <ms>] [--top <num>]\n" \
"  --conn_trace [--sort <type>|--filter <type>|--id <num>|--cid <bytes>] [--top <num>]\n" \
"  --conn_qlog [--sort <type>|--filter <type>|--id <num>|--cid <bytes>]\n" \
"\n" \
"Stream Commands:\n" \
"  --stream_trace [--id <num>] [--top <num>]\n" \
"\n" \
"Worker Commands:\n" \
"  --worker [--sort <type>] [--id <num>]\n" \
"  --worker_list [--sort <type>] [--top <num>]\n" \
"  --worker_queue [--sort <type>] [--id <num>] [--reso <ms>]\n" \
"  --worker_trace [--sort <type>|--id <num>] [--top <num>]\n" \
"\n" \
"Command Options:\n" \
"  --sort <type>, Specifies a sorting order\n" \
"         {age,cpu_active,cpu_queued,cpu_idle,tx,rx,conn_count,shutdown}\n" \
"  --filter <type>, Specifies a filter to look for\n" \
"         {disconnect}\n" \
"  --id <num>, Number from the output of --conn_list or --worker_list\n" \
"  --cid <bytes>, Connection ID to search for\n" \
"  --top <num>, Limits the number of output lines\n" \
"  --reso <ms>, Event resolution in milliseconds\n" \
"  --verbose, Includes more detailed output\n" \

#define QUIC_MAN_PATH L"\\minio\\quic\\manifest\\MsQuicEtw.man"

const GUID QuicEtwProviderId = { // {ff15e657-4f26-570e-88ab-0796b258d11c}
    0xff15e657,0x4f26,0x570e,0x88,0xab,0x07,0x96,0xb2,0x58,0xd1,0x1c};

const GUID QuicEtwSessionGuid = { // {0d64a339-b80c-4efe-867f-200c1b511316}
    0x0d64a339, 0xb80c, 0x4efe, 0x86, 0x7f, 0x20, 0x0c, 0x1b, 0x51, 0x13, 0x16};

const char QuicEtwSessionName[] = "quicetw";

const char QuicEtwFileName[] = "C:\\Windows\\System32\\LogFiles\\WMI\\quicetw.etl";

CMD_ARGS Cmd = {
    COMMAND_NONE,
    FALSE,
    SORT_NONE,
    0,
    MS_TO_NS100(100), // 0.1sec default
    ULONG_MAX
};

TRACE_STATE Trace = {0};

QJSON* Qj = NULL;

ULONG64 LibraryEventCounts[EventId_QuicLibraryCount];
ULONG64 RegistrationEventCounts[EventId_QuicRegistrationCount];
ULONG64 WorkerEventCounts[EventId_QuicWorkerCount];
ULONG64 SessionEventCounts[EventId_QuicSessionCount];
ULONG64 ListenerEventCounts[EventId_QuicListenerCount];
ULONG64 ConnEventCounts[EventId_QuicConnCount];
ULONG64 StreamEventCounts[EventId_QuicStreamCount];
ULONG64 BindingEventCounts[EventId_QuicBindingCount];
ULONG64 TlsEventCounts[EventId_QuicTlsCount];
ULONG64 DatapathEventCounts[EventId_QuicDatapathCount];
ULONG64 LogEventCounts[EventId_QuicLogCount];

EVENT_COUNTS EventCounts[EventType_Count] = {
    { "Library     ", LibraryEventCounts, EventId_QuicLibraryCount },
    { "Registration", RegistrationEventCounts, EventId_QuicRegistrationCount },
    { "Worker      ", WorkerEventCounts, EventId_QuicWorkerCount },
    { "Session     ", SessionEventCounts, EventId_QuicSessionCount },
    { "Listener    ", ListenerEventCounts, EventId_QuicListenerCount },
    { "Connection  ", ConnEventCounts, EventId_QuicConnCount },
    { "Stream      ", StreamEventCounts, EventId_QuicStreamCount },
    { "Binding     ", BindingEventCounts, EventId_QuicBindingCount },
    { "Tls         ", TlsEventCounts, EventId_QuicTlsCount },
    { "Datapath    ", DatapathEventCounts, EventId_QuicDatapathCount },
    { "Log         ", LogEventCounts, EventId_QuicLogCount }
};

const ObjEventHandler EventHandlers[EventType_Count] = {
    LibraryEventCallback,
    NULL,
    WorkerEventCallback,
    SessionEventCallback,
    ListenerEventCallback,
    ConnEventCallback,
    StreamEventCallback,
    BindingEventCallback,
    TlsEventCallback,
    NULL
};

void WINAPI EventCallback(_In_ PEVENT_RECORD ev)
{
    if (!IsEqualGUID(&ev->EventHeader.ProviderId, &QuicEtwProviderId)) {
        return;
    }

    QUIC_EVENT_TYPE EventType = GetEventType(ev->EventHeader.EventDescriptor.Id);
    _Analysis_assume_(EventType >= 0);
    if (EventType >= EventType_Count) {
        printf("WARNING: Unknown Event Type: %u\n", (UINT32)EventType);
        return;
    }

    Trace.EventCount++;
    Trace.EventTypeCount[EventType]++;

    USHORT EventId = GetEventId(ev->EventHeader.EventDescriptor.Id);
    _Analysis_assume_(EventId >= 0);
    if (EventId >= EventCounts[EventType].Length) {
        printf("WARNING: Unknown Event ID: %hu (Type=%u)\n", EventId, (UINT32)EventType);
    } else {
        EventCounts[EventType].Counts[EventId]++;
    }

    if (Trace.StartTimestamp == 0) {
        Trace.StartTimestamp = ev->EventHeader.TimeStamp.QuadPart;
    }

    ULONG ObjectId = 0;
    BOOLEAN TraceEvent = Cmd.Command == COMMAND_TRACE;
    ULONG64 InitialTimestamp = Trace.StartTimestamp;
    if (EventHandlers[EventType] != NULL) {
        EventHandlers[EventType](ev, &ObjectId, &TraceEvent, &InitialTimestamp);
    }

    if (TraceEvent) {
        QuicTraceEvent(ev, ObjectId, InitialTimestamp);
    }

    Trace.StopTimestamp = ev->EventHeader.TimeStamp.QuadPart;
}

BOOLEAN OpenTraceFile(const char* FileName)
{
    EVENT_TRACE_LOGFILEA LogFile = {0};
    LogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    LogFile.EventRecordCallback = EventCallback;
    LogFile.LogFileName = (LPSTR)FileName;

    Trace.Handle = OpenTraceA(&LogFile);
    if (Trace.Handle == INVALID_PROCESSTRACE_HANDLE) {
        int Err = GetLastError();
        printf("OpenTrace failed with %u\n", Err);
        return FALSE;
    }

    if (LogFile.LogfileHeader.BuffersLost != 0) {
        printf("WARNING: Lost %u buffers!\n", LogFile.LogfileHeader.BuffersLost);
    }

    if (LogFile.LogfileHeader.EventsLost != 0) {
        printf("WARNING: Lost %u events!\n", LogFile.LogfileHeader.EventsLost);
    }

    return TRUE;
}

BOOLEAN CollectTrace(void)
{
    UCHAR PropertiesBuffer[
        sizeof(EVENT_TRACE_PROPERTIES) +
        sizeof(QuicEtwSessionName) +
        sizeof(QuicEtwFileName)] = {0};
    EVENT_TRACE_PROPERTIES* Properties = (EVENT_TRACE_PROPERTIES*)PropertiesBuffer;
    BOOLEAN Success = FALSE;
    BOOLEAN Stop = FALSE;

    Properties->Wnode.BufferSize = sizeof(PropertiesBuffer);
    Properties->Wnode.Guid = QuicEtwSessionGuid;
    Properties->Wnode.ClientContext = 1; // QPC clock resolution
    Properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    Properties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    Properties->MaximumFileSize = 10;  // 10 MB
    Properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    Properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(QuicEtwSessionName);
    memcpy(PropertiesBuffer + Properties->LogFileNameOffset, QuicEtwFileName, sizeof(QuicEtwFileName));

    ULONG Err = StartTraceA(&Trace.Handle, QuicEtwSessionName, Properties);
    if (Err != ERROR_SUCCESS) {
        printf("StartTrace failed with %u\n", Err);
        goto Cleanup;
    }
    Stop = TRUE;

    Err = EnableTraceEx2(
        Trace.Handle,
        &QuicEtwProviderId,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, // TODO - Only low volume events?
        0,
        0,
        NULL
        );
    if (Err != ERROR_SUCCESS) {
        printf("EnableTraceEx2 failed with %u\n", Err);
        goto Cleanup;
    }

    Sleep(250); // Just let the rundowns fire.

    Err = ControlTraceA(
        Trace.Handle,
        QuicEtwSessionName,
        Properties,
        EVENT_TRACE_CONTROL_STOP);
    if (Err != ERROR_SUCCESS) {
        printf("ControlTrace(STOP) failed with %u\n", Err);
        goto Cleanup;
    }
    Stop = FALSE;

    Success = OpenTraceFile(QuicEtwFileName);

Cleanup:

    if (Stop) {
        Err = ControlTraceA(
            Trace.Handle,
            QuicEtwSessionName,
            Properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    return Success;
}

void RunProcessTrace(void)
{
    ObjectSetReset(&Workers);
    ObjectSetReset(&Sessions);
    ObjectSetReset(&Listeners);
    ObjectSetReset(&Cxns);
    ObjectSetReset(&Streams);
    ObjectSetReset(&Bindings);

    Trace.EventCount = 0;
    Trace.ApiCallCount = 0;
    ZeroMemory(Trace.EventTypeCount, sizeof(Trace.EventTypeCount));
    for (UINT32 i = 0; i < ARRAYSIZE(EventCounts); ++i) {
        ZeroMemory(
            EventCounts[i].Counts,
            EventCounts[i].Length * sizeof(UINT64));
    }
    ZeroMemory(ApiStats, sizeof(ApiStats));
    Trace.StartTimestamp = 0;
    Trace.StopTimestamp = 0;
    Trace.HasSchedulingEvents = FALSE;
    Trace.HasDatapathEvents = FALSE;

    LARGE_INTEGER Frequency, ProcessStart;
    QueryPerformanceFrequency(&Frequency);
    QueryPerformanceCounter(&ProcessStart);

    int Err = ProcessTrace(&Trace.Handle, 1, 0, 0);
    if (Err != NO_ERROR) {
        printf("ProcessTrace failed with %u\n", Err);
        exit(1);
    }

    LARGE_INTEGER ProcessEnd;
    QueryPerformanceCounter(&ProcessEnd);
    Trace.ProcessedMs = ProcessEnd.QuadPart - ProcessStart.QuadPart;
    Trace.ProcessedMs *= 1000000;
    Trace.ProcessedMs /= Frequency.QuadPart;
    Trace.ProcessedMs /= 1000;

    Trace.Processed = TRUE;
}

#define InvalidCommandUsage() printf(USAGE_PART2); return

void ProcessCommandArgs(int argc, char** argv)
{
    BOOLEAN ProcessTraceFile = !Trace.Processed;
    Cmd.Sort = SORT_NONE;
    Cmd.Filter = FILTER_NONE;
    Cmd.Command = COMMAND_NONE;
    Cmd.SelectedId = 0;
    Cmd.OutputResolution = MS_TO_NS100(100);
    Cmd.MaxOutputLines = ULONG_MAX;
    Cmd.CidLength = 0;
    Cmd.Verbose = FALSE;
    Trace.OutputLineCount = 0;

    QJSON QjWorkSpace = {0};

    while (argc > 0) {

        if (!strcmp(*argv, "--help") ||
            !strcmp(*argv, "--?") ||
            !strcmp(*argv, "-?") ||
            !strcmp(*argv, "?")) {
            if (argc > 1) {
                InvalidCommandUsage(); // TODO - Support per command help.
            } else {
                InvalidCommandUsage();
            }
        } else if (!strcmp(*argv, "--summary")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_SUMMARY;

        } else if (!strcmp(*argv, "--report")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_REPORT;

        } else if (!strcmp(*argv, "--trace")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_TRACE;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--conn")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_CONN;

        } else if (!strcmp(*argv, "--conn_list")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_CONN_LIST;

        } else if (!strcmp(*argv, "--conn_tput")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_CONN_TPUT;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--conn_trace")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_CONN_TRACE;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--conn_qlog")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_CONN_QLOG;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--worker")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_WORKER;

        } else if (!strcmp(*argv, "--worker_list")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_WORKER_LIST;

        } else if (!strcmp(*argv, "--worker_queue")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_WORKER_QUEUE;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--worker_trace")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_WORKER_TRACE;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--stream_trace")) {
            if (Cmd.Command != COMMAND_NONE) {
                InvalidCommandUsage();
            }
            Cmd.Command = COMMAND_STREAM_TRACE;
            ProcessTraceFile = TRUE;

        } else if (!strcmp(*argv, "--sort")) {
            if (argc < 2 || Cmd.SelectedId != 0) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            Cmd.Sort = StringToSortType(*argv);
            if (Cmd.Sort == SORT_NONE) {
                printf("Invalid sort: '%s'\n", *argv);
                InvalidCommandUsage();
            }

        } else if (!strcmp(*argv, "--filter")) {
            if (argc < 2 || Cmd.SelectedId != 0) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            Cmd.Filter = StringToFilterType(*argv);
            if (Cmd.Filter == FILTER_NONE) {
                printf("Invalid filter: '%s'\n", *argv);
                InvalidCommandUsage();
            }

        } else if (!strcmp(*argv, "--id")) {
            if (argc < 2 || Cmd.Sort != SORT_NONE) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            Cmd.SelectedId = atoi(*argv);

        } else if (!strcmp(*argv, "--reso")) {
            if (argc < 2) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            Cmd.OutputResolution = MS_TO_NS100(atoi(*argv));

        } else if (!strcmp(*argv, "--top")) {
            if (argc < 2) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            Cmd.MaxOutputLines = atoi(*argv);

        } else if (!strcmp(*argv, "--cid")) {
            if (argc < 2) {
                InvalidCommandUsage();
            }
            argc--; argv++;
            ReadCid(*argv);

        } else if (!strcmp(*argv, "--verbose")) {
            Cmd.Verbose = TRUE;

        } else {
            printf("Invalid arg: '%s'\n", *argv);
            InvalidCommandUsage();
        }
        argc--; argv++;
    }

    switch (Cmd.Command) {
    case COMMAND_NONE:
        InvalidCommandUsage();
        return;
    case COMMAND_CONN:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0 && Cmd.CidLength == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    case COMMAND_CONN_TPUT:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0 && Cmd.CidLength == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    case COMMAND_CONN_TRACE:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0 && Cmd.CidLength == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    case COMMAND_CONN_QLOG:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0 && Cmd.CidLength == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    case COMMAND_WORKER:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    case COMMAND_WORKER_QUEUE:
        if (Cmd.Sort == SORT_NONE && Cmd.SelectedId == 0) {
            InvalidCommandUsage();
            return;
        }
        break;
    }

    if (Cmd.FormatCSV) {
        switch (Cmd.Command) {
        case COMMAND_CONN_LIST:
            printf("ID,State,Age(us),Active(us),Queued(us),Idle(us),TX,RX,LocalIp,RemoteIp,SourceCid,DestinationCID\n");
            break;
        case COMMAND_CONN_TPUT:
            printf("ms,TxMbps,RxMbps,RttMs,CongEvents,InFlight,Cwnd,TxBufBytes,FlowAvailStrm,FlowAvailConn,SsThresh,CubicK,CubicWindowMax,StrmSndWnd\n");
            break;
        case COMMAND_WORKER_LIST:
            printf("ID,Thread,IdealProc,CxnCount,Age(us),Active(us)\n");
            break;
        case COMMAND_WORKER_QUEUE:
            printf("ms,CxnCount,CxnQueueLength,AvgQueueDelay(us),AvgCxnQuantum(us)\n");
            break;
        default:
            break;
        }
    }

    if (Cmd.Command == COMMAND_CONN_QLOG) {
        Qj = &QjWorkSpace;
        if (!QjOpen(Qj, "conn.qlog")) {
            printf("Failed to open 'conn.qlog'\n");
            return;
        }
        QjWriteString(Qj, "qlog_version", "draft-00");
        QjObjectStart(Qj, "configuration");
        QjWriteString(Qj, "time_units", "ms"); // TODO - Tools don't work well with 'us' right now
        QjObjectEnd(Qj);
        QjArrayStart(Qj, "traces");
    }

    if (ProcessTraceFile) {
        RunProcessTrace();
    }

    switch (Cmd.Command) {
    case COMMAND_SUMMARY:
        ExecuteSummaryCommand();
        break;
    case COMMAND_REPORT:
        ExecuteReportCommand();
        break;
    case COMMAND_CONN:
    case COMMAND_CONN_LIST:
    case COMMAND_CONN_TPUT:
    case COMMAND_CONN_TRACE:
    case COMMAND_CONN_QLOG:
        ExecuteCxnCommand();
        break;
    case COMMAND_WORKER:
    case COMMAND_WORKER_LIST:
    case COMMAND_WORKER_QUEUE:
        ExecuteWorkerCommand();
        break;
    default:
        break;
    }

    if (Qj != NULL) {
        QjArrayEnd(Qj);
        QjClose(Qj);
    }

    if (Cmd.MaxOutputLines != ULONG_MAX &&
        Trace.OutputLineCount > Cmd.MaxOutputLines) {
        printf("\nFiltered %u output lines. Overwrite with --top <num> option.\n",
            (Trace.OutputLineCount - Cmd.MaxOutputLines));
    }
}

void TerminateString(char* str)
{
    char* find = strchr(str, ' ');
    if (find == NULL) find = strchr(str, '\t');
    if (find == NULL) find = strchr(str, '\r');
    if (find == NULL) find = strchr(str, '\n');
    if (find != NULL) {
        *find = '\0';
    }
}

#define InvalidUsage() printf(USAGE USAGE_PART2); exit(ERROR_INVALID_PARAMETER)

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int Err = NO_ERROR;
    BOOLEAN LoadManifest = FALSE;
    wchar_t ManifestFilePath[256] = {0};

    CxPlatSystemLoad();
    CxPlatInitialize();

    if (argc < 2) {
        InvalidUsage();
    }

    if (!strcmp(argv[1], "--help") ||
        !strcmp(argv[1], "--?") ||
        !strcmp(argv[1], "-?") ||
        !strcmp(argv[1], "?")) {
        if (argc > 2) {
            InvalidUsage(); // TODO - Support per command help.
        } else {
            InvalidUsage();
        }
    }

    char* Arg1 = argv[1];
    argc-=2; argv+=2;

    while (argc > 0) {
        if (!strcmp(*argv, "--man")) {
            if (argc < 2) {
                InvalidUsage();
            }
            argc--; argv++;
            if (!strcmp(*argv, "sdxroot")) {
                DWORD Len =
                    GetEnvironmentVariableW(
                        L"SDXROOT", // Returns something like 'g:\os\src'
                        ManifestFilePath,
                        ARRAYSIZE(ManifestFilePath));
                if (Len == 0) {
                    printf("%%SDXROOT%% not found!!!");
                    exit(ERROR_INVALID_PARAMETER);
                }
                memcpy_s(
                    ManifestFilePath + Len, sizeof(ManifestFilePath),
                    QUIC_MAN_PATH, sizeof(QUIC_MAN_PATH));
            } else {
                size_t CharsConverted;
                mbstowcs_s(
                    &CharsConverted,
                    ManifestFilePath,
                    ARRAYSIZE(ManifestFilePath),
                    *argv,
                    _TRUNCATE);
            }
            LoadManifest = TRUE;

        } else if (!strcmp(*argv, "--csv")) {
            Cmd.FormatCSV = TRUE;

        } else {
            break;
        }
        argc--; argv++;
    }

    if (LoadManifest) {
        Err = TdhLoadManifest(ManifestFilePath);
        if (Err != NO_ERROR) {
            printf("TdhLoadManifest(%ws) failed with %u\n", ManifestFilePath, Err);
            LoadManifest = FALSE;
            goto Done;
        }
    }

    if (!strcmp(Arg1, "--local")) {
        if (!CollectTrace()) {
            goto Done;
        }
    } else {
        if (!OpenTraceFile(Arg1)) {
            goto Done;
        }
    }

    if (argc != 0) {
        ProcessCommandArgs(argc, argv);

    } else {
        const char* Delims = " \t";
        char* LocalArgv[16] = {0};
        char LocalArgBuffer[256];

        for (;;) {
            printf("\nquicetw>");
            fgets(LocalArgBuffer, ARRAYSIZE(LocalArgBuffer), stdin);

            char* NextToken = NULL;
            char* Token = strtok_s(LocalArgBuffer, Delims, &NextToken);

            argc = 0;
            while (Token != NULL && argc < ARRAYSIZE(LocalArgv)) {
                LocalArgv[argc++] = Token;
                Token = strtok_s(NULL, Delims, &NextToken);
            }

            if (argc != 0) {
                for (int i = 0; i < argc; ++i) {
                    TerminateString(LocalArgv[i]);
                }
                if (!strcmp(*LocalArgv, "--exit") ||
                    !strcmp(*LocalArgv, "exit")) {
                    break;
                }
                ProcessCommandArgs(argc, LocalArgv);
            }
        }
    }

Done:

    ObjectSetDestroy(&Workers);
    ObjectSetDestroy(&Sessions);
    ObjectSetDestroy(&Listeners);
    ObjectSetDestroy(&Cxns);
    ObjectSetDestroy(&Streams);
    ObjectSetDestroy(&Bindings);

    if (LoadManifest) {
        TdhUnloadManifest(ManifestFilePath);
    }

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return Err;
}
