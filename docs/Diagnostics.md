# Diagnosing Issues with MsQuic

This document describes various ways to debug and diagnose issues when using MsQuic.

# Trace Collection

For debugging issues, generally logging is the best way to diagnose problems. MsQuic has extensive logs in the code to facilitate debugging.

## Windows

On Windows, MsQuic leverages [ETW](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) for its logging.

To start collecting a trace, you can use the following command:

```
netsh.exe trace start overwrite=yes report=dis correlation=dis traceFile=quic.etl provider={ff15e657-4f26-570e-88ab-0796b258d11c} level=0x5 keywords=0xffffffff
```

> **Note** - The command above collects **all** keywords (`0xffffffff`) which may be too verbose for some scenarios, such as high throughput testing or large number of parallel connections. For a detailed list of the available keywords, see [MsQuicEtw.man](..\src\manifest\MsQuicEtw.man) and see `<keywords>`.

And to stop log the trace session, you can use the following command:

```
netsh.exe trace stop
```

To convert the trace, you can use the following command:

```
netsh.exe trace convert quic.etl
```

> **Important** - If you're using a version of MsQuic that uses an ETW manifest version more recent than the one built into the Windows image, decoding may not provide correct output. **TODO** - Provide instructions to get around this problem.

You may also open the trace in Windows Performance Analyzer. See the [WPA instructions](../src/plugins/trace/README.md) for more details.

### Using WPR to Collect Traces

You can also use [MsQuic.wprp](../src/manifest/MsQuic.wprp) along with `wpr.exe` (inbox on Windows) to collect several different, specifically tailored traces. Once you copy [MsQuic.wprp](../src/manifest/MsQuic.wprp) to the machine you wish to collect the traces for, you can simply run the following to start trace collection:

```
wpr.exe -start MsQuic.wprp!PROFILE -filemode
```

You must replace `PROFILE` with the name of the profile you want to run. You can find more details on the supported profiles farther below.

When you're done and ready to collect the logs, you run:

```
wpr.exe -stop ETL_PATH
```

You must replace `ETL_PATH` with the path of the output ETL file that you want to be written.

#### Available WPRP Profiles

- `Stacks.Light`- Collects CPU callstacks.
- `Performance.Light` - Collects all well-formated MsQuic events.
- `Performance.Verbose` - Collects CPU callstacks and all well-formated MsQuic events.
- `Basic.light` - Collects general, "low volume" MsQuic events.
- `Basic.Verbose` - Collects all MsQuic events.
- `Scheduling.Verbose` - Collects "low volume" and scheduling related MsQuic events.
- `Datapath.Light` - Collects "low volume" and datapath related MsQuic events.
- `Datapath.Verbose` - Collects CPU callstacks and "low volume" and datapath related MsQuic events.
- `Full.Light` - Collects all MsQuic events as well as [TAEF](https://docs.microsoft.com/en-us/windows-hardware/drivers/taef/) events.
- `Full.Verbose` - Collects All MsQuic events, [TAEF](https://docs.microsoft.com/en-us/windows-hardware/drivers/taef/) events and several networking components' events.
- `SpinQuic.Light` - Collects "low volume" and API related MsQuic events.

## Linux

On Linux, MsQuic leverages [LTTng](https://lttng.org/features/) for its logging.

To start collecting a trace, you can use the following commands:

```
mkdir msquic_lttng
lttng create msquic -o=./msquic_lttng
lttng enable-event --userspace CLOG_*
lttng add-context --userspace --type=vpid --type=vtid
lttng start
```

And to stop log the trace session, you can use the following command:

```
lttng stop msquic
```

To convert the trace, you can use the following commands:

```
babeltrace --names all ./msquic_lttng/* > quic.babel.txt
clog2text_lttng -i quic.babel.txt -s clog.sidecar -o quic.log --showTimestamp --showCpuInfo
```

> **Note** - The `clog.sidecar` file that was used to build MsQuic must be used. It can be found in the `./src/manifest` directory of the repository.

> **Note** - WPA support for LTTng based logs is not yet available but will be supported in the future.

# Trace Analysis

MsQuic supports a custom plugin for Windows Performance Analyzer (WPA) to detailed analysis of ETW traces. See the [WPA instructions](../src/plugins/trace/README.md) for more details.

## Text Analysis Tool

When viewing the traces as text, we recommend [TextAnalysisTool.NET](https://textanalysistool.github.io/) (Windows only) and we have several filter files we maintain for it ([folder](./tat)). The different filters are meant to quickly highlight and color code important information.

![](images/tat.png)

# Performance Counters

To assist investigations into running systems, MsQuic has a number of performance counters that are updated during runtime. These counters are exposed as an array of unsigned 64-bit integers, via a global `GetParam` parameter.
Sample code demonstrating how to query the performance counters:
```c
uint64_t Counters[QUIC_PERF_COUNTER_MAX];
uint32_t BufferLength = sizeof(Counters);
MsQuic->GetParam(
    NULL,
    QUIC_PARAM_LEVEL_GLOBAL,
    QUIC_PARAM_GLOBAL_PERF_COUNTERS,
    &BufferLength,
    Counters);
```

Each of the counters available is described here:
Counter | Description
--------|------------
QUIC_PERF_COUNTER_CONN_CREATED | Total connections ever allocated
QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL | Total connections that failed during handshake
QUIC_PERF_COUNTER_CONN_APP_REJECT | Total connections rejected by the application
QUIC_PERF_COUNTER_CONN_RESUMED | Total connections resumed
QUIC_PERF_COUNTER_CONN_ACTIVE | Connections currently allocated
QUIC_PERF_COUNTER_CONN_CONNECTED | Connections currently in the connected state
QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS | Total connections shutdown with a protocol error
QUIC_PERF_COUNTER_CONN_NO_ALPN | Total connection attempts with no matching ALPN
QUIC_PERF_COUNTER_STRM_ACTIVE | Current streams allocated
QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST | Total suspected packets lost
QUIC_PERF_COUNTER_PKTS_DROPPED | Total packets dropped for any reason
QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL | Total packets with decryption failures
QUIC_PERF_COUNTER_UDP_RECV | Total UDP datagrams received
QUIC_PERF_COUNTER_UDP_SEND | Total UDP datagrams sent
QUIC_PERF_COUNTER_UDP_RECV_BYTES | Total UDP payload bytes received
QUIC_PERF_COUNTER_UDP_SEND_BYTES | Total UDP payload bytes sent
QUIC_PERF_COUNTER_UDP_RECV_EVENTS | Total UDP receive events
QUIC_PERF_COUNTER_UDP_SEND_CALLS | Total UDP send API calls
QUIC_PERF_COUNTER_APP_SEND_BYTES | Total bytes sent by applications
QUIC_PERF_COUNTER_APP_RECV_BYTES | Total bytes received by applications
QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH | Current connections queued for processing
QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH | Current connection operations queued
QUIC_PERF_COUNTER_CONN_OPER_QUEUED | Total connection operations queued ever
QUIC_PERF_COUNTER_CONN_OPER_COMPLETED | Total connection operations processed ever
QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH | Current worker operations queued
QUIC_PERF_COUNTER_WORK_OPER_QUEUED | Total worker operations queued ever
QUIC_PERF_COUNTER_WORK_OPER_COMPLETED | Total worker operations processed ever

## Windows Performance Monitor

On the latest version of Windows, these counters are also exposed via PerfMon.exe under the `QUIC Performance Diagnostics` category. The values exposed via PerfMon **only represent kernel mode usages** of MsQuic, and do not include user mode counters.

![](images/perfmon.png)

## ETW

Counters are also captured at the beginning of MsQuic ETW traces, and unlike PerfMon, includes all MsQuic instances running on the system, both user and kernel mode.

# Detailed Troubleshooting

For detailed trouble shooting steps please see the MsQuic [Trouble Shooting Guide](TSG.md).
