# Diagnosing Issues with MsQuic

This document describes various ways to debug and diagnose issues when using MsQuic.

# Logging

For functional problems, generally logging is the best way to diagnose problems. MsQuic has extensive logs in the code to facilitate debugging.

## Windows

On Windows, MsQuic leverages [ETW](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) for its logging.

To start collecting a trace, you can use the following command:

```
netsh.exe trace start overwrite=yes report=dis correlation=dis traceFile=quic.etl provider={ff15e657-4f26-570e-88ab-0796b258d11c} level=0x5 keywords=0xffffffff
```

And to stop log the trace session, you can use the following command:

```
netsh.exe trace stop
```

To convert the trace, you can use the following command:

```
netsh.exe trace convert quic.etl
```

> **Important** - If you're using a version of MsQuic that uses an ETW manifest version more recent than the one built into the Windows image, decoding may not provide correct output. **TODO** - Provide instructions to get around this problem.

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

# Performance

When dealing with performance issues or you're just trying to profile the performance of the system logging isn't usually the best way forward. The following sections describe a few ways to anaylze difference performance characteristics of MsQuic.

## Traces


## Windows

First off, you're going to need xperf and wpa. Installing the [Windows ADK](https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install) is one of the easiest ways to get them.

## Counters

# FAQ
