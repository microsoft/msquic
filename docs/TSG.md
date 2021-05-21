# Trouble Shooting Guide

This document is meant to be a step-by-step guide for trouble shooting any issues while using MsQuic.

## What kind of Issue are you having?

1. [I am debugging a crash.](#debugging-a-crash)
2. [Something is not functionally working as I expect.](#trouble-shooting-a-functional-issue)
3. [Performance is not what I expect it to be.](#trouble-shooting-a-performance-issue)

# Debugging a Crash

> TODO

# Trouble Shooting a Functional Issue

1. [I am getting an error code I don't understand.](#understanding-error-codes)
2. [The connection is unexpectedly shutting down.](#why-is-the-connection-shutting-down)
3. [No application (stream) data seems to be flowing.](#why-isnt-application-data-flowing)
4. [Why is this API failing?](#why-is-this-api-failing)

## Understanding Error Codes

Some error codes are MsQuic specific (`QUIC_STATUS_*`), and some are simply a passthrough from the platform. You can find the MsQuic specific error codes in the platform specific header ([msquic_posix.h](../src/inc/msquic_posix.h), [msquic_winkernel.h](../src/inc/msquic_winkernel.h), or [msquic_winuser.h](../src/inc/msquic_winuser.h)).

From [msquic_winuser.h](../src/inc/msquic_winuser.h):
```C
#define QUIC_STATUS_ADDRESS_IN_USE          HRESULT_FROM_WIN32(WSAEADDRINUSE)               // 0x80072740
#define QUIC_STATUS_CONNECTION_TIMEOUT      ERROR_QUIC_CONNECTION_TIMEOUT                   // 0x80410006
#define QUIC_STATUS_CONNECTION_IDLE         ERROR_QUIC_CONNECTION_IDLE                      // 0x80410005
#define QUIC_STATUS_UNREACHABLE             HRESULT_FROM_WIN32(ERROR_HOST_UNREACHABLE)      // 0x800704d0
#define QUIC_STATUS_INTERNAL_ERROR          ERROR_QUIC_INTERNAL_ERROR                       // 0x80410003
```

For more info, see the [Well Known Status Codes](./api/QUIC_STATUS.md#well-known-status-codes).

### Linux File Handle Limit Too Small

In many Linux setups, the default per-process file handle limit is relatively small (~1024). In scenarios where lots of (usually client) connection are opened, a large number of sockets (a type of file handle) are created. Eventually the handle limit is reached and connections start failing (error codes `0x16` or `0xbebc202`) because new sockets cannot be created. To fix this, you will need to increase the handle limit.

To query the maximum limit you may set:
```
ulimit -Hn
```

To set a new limit (up to the max):
```
ulimit -n newValue
```

## Why is the connection shutting down?

1. [What does this QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT event mean?](#understanding-shutdown-by-transport)
2. [What does this QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_APP event mean?](#understanding-shutdown-by-app)

### Understanding shutdown by Transport.

There are two ways for a connection to be shutdown, either by the application layer or by the transport layer (i.e. the QUIC layer). The `QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT` event occurs when the transport shuts the connection down. Generally, the transport shuts down the connection either when there's some kind of error or if the negotiated idle period has elapsed.

```
[2]6F30.34B0::2021/04/13-09:22:48.297449100 [Microsoft-Quic][conn][0x1CF25AC46B0] Transport Shutdown: 18446744071566327813 (Remote=0) (QS=1)
```

Above is an example event collected during an attempt to connect to a non-existent server. Eventually the connection failed and the transport indicated the event with the appropriate error code. This error code (`18446744071566327813`) maps to `0xFFFFFFFF80410005`, which specifically refers to the `QUIC_STATUS` (indicated by `QS=1`) for `0x80410005`; which indicates `ERROR_QUIC_CONNECTION_IDLE`. For more details for understanding error codes see [here](#understanding-error-codes).

### Understanding shutdown by App.

As indicated in [Understanding shutdown by Transport](#understanding-shutdown-by-transport), there are two ways for connections to be shutdown. The `QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_APP` event occurs when the peer application has explicitly shut down the connection. In MsQuic API terms, this would mean the app called [ConnectionShutdown](./api/connectionshutdown.md).

> TODO - Add an example event

The error code indicated in this event is completely application defined (type of `QUIC_UINT62`). The transport has no understanding of the meaning of this value. It never generates these error codes itself. So, to map these values to some meaning will require the application protocol documentation.

## Why isn't application data flowing?

> TODO

## Why is this API Failing?

The simplest way to determine exactly why a particular API is failing is via tracing. [Collect the traces](./Diagnostics.md#trace-collection) for the repro and convert them to text and open them in your favorite text editor (try [TextAnalysisTool](./Diagnostics.md#text-analysis-tool)!).

MsQuic logs every API entry and exit. Depending on the platform and tool used to decode the traces to text, you may either have the number or an enum represented as the API type (see `QUIC_TRACE_API_TYPE` in [quic_trace.h](../src/inc/quic_trace.h)), but all events look something like this:

```
[cpu][process.thread][time][ api] Enter <API Type> (<pointer>)
[cpu][process.thread][time][ api] Exit [optional status code]
```

### Example (ListenerStart failing with QUIC_STATUS_INVALID_STATE)

In a recent example, we wanted to know why an app occasionally received `QUIC_STATUS_INVALID_STATE` when it called `ListenerStart`. We took the following steps to diagnose it.

1. Collected traces for the repro.
2. Converted to text and opened them in [TextAnalysisTool](./Diagnostics.md#text-analysis-tool).
3. Added a filter for all API enter events for `QUIC_TRACE_API_LISTENER_START` (`10`).
4. Looked for the following `[ api] Exit` event after each enter event on the same `[process.thread]`.

This quickly resulted in the following pair of events. They show the app called `ListenerStart` for the listener pointer `7f30ac0dcff0` at `09:54:03.528362` in process `2e73` on thread `2e8b` (CPU 1). Shortly after, MsQuic returned with status `200000002` (`QUIC_STATUS_INVALID_STATE` on Posix platforms).

```
[1][2e73.2e8b][09:54:03.528362][ api] Enter 10 (0x7f30ac0dcff0).
[1][2e73.2e8b][09:54:03.528913][ api] Exit 200000002
```

From here, we simply went backwards from the exit event to find any errors; and came up with the full set of important traces:

```
[1][2e73.2e8b][09:54:03.528362][ api] Enter 10 (0x7f30ac0dcff0).
[1][2e73.2e8b][09:54:03.528902][bind][0x7f30b80394e0] Listener (0x7f30ac076d90) already registered on ALPN
[1][2e73.2e8b][09:54:03.528903][list][0x7f30ac0dcff0] ERROR, "Register with binding".
[1][2e73.2e8b][09:54:03.528913][ api] Exit 200000002
```

This clearly shows that listener `7f30ac0dcff0` failed to register with the binding (i.e. UDP socket abstraction) because listener `7f30ac076d90` was already registered for the same ALPN. MsQuic only allows a single listener to be registered for a given ALPN on a local IP address and port.

# Trouble Shooting a Performance Issue

1. [Is it a problem with just a single (or very few) connection?](#why-in-performance-bad-for-my-connection)
2. [Is it a problem multiple (lots) of connections?](#why-is-performance-bad-across-all-my-connections)

## Why is Performance bad for my Connection?

1. [Where is the CPU being spent for my connection?](#analyzing-cpu-usage)
2. [What is limiting throughput for my connection?](#finding-throughput-bottlenecks)
3.

### Analyzing CPU Usage

> **Important** - The following is specific to Windows OS.

It's extremely common that everything may be functional, but not just as fast as expected. So the normal next step is then to grab a performance trace for the scenario and then dive into the details to analyze what exactly is happening. When you're explicitly looking for where the CPU is spending its time in the scenario, you will need to collect CPU traces. One way to do this is to [use WPR](./Diagnostics.md#using-wpr-to-collect-traces) (with `Stacks.Light` profile).

Once you have the ETL, open it [in WPA](../src/plugins/wpa/README.md) (MsQuic plugin is unnecessary). Then, go to the `Graph Explorer`, expand `Computation`, expand `CPU Usage (Sampled)` and open up `Utilization by Process, Thread, Stack`. The following is an example of a CPU trace a server in a client upload scenario:

![](images/cpu-debug-1.png)

The next step is to filter things down to only the important information. First, select the relavent time period: click and drag over the area, right click, select `Zoom`.

![](images/cpu-debug-2.png)

Then eliminate any unrelated "noise". The easiest way is to select all the Processes that have very little weight; then right click, and select `Filter Out Selection`. Another important thing to filter is the `[Idle]` stack under the `Idle (0)` process. Expact the `Thread ID` column for `Idle (0)`, right click the `[Idle]` row and then select `Filter Out Selection`. You should then be left with only the relavent CPU usage.

![](images/cpu-debug-3.png)

The current view now shows the CPU usage as a fraction of the total available CPU resources. Generally, the total available resources will include multiple (possibly many) different CPUs. So, it's a lot more helpful to get a per-CPU view. To see this, right click the table header (for instance, on `Process`), expand `More Columns ...`, and select `CPU`. Next, drag the `CPU` column to the front, before `Process`.

Initially, nothing will most likely show up in the graph view. You will need to manually enable the relavent CPUs. In this particular example, only CPUs 4 and 36 have any significant usage (as seen by `Count` or `Weight` columns). In the `Series` list in the graph view, click the boxes next to each relavent CPU series to enable it. You may also chose to explicitly filter out the CPUs that are irrelevant.

![](images/cpu-debug-4.png)

Now, you could use this view to dig into the various stacks by expanding the rows under the `Stack` column, but a better way is to change the view to a Flame Graph. Click the icon at the top to `Select chart type` and change it to `Flame`. Additionally, check the `Enable` box under it to enable filtering.

![](images/cpu-debug-5.png)

You can then slide the filter slider to change the level of filtering. In this example, after resizing the window some, it looks like this:

![](images/cpu-debug-6.png)

As you will immediately see, `<Symbols disabled>` shows up everywhere because symbols haven't been loaded. To load them, you will first need to configure the symbol path. You can do this by clicking on `Trace` in the top and then `Configure Symbol Path`. Then add any relavent paths to the list and close the window (hit `Ok`). Next you can load the symbols; `Trace` -> `Load Symbols`.

![](images/cpu-debug-7.png)

This example has just the `msquic.dll` and `secnetperf.exe` symbols loaded. You can then drill down to various various part of the flame, and zoom into them by right clicking on them and selecting `Filter To Flame`. Also, remember you can change the Flame filter slider at any time as well. For example, the following is what filtering to the `msquic.dll!QuicWorkerThread` flame.

![](images/cpu-debug-8.png)

Since this flame was essentially all of CPU 4, whatever is taking the most significant CPU resources here can be blamed as the most significant cost of CPU resources. Practically, this comes down to `bcrypt.dll`. From experience, since this happens in `QuicConnRecvDecryptAndAuthenticate` this is the work related to decrypting the packet payloads (over 71% of the CPU!).

### Finding Throughput Bottlenecks

> TODO

## Why is Performance bad across all my Connections?

1. [The work load isn't spreading evenly across cores.](#diagnosing-rss-issues)
2.

### Diagnosing RSS Issues

> **Important** - The following is specific to Windows OS.

For scenarios with lots of parallel connections, generally the work should be spread across all the available processors. But if there are issues with the work not spreading there are a few things you can do. First off, here's an example where the RPS tests were run to a server that should be able to handle near 1 million requests per second:

```
> secnetperf.exe -test:RPS -target:quic-server -conns:250 -requests:7500 -request:0 -response:4096 -runtime:20000
All Connected! Waiting for idle.
Start sending request...
Started!

Result: 25869 RPS, Min: 944, Max: 888078, 50th: 281889.000000, 90th: 369965.000000, 99th: 490582.000000, 99.9th: 574533.000000, 99.99th: 797810.000000, 99.999th: 884055.000000, 99.9999th: 888078.000000, StdErr: 91.224221
App Main returning status 0
```

As you can see from the output of `secnetperf.exe` the resulting `25869 RPS` is nowhere near what it should be. The next step is to grab a performance trace to see what is going on. For these type of issues the best way to collect the traces would be to [use WPR](./Diagnostics.md#using-wpr-to-collect-traces) (with `Scheduling.Verbose` or `Performance.Verbose` profiles).

Once you have the ETL, open it [in WPA using the MsQuic plugin](../src/plugins/trace/README.md). First thing after opening, let's take a look at the QUIC Worker utilization. In the `Graph Explorer`, under `Computation`, expand `QUIC Workers` and open the one labeled `Utilization by Worker`. For the example above (server-side trace), here is what the output looks like:

![](images/rss-debug-1.png)

You can immediately see that only 2 different workers are being used, with worker `2` being used primarily.

> **In depth details** - MsQuic always uses at least two workers on the server side for per connection. The first worker is a global, shared worker that is used to do initial validation of the connection request. Its job is to figure out which app the incoming connection belongs to. Once that's complete, the connection will be handed off to that app (and its worker thread(s)). So, this is why you only see usage of worker `1` at the beginning of the trace.

The first usage spikes are from the RPS test initially connecting all its (250) parallel connections. There is a bit of back and forth to do the handshakes for these connections. Then there is an idle period while the test waits for things to die down. Finally, the actual RPS tests commense and that is where you see the solid usage of worker `2`.

Ideally, RPS tests should generate work that is spread across **many** different workers. The fact that only 1 worker is being used is definitely the source of the low RPS numbers that were measured and indicated in the tool output above. Since MsQuic picks which workers to use based on how the UDP datagrams are received, the next step is to look into the UDP receive layer.

One way to do this is by using the `Generic Events` table (under `System Activity` in the `Graph Explorer`). Open that up, and then filter to just MsQuic (also shows up as `ff15e657-4f26-570e-88ab-0796b258d11c` some times) `Provider Name` (Right Click -> `Filter To Selection`). Next, we're looking for specifically the datapath receive events, which are `Id` 9218. Filter to just those and we see something like this:

![](images/rss-debug-2.png)

Now, what we're really interested in is what CPU these events are coming in on. So, add the CPU column to the left of the yellow bar. It doesn't really show a much different picture, but you can clearly see that all events happen on CPU 0.

![](images/rss-debug-3.png)

Now, we can clearly see that all our receive events are happening on the same CPU. This definitely not supposed to happen in an environment where RSS should be spreading all the different incoming UDP flows/tuples to different processors.

The next step is to take a look at the RSS configuration on the machine to ensure things are properly configured. Run `Get-NetAdapterRss` to get an output like this:

```
Name                                            : Slot0A x8
InterfaceDescription                            : Mellanox ConnectX-3 Pro Ethernet Adapter
Enabled                                         : True
NumberOfReceiveQueues                           : 8
Profile                                         : Closest
BaseProcessor: [Group:Number]                   : 0:0
MaxProcessor: [Group:Number]                    : 1:38
MaxProcessors                                   : 8
RssProcessorArray: [Group:Number/NUMA Distance] : 0:0/0  0:2/0  0:4/0  0:6/0  0:8/0  0:10/0  0:12/0  0:14/0
                                                  0:16/0  0:18/0  0:20/0  0:22/0  0:24/0  0:26/0  0:28/0  0:30/0
                                                  0:32/0  0:34/0  0:36/0  0:38/0  1:0/32767  1:2/32767  1:4/32767
                                                  1:6/32767
                                                  1:8/32767  1:10/32767  1:12/32767  1:14/32767  1:16/32767
                                                  1:18/32767  1:20/32767  1:22/32767
                                                  1:24/32767  1:26/32767  1:28/32767  1:30/32767  1:32/32767
                                                  1:34/32767  1:36/32767  1:38/32767
IndirectionTable: [Group:Number]                : 0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
                                                  0:0   0:2     0:4     0:6     0:8     0:10    0:12    0:14
```

The output above indicates RSS is configured with 8 queues, so there should be spreading of the incoming flows to 8 different CPUs (and then passed to 8 different workers) instead of just the 1 that we are seeing. So, finally, in cases where everything seems to be configured correctly, but things **still** aren't working, that usually indicates a problem with the network card driver. Make sure the driver is up to date with the latest version available. If that still doesn't fix the problem, you will likely need to contact support from the network card vendor.
