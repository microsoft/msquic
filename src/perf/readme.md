# Secured Network Performance Testing

SecNetPerf is the standard (cross-platform) tool used for performance testing of MsQuic. It implements the protocol defined [here](https://tools.ietf.org/html/draft-banks-quic-performance). This protocol defines a generic interface that allows for client-driven performance testing.

# Server

The server generally is meant to be run zero or minimal additional arguments.

```
> secnetperf
```

or perhaps the following for high throughput tests:

```
> secnetperf -exec:maxtput
```

There are all the arguments that can be passed to the server:

Argument | Usage | Meaning
--- | --- | ---
bind | `-bind:<address>` | Binds to the specified local address.
cc | `-cc:<cubic,bbr>` | Congestion control algorithm used.
cibir | `-cibir:<hex_bytes>` | The well-known CIBIR identifier.
cipher | `-cipher:<value>` | Decimal value of 1 or more `QUIC_ALLOWED_CIPHER_SUITE_FLAGS`.
cpu | `-cpu:<cpu_indexes>` | Comma-separated list of CPUs to run on.
ecn | `-ecn:<0,1>` | Enables sender-side ECN support.
exec | `-exec:<lowlat,maxtput,scavenger,realtime>` | The execution profile used for the application.
pollidle | `-pollidle:<time_us>` | The time, in microseconds, to poll while idle before sleeping (falling back to interrupt-driven IO).
stats | `-stats:<0,1>` | Prints out statistics at the end of each connection.

# Client

Since tests are client-driven, the client side of secnetperf generally has several arguments passed in to specify which scenarios to run. For example, for a simple download test:

```
> secnetperf -target:perf-server -down:1gb
```

or for a repeated request/response style exchange

```
> secnetperf -target:perf-server -rstream:1 -run:10s -up:500 -down:4000
```

The `target` must be specified to indicate the hostname of the server to connect to. Note that `server`, `to`, `remote`, and `peer` are all aliases for `target`.

## Remote Options

The following options configure the behavior around connecting to the remote peer:

Alias | Usage | Meaning
--- | --- | ---
ip, af | `-ip:<0,4,6>` | A address family hint for resolving the hostname to IP address.
port | `-port:<value>` | The UDP port of the remote peer.
cibir | `-cibir:<hex_bytes>` | The well-known CIBIR identifier.
incttarget | `-inctarget:<0,1>` | Set to 1 to append core index to target hostname.

## Local Options

The following options configure the behavior related to local execution:

Alias | Usage | Meaning
--- | --- | ---
threads | `-threads:<value>` | The max number of worker threads to use.
affinitize | `-affinitize:<0,1>` | Affinitizes worker threads to a core.
comp | `-comp:<value>` | The network compartment ID to run in. **Windows Only**
bind | `-bind:<addr(s)>` | The local IP address(es)/port(s) to bind to.
share | `-share:<0,1>` | Set to 1 to append core index to target hostname.

## General Configuration Options

The following options control various general configuration options:

Alias | Usage | Meaning
--- | --- | ---
tcp | `-tcp:<0,1>` | Disables/enables TCP usage (instead of QUIC).
encrypt | `-encrypt:<0,1>` | Disables/enables encryption.
pacing | `-pacing:<0,1>` | Disables/enables send pacing.
sendbuf | `-sendbuf:<0,1>` | Disables/enables send buffering.
ptput | `-ptput:<0,1>` | Print throughput information.
pconnection, pconn | `-pconn:<0,1>` | Print connection statistics.
pstream | `-pstream:<0,1>` | Print stream statistics.
platency, plat | `-platency:<0,1>` | Print latency statistics.
praw | `-praw:<0,1>` | Print raw information.

## Scenario Options

The following options configure the various scenario behaviors:

Alias | Usage | Meaning
--- | --- | ---
conns | `-conns:<value>` | The number of connections to use.
streams, requests | `-streams:<value>` | The number of streams to send on at a time.
upload, up, request | `-upload:<value>[units]` | The length of bytes (or optional time or length unit) to send on each stream.
download, down, response | `-download:<value>[units]` | The length of bytes (or optional time or length unit) to receive on each stream.
iosize | `-iosize:<value>` | The size of each send request queued.
rconn, rc | `-rconn:<0,1>` | Repeat the scenario at the connection level.
rstream, rs | `-rstream:<0,1>` | Repeat the scenario at the stream level.
runtime, run, time | `-runtime:<value>[units]` | The total runtime (in us, or optional unit). Only relevant for repeat scenarios.

## Example Scenarios

Download for 5 seconds, printing throughput information
```
> secnetperf -target:localhost -exec:maxtput -down:5s -ptput:1
Started!

Download: 2996595053 bytes @ 4793496 kbps (5001.101 ms).
App Main returning status 0
```

Upload for 1 MB on 10 different streams, printing throughput information
```
> secnetperf -target:localhost -exec:maxtput -up:10mb -streams:10 -ptput:1
Started!

  Upload: 10000000 bytes @ 1517393 kbps (52.722 ms).
  Upload: 10000000 bytes @ 1513403 kbps (52.861 ms).
  Upload: 10000000 bytes @ 1055868 kbps (75.767 ms).
  Upload: 10000000 bytes @ 655189 kbps (122.102 ms).
  Upload: 10000000 bytes @ 458289 kbps (174.562 ms).
  Upload: 10000000 bytes @ 457202 kbps (174.977 ms).
  Upload: 10000000 bytes @ 404422 kbps (197.813 ms).
  Upload: 10000000 bytes @ 403960 kbps (198.039 ms).
  Upload: 10000000 bytes @ 403632 kbps (198.200 ms).
  Upload: 10000000 bytes @ 403057 kbps (198.483 ms).
App Main returning status 0
```

Upload for 10 seconds on 10 different connections, printing throughput information
```
> secnetperf -target:localhost -exec:maxtput -up:10s -conns:10 -ptput:1
Started!

  Upload: 3590914048 bytes @ 2869166 kbps (10012.423 ms).
  Upload: 3586523136 bytes @ 2865446 kbps (10013.163 ms).
  Upload: 1803091968 bytes @ 1439601 kbps (10019.950 ms).
  Upload: 1765015552 bytes @ 1408638 kbps (10023.949 ms).
  Upload: 1161232384 bytes @ 925992 kbps (10032.325 ms).
  Upload: 1208811520 bytes @ 963208 kbps (10039.870 ms).
  Upload: 1170145280 bytes @ 932025 kbps (10043.895 ms).
  Upload: 1198981120 bytes @ 954894 kbps (10044.932 ms).
  Upload: 1228996608 bytes @ 977891 kbps (10054.261 ms).
  Upload: 1196163072 bytes @ 951211 kbps (10060.125 ms).
App Main returning status 0
```

Send 512 byte requests, receive 4 KB responses on a single connection repeatidly for 7 seconds, printing total requests per second (RPS) and latency at the end
```
> secnetperf -target:localhost -rstream:1 -run:7s -up:512 -down:4kb -plat:1
Started!

Result: 21566 RPS, Latency,us 0th: 39, 50th: 44, 90th: 46, 99th: 108, 99.9th: 166, 99.99th: 235, 99.999th: 7456, 99.9999th: 7567, Max: 7567
App Main returning status 0
```

Do ths same as above, but using TCP/TLS instead of QUIC
```
> secnetperf -target:localhost -rstream:1 -run:7s -up:512 -down:4kb -plat:1 -tcp:1
Started!

Result: 30555 RPS, Latency,us 0th: 24, 50th: 32, 90th: 34, 99th: 81, 99.9th: 131, 99.99th: 192, 99.999th: 456, 99.9999th: 1766, Max: 1766
App Main returning status 0
```
