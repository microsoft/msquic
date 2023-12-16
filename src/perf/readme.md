# Secured Network Performance Testing

SecNetPerf is the standard (cross-platform) tool used for performance testing of MsQuic. It implements the protocol defined [here](https://tools.ietf.org/html/draft-banks-quic-performance). This protocol defines a generic interface that allows for client-driven performance testing.

# Server

The server generally is meant to be run zero or minimal additional arguments.

```
> secnetperf
```

There are a few arguments that can be passed to the server:

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

Since tests are client-driven, the client side of secnetperf generally has several arguments passed in to specify which scenarios to run.

```
> secnetperf -test:client -target:perf-server -download:10000000
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
upload, up, request | `-upload:<value>` | The length of bytes to send on each stream.
download, down, response | `-download:<value>` | The length of bytes to receive on each stream.
iosize | `-iosize:<value>` | The size of each send request queued.
timed | `-timed:<0,1>` | Indicates the upload/download args are times (in ms).
rconn | `-rconn:<0,1>` | Repeat the scenario at the connection level.
rstream | `-rstream:<0,1>` | Repeat the scenario at the stream level.
runtime, run, time | `-runtime:<value>` | The total runtime (in ms). Only relevant for repeat scenarios.
