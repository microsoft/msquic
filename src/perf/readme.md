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

Since tests are client-driven, the client side of secnetperf generally has several arguments passed in to specify which test to run. Many of the arguments are also test specific, but the following (overlap with server) do apply to all:

Argument | Usage | Meaning
--- | --- | ---
cc | `-cc:<cubic,bbr>` | Congestion control algorithm used.
cipher | `-cipher:<value>` | Decimal value of 1 or more `QUIC_ALLOWED_CIPHER_SUITE_FLAGS`.
cpu | `-cpu:<cpu_indexes>` | Comma-separated list of CPUs to run on.
ecn | `-ecn:<0,1>` | Enables sender-side ECN support.
exec | `-exec:<lowlat,maxtput,scavenger,realtime>` | The execution profile used for the application.
pollidle | `-pollidle:<time_us>` | The time, in microseconds, to poll while idle before sleeping (falling back to interrupt-driven IO).

## Throughput Test

To run the throughput test, you must specify the `-test:tput` option, followed by a number of other arguments (most of which are optional).

### Examples

```
> secnetperf.exe -exec:maxtput -test:tput -target:127.0.0.1 -download:10000000
```

```
> secnetperf.exe -test:tput -target:127.0.0.1 -upload:10000 -timed:1 -stats:1
```

### Required

Argument | Usage | Meaning
--- | --- | ---
target,server | `-target:<hostname_or_IP>` | The target server to connect to. May be a hostname or an IP address.
download | `-download:<####>` | The length of data in bytes (or time with `-timed:1` arg) to receive. Mutually exclusive with `-upload` arg.
upload | `-upload:<####>` | The length of data in bytes (or time with `-timed:1` arg) to send. Mutually exclusive with `-download` arg.

### Optional

Argument | Usage | Meaning
--- | --- | ---
bind | `-bind:<address>` | Binds to the specified local address.
cc | `-cc:<cubic,bbr>` | Congestion control algorithm used.
cibir | `-cibir:<hex_bytes>` | The well-known CIBIR identifier.
comp | `-comp:<####>` | The compartment ID to run in. **Windows Only**
core | `-core:<####>` | The CPU to use for the main thread.
encrypt | `-encrypt:<0,1>` | Enables/disables encryption.
iosize | `-iosize:<####>` | The size of each send request queued.
ip | `-ip:<0,4,6> ` | A hint for the resolving the hostname to an IP address.
pacing | `-pacing:<0,1>` | Whether to use pacing.
port | `-port:<####>` | The UDP port of the server.
sendbuf | `-sendbuf:<0,1>` | Whether to use send buffering.
sstats | `-sstats:<0,1>` | Prints out stream-level statistics at the end of each stream.
stats | `-stats:<0,1>` | Prints out statistics at the end of each connection.
tcp | `-tcp:<0,1>` | Indicates TCP/TLS should be used instead of QUIC. **Windows Only**
timed | `-timed:<0,1>` | Indicates the `upload` & `download` arg represent time (ms).

## RPS Test

To run the "request per second" test, you must specify the `-test:rps` option, followed by a number of other arguments (most of which are optional).

### Examples

```
> secnetperf.exe -test:rps -target:127.0.0.1
```

```
> secnetperf.exe -test:rps -target:127.0.0.1 -runtime:1000 -response:8096 -stats:1
```

### Required

Argument | Usage | Meaning
--- | --- | ---
target,server | `-target:<hostname_or_IP>` | The target server to connect to. May be a hostname or an IP address.

### Optional

Argument | Usage | Meaning
--- | --- | ---
addrs | `-addrs:<####>` | The number of local addresses to use.
affinitize | `-affinitize:<0,1>` | Affinitizes threads to a core.
bind | `-bind:<address>` | Binds to the specified local address.
cibir | `-cibir:<hex_bytes>` | The well-known CIBIR identifier.
conns | `-conns:<####>` | The number of connections to use.
encrypt | `-encrypt:<0,1>` | Enables/disables encryption.
inline | `-inline:<0,1>` | Configured sending requests inline.
ip | `-ip:<0,4,6> ` | A hint for the resolving the hostname to an IP address.
port | `-port:<####>` | The UDP port of the server.
requests | `-requests:<####>` | The number of requests to send at a time.
request | `-request:<####>` | The length of request payloads.
response | `-response:<####>` | The length of request payloads.
runtime | `-runtime:<####>` | The total runtime (in ms).
sendbuf | `-sendbuf:<0,1>` | Whether to use send buffering.
stats | `-stats:<0,1>` | Prints out statistics at the end of each connection.
threads | `-threads:<####>` | The number of threads to use (capped to number of cores).

## HPS Test

To run the "handshakes per second" test, you must specify the `-test:hps` option, followed by a number of other arguments (most of which are optional).

### Examples

```
> secnetperf.exe -test:hps -target:127.0.0.1
```

```
> secnetperf.exe -test:hps -target:127.0.0.1 -runtime:1000 -response:8096 -stats:1
```

### Required

Argument | Usage | Meaning
--- | --- | ---
target,server | `-target:<hostname_or_IP>` | The target server to connect to. May be a hostname or an IP address.

### Optional

Argument | Usage | Meaning
--- | --- | ---
bind | `-bind:<address>` | Binds to the specified local address.
incrementtarget | `-incrementtarget<0,1>` | Set to 1 to append core index to target.
parallel | `-parallel:<####>` | The number of parallel connections per core.
port | `-port:<####>` | The UDP port of the server.
runtime | `-runtime:<####>` | The total runtime (in ms).
threads | `-threads:<####>` | The number of threads to use (capped to number of cores).
