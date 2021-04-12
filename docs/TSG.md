# Trouble Shooting Guide

This document is meant to be a step-by-step guide for trouble shooting any issues while using MsQuic.

## What kind of Issue are you having?

1. [I am debugging a crash.]()
2. [Something is not functionally working as I expect.]()
3. [Performance is not what I expect it to be.]()

# Debugging a Crash

> TODO

# Trouble Shooting a Functional Issue

1. [The handshake is failing for some or all of my connections.]()
2. [The connection is unexpectedly disconnecting.]()
3. [No application (stream) data seems to be flowing.]()

## Why is the handshake failing?

> TODO - More stuff

### Does it happen on Linux, only with large number of connections?

In many Linux setups, the default per-process file handle limit is relatively small (~1024). In scenarios where lots of (usually client) connection are opened, a large number of sockets (a type of file handle) are created. Eventually the handle limit is reached and connections start failing because new sockets cannot be created. To fix this, you will need to increase the handle limit.

To query the maximum limit you may set:
```
ulimit -Hn
```

To set a new limit (up to the max):
```
ulimit -n newValue
```

## Why is the connection disconnecting?

> TODO

## Why isn't application data flowing?

> TODO

# Trouble Shooting a Performance Issue

> TODO
