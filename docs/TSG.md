# Trouble Shooting Guide

This document is meant to be a step-by-step guide for trouble shooting any issues while using MsQuic.

## What kind of Issue are you having?

1. [I am debugging a crash.](#debugging-a-crash)
2. [Something is not functionally working as I expect.](#trouble-shooting-a-functional-issue)
3. [Performance is not what I expect it to be.](#trouble-shooting-a-performance-issue)

# Debugging a Crash

> TODO

# Trouble Shooting a Functional Issue

1. [The handshake is failing for some or all of my connections.](#why-is-the-handshake-failing)
2. [The connection is unexpectedly disconnecting.](#why-is-the-connection-disconnecting)
3. [No application (stream) data seems to be flowing.](#why-isnt-application-data-flowing)

## Why is the handshake failing?

1. [The handshake failed with an error code I don't understand.](#mapping-error-codes-for-handshake-failures)
2. [Does it happen on Linux, only with large number of connections?](#linux-file-handle-limit-too-small)
3.

### Mapping Error Codes for Handshake Failures

> TODO

### Linux File Handle Limit Too Small

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

1. [Is it a problem with just a single (or very few) connection?]()
2. [Is it a problem multiple (lots) of connections?]()

## Why is Performance bad for my Connection?

> TODO

## Why is Performance bad across all my Connections?

1. [The work load isn't spreading evenly across cores.](diagnosing-rss-issues)
2.

### Diagnosing RSS Issues

> TODO
