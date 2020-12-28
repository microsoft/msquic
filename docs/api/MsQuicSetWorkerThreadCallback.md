MsQuicSetWorkerThreadCallback function
======

Sets a callback to be called on each worker thread when it is started or stopped.

# Syntax

```C
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSetWorkerThreadCallback(
    _In_ QUIC_WORKER_CALLBACK_HANDLER Handler
    );
```

# Parameters

`Handler`

The handler to be invoked when a worker thread is started or stopped.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remakrs

The callback passed in is only called when a newly created worker is started or stopped. It is not invoked dynamically for each existing thread. This means that in order to work for all created workers, it must be called before [MsQuicOpen](api/MsQuicOpen.md).

Additionally, each worker thread holds onto the callback that existed when started, and calls that callback when stopped. It does not reload the callback when stopping the thread.

The callback with `QUIC_WORKER_STOPPED` event type will not be called if the thread is aborted and not allowed to exit cleanly.
