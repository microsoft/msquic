ExecutionDelete function
======

Deletes the externally managed execution contexts and waits for remaining internal cleanup to complete.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_EXECUTION_DELETE_FN)(
    _In_ uint32_t Count,
    _In_reads_(Count) QUIC_EXECUTION** Executions
    );
```

# Parameters

`Count`

The number of execution contexts in `Executions`.

`Executions`

The array of execution contexts returned by [ExecutionCreate](ExecutionCreate.md).

# Remarks

Each execution context requires its own distinct event queue. Different execution contexts must not share the same underlying queue.

Before calling this function, the application must close all listeners, connections, streams, and configurations and complete closure of all registrations. Continue calling [ExecutionPoll](ExecutionPoll.md) and dispatching event queue completions until the final [RegistrationClose](RegistrationClose.md) returns or the final [RegistrationClose2](RegistrationClose2.md) completion callback is delivered. A synchronous registration close must run on a separate thread from the one driving its execution contexts.

After registration closure completes, stop and synchronize with all application threads polling these execution contexts or dispatching their queue completions before calling `ExecutionDelete`. Do not call this function from a polling or completion callback while application dispatch is still active.

Registration closure does not guarantee that all internal cleanup has completed. For example, canceled socket I/O may still have queued completions that retain internal resources. There is no separate notification that the execution queues are fully drained, and the timeout returned by `ExecutionPoll` is not such a notification.

This function blocks while MsQuic cleanup threads take over the event queues, process remaining completions, and release internal resources. These threads may also dispatch application-owned completions on the supplied queues. Keep the queues and any completion-handler state valid until this function returns. The application remains responsible for closing the queues afterward.

The execution contexts are invalid after this function returns and must not be polled or otherwise used.

# See Also

[ExecutionCreate](ExecutionCreate.md)<br>
[ExecutionPoll](ExecutionPoll.md)<br>
[Execution](../Execution.md)<br>
[QUIC_API_TABLE](QUIC_API_TABLE.md)<br>
