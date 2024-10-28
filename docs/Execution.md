Execution
======

The MsQuic API takes a very difference stance when it comes to its execution model compared to BSD sockets (and most other networking libraries built on top of them).
The sections below detail the designs MsQuic uses, with some of the details as to why these design choices were made.

## Event Model

In the MsQuic API, all state changes and other notifications are indicated directly to the application via a callback.

```c
typedef struct QUIC_LISTENER_EVENT {
    QUIC_LISTENER_EVENT_TYPE Type;
    union {
        struct { ... } NEW_CONNECTION;
        struct { ... } STOP_COMPLETE;
    };
} QUIC_LISTENER_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_LISTENER_CALLBACK)(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    );
```

Above is an example of the type of callback delivered to the listener interface.
The application is requires to register a callback handler that should handle all the events MsQuic may indicate, returning a status for if it was successfully handled or not.

This is very different from BSD sockets which required the application to make a call (e.g., `send` or `recv`) in order to determine something happened.
This difference was made for several reasons:

- The MsQuic API **runs in-proc**, and therefore doesn't require a kernel to user mode boundary switch to indicate something to the application layer. This allows for the callback-based design which is not as practical for BSD sockets.

- MsQuic, by virtue of the QUIC protocol itself, has a lot of different types of events. Just considering streams, the app maybe have hundreds of objects at once which may have some state change. By leveraging the callback model, the application doesn't have to manage having pending calls on each object.

- Experience has shown it to be very difficult to write correct, performant code on top of the BSD-style interface. By leveraging callbacks (that happen at the correct time, on the correct thread/processor), it allows MsQuic to abstract a lot of complexity away from applications and make things "just work" out of the box.

- It simplifies much of the logic in MsQuic, because it eliminates the need for a queue or cached state that needs to be indicated to the application. In the BSD model, the networking stack must wait for the top-down call from the application before it can indicate the completion. This adds increased code size, complexity and memory usage.

### Writing Event Handlers

Event handlers are **required** for all objects (that support them), because much of the MsQuic API happens through these callbacks.
Additionally, important events, such as "shutdown complete" events provide crucial information to the application to function properly.
Without these events, the application cannot not know when it is safe to clean up objects.

Applicationss are expected to keep any execution time in the callbacks **to a minimum**.
MsQuic does not use separate threads for the protocol execution and upcalls to the application.
Therefore, any significant delays on the callback **will delay the protocol**.
Any significant time or work needed to be completed by the application must happen on its own thread.

This doesn't mean the application isn't allowed to do any work in the callback handler.
In fact, many things are expressly designed to be most efficient when the application does them on the callback.
For instance, closing a handle to a connection or stream is ideally implemented in the "shutdown complete" indications.

One important aspect of this design is that all blocking API (down) calls invoked on a callback always happen inline (to prevent deadlocks), and will supercede any calls in progress or queued from a separate thread.

## Threading


