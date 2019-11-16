MsQuic API
======

The MsQuic API is written in C (like the rest of the libary) and is cross platform. It is also possible to invoke from any other language that supports calling C (such as [C#](https://docs.microsoft.com/en-us/cpp/dotnet/how-to-call-native-dlls-from-managed-code-using-pinvoke?view=vs-2019) or [Rust](https://static.rust-lang.org/doc/master/book/ffi.html)).

The primary API header can be found in the `inc` directory: [msquic.h](../inc/msquic.h)

## Terms

Term | Definition
--- | ---
*app* | The application that is calling into MsQuic
*client* | The app that initiates a connection
*server* | The app that accepts a connection from a peer

## High Level Overview

The API supports both server and client applications. All functionality is exposed primarily via a set of different objects:

**Api** - The top level handle and function table for all other API calls.

**Registration** – Manages the execution context for all child objects. An app may open multiple registrations but ideally should only open one.

**Security Configuration** – Abstracts the configuration for the TLS layer. This primarily consists of a certificate that is used for authentication. The app may create as many of these as necessary.

**Session** – Abstracts several different session-layer concepts: TLS Session Resumption, Application Protocol Layer Negotiation (ALPN) and platform specifics (such as Server Silo and Network Compartment ID on Windows). The app may create as many of these as necessary.

**Listener** – Server side only, this object provides the interface for an app to accept incoming connections from clients. Once the connection has been accepted, it is independent of the listener. The app may create as many of these as necessary.

**Connection** – Represents the actual QUIC connection state between the client and server. The app may create (and/or accept) as many of these as necessary.

**Stream** – The layer at which application data is exchanged. Streams may be opened by either peer of a connection and may be unidirectional or bidirectional. For a single connection, as many streams as necessary may be created.

### Versioning

MsQuic API is explicitly versioned by making the API function table version specific. The top level `MsQuicOpen` function takes an `ApiVersion` parameter as input and returns the corresponding function table. This allows for new versions of the function table to be easily added in the future.

The API version number **needs to change** when:
- The signature of an existing function changes.
- The behavior of an existing function changes, that breaks existing clients.

The API version number **does not need to change** when:
- New values are added to existing flags or enums.
- New functions are added. They are appended to the existing function table.
- The behavior of an existing function changes but can either be controlled via a flags field or doesn't break existing clients.

### Execution Mode

In general, MsQuic uses a callback model for all asynchronous events up to the app. This includes things like connection state changes, new streams being created, stream data being received, and stream sends completing. All these events are indicated to the app via a callback on a thread owned by MsQuic.

Apps are expected to keep any execution time in the callback **to a minimum**. MsQuic does not use separate threads for the protocol execution and upcalls to the app. Therefore, any significant delays on the callback **will delay the protocol**. Any significant time or work needed to be completed by the app must happen on its own thread.

This doesn't mean the app isn't allowed to do any work in the callback. In fact, many things are expressly designed to be most efficient when the app does them on the callback. For instance, closing a handle to a connection or stream is ideally implemented in the "shutdown complete" indications.

One important aspect of this design is that all blocking calls invoked on a callback always happen inline (to prevent deadlocks), and will supercede any calls in progress or queued from a separate thread.
