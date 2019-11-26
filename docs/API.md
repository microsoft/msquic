MsQuic API
======

The MsQuic API is written in C (like the rest of the libary) and is cross platform. It is also possible to invoke from any other language that supports calling C (such as [C#](https://docs.microsoft.com/en-us/cpp/dotnet/how-to-call-native-dlls-from-managed-code-using-pinvoke?view=vs-2019) or [Rust](https://static.rust-lang.org/doc/master/book/ffi.html)).

The primary API header can be found in the `inc` directory: [msquic.h](../inc/msquic.h)

# Terminology

Term | Definition
--- | ---
*app* | The application that is calling into MsQuic.
*client* | The app that initiates a connection.
*server* | The app that accepts a connection from a peer.
*handle* | A pointer to an MsQuic object.
*endpoint* | One side of a connection; client or server.
*peer* | The *other* side of a connection.
*callback handler* | The function pointer the app registers with an MsQuic object.
*event* | An upcall to a callback handler.

# High Level Overview

## Object Model

![API Objects](images/api_objects.png)

The API supports both server and client applications. All functionality is exposed primarily via a set of different objects:

[**Api**](#library-function-table) - The top level handle and function table for all other API calls.

[**Registration**](#registration) – Manages the execution context for all child objects. An app may open multiple registrations but ideally should only open one.

[**Security Configuration**](#security-configuration) – Abstracts the configuration for the TLS layer. This primarily consists of a certificate that is used for authentication. The app may create as many of these as necessary.

[**Session**](#session) – Abstracts several different session-layer concepts: TLS Session Resumption, Application Protocol Layer Negotiation (ALPN) and platform specifics (such as Server Silo and Network Compartment ID on Windows). The app may create as many of these as necessary.

[**Listener**](#listener) – Server side only, this object provides the interface for an app to accept incoming connections from clients. Once the connection has been accepted, it is independent of the listener. The app may create as many of these as necessary.

[**Connection**](#connection) – Represents the actual QUIC connection state between the client and server. The app may create (and/or accept) as many of these as necessary.

[**Stream**](#stream) – The layer at which application data is exchanged. Streams may be opened by either peer of a connection and may be unidirectional or bidirectional. For a single connection, as many streams as necessary may be created.

## Versioning

MsQuic API is explicitly versioned by making the API function table version specific. The top level [MsQuicOpen](v0/MsQuicOpen.md) function takes an `ApiVersion` parameter as input and returns the corresponding function table. This allows for new versions of the function table to be easily added in the future.

The API version number **needs to change** when:
- The signature of an existing function changes.
- The behavior of an existing function changes, that breaks existing clients.

The API version number **does not need to change** when:
- New values are added to existing flags or enums.
- New functions are added. They are appended to the existing function table.
- The behavior of an existing function changes but can either be controlled via a flags field or doesn't break existing clients.

## Execution Mode

In general, MsQuic uses a callback model for all asynchronous events up to the app. This includes things like connection state changes, new streams being created, stream data being received, and stream sends completing. All these events are indicated to the app via a callback on a thread owned by MsQuic.

Apps are expected to keep any execution time in the callback **to a minimum**. MsQuic does not use separate threads for the protocol execution and upcalls to the app. Therefore, any significant delays on the callback **will delay the protocol**. Any significant time or work needed to be completed by the app must happen on its own thread.

This doesn't mean the app isn't allowed to do any work in the callback. In fact, many things are expressly designed to be most efficient when the app does them on the callback. For instance, closing a handle to a connection or stream is ideally implemented in the "shutdown complete" indications.

One important aspect of this design is that all blocking calls invoked on a callback always happen inline (to prevent deadlocks), and will supercede any calls in progress or queued from a separate thread.

# API Objects

## Library Function Table

There are only two top level functions:

- [MsQuicOpen](v0/MsQuicOpen.md) - Initializes the MsQuic library and returns a version specific function table.
- [MsQuicClose](v0/MsQuicClose.md) - Cleans up the function table and releases the library reference from the previous [MsQuicOpen](v0/MsQuicOpen.md) call.

As mentioned above (see [Versioning](#versioning)), [MsQuicOpen](v0/MsQuicOpen.md) takes an API version number as input and returns the corresponding version specific function table. This function table contains the functions for the rest of the MsQuic API.

When the app is done with the MsQuic library, it **must** call [MsQuicClose](v0/MsQuicClose.md) and pass in the function table it received from [MsQuicOpen](v0/MsQuicOpen.md). This allows for the library state to be cleaned up.

Please note, there is no explicit start/stop API for this library. Each API function table has a reference on the QUIC library: the library is initialized when the first call to [MsQuicOpen](v0/MsQuicOpen.md) succeeds and uninitialized when the last call to [MsQuicClose](v0/MsQuicClose.md) completes. An app should therefore beware of repeatedly calling [MsQuicOpen](v0/MsQuicOpen.md) and [MsQuicClose](v0/MsQuicClose.md), as library setup/cleanup can be expensive.

## Registration

Generally, each app only needs a single registration. The registration represents the execution context where all logic for the app's connections run. The library will create a number of worker threads for each registration, shared for all the connections. This execution context is not shared between different registrations.

A registration is created by calling [RegistrationOpen](v1/RegistrationOpen.md) and deleted by calling [RegistrationClose](v1/RegistrationClose.md).

## Security Configuration

Currently only used on the server side, the security configuration (AKA security config) abstracts a server certificate (and other configuration) used by a [listener](#listener) to accept an incoming connection request.

A security config is created by calling [SecConfigCreate](v1/SecConfigCreate.md) and deleted by calling [SecConfigDelete](v1/SecConfigDelete.md).

## Session

An app must create a session before it can create any listeners or connections. Each session maintains certain transport and platform state common to all child handles. Primarily, this consists of the ALPN string used for the connection handshakes and TLS state used for session resumption. On Windows platforms it also inherits the Silo and Network Compartment ID from the thread that creates it.

A session is created by calling [SessionOpen](v1/SessionOpen.md) and deleted by calling [SessionClose](v1/SessionClose.md). [SessionClose](v1/SessionClose.md) **will block** on all oustanding connections. Therefore do not call it on any MsQuic thread, as it will likely create a deadlock.

## Listener

To create a QUIC server, an app must create a listener via [ListenerOpen](v1/ListenerOpen.md). This will return a new listener handle that is ready to start accepting incoming connections. Then, the app must call [ListenerStart](v1/ListenerStart.md) to get callbacks for new incoming connections. [ListenerStart](v1/ListenerStart.md) takes the network address the app wants to listener on.

When a new connection is started by a client, the app will get a callback allowing it to accept the connection. This happens via the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback event, which contains all the currently known information in the `QUIC_NEW_CONNECTION_INFO` struct. The app is required to do one of three things in response to this event:

1. Return a failure status, indicating it didn’t accept the new connection.
2. Return `QUIC_STATUS_SUCCESS` and set the SecConfig output parameter in the event.
3. Return `QUIC_STATUS_PENDING`, which allows the SecConfig to be set later, via a call to SetParam with the `QUIC_PARAM_CONN_SEC_CONFIG` option.

If both 2 and 3 above, the app now has ownership of the connection object. It **must** set the callback handler via [SetCallbackHandler](v1/SetCallbackHandler.md) before the callback returns. Additionally, it must call [ConnectionClose](v1/ConnectionClose.md) on the connection to clean it up when it’s done with the connection. Also, in case 2, if the app does not set the SecConfig, it is treated as case 1.

When the app wishes to stop accepting new connections and stop further callbacks to the registered handler, it can call [ListenerStop](v1/ListenerStop.md). This call will block while any existing callbacks complete, and when it returns no future callbacks will occur. Therefore, the app ***must not** call this on any other library callbacks. The app may call [ListenerStart](v1/ListenerStart.md) again on the listener to start listening for incoming connections again.

To clean up the listener object, the app calls [ListenerClose](v1/ListenerClose.md). If the listener was not previously stopped, this function implicitly calls [ListenerStop](v1/ListenerStop.md), so all the same restrictions to that call apply.

## Connection

A connection handle represents a single QUIC connection and is generally the same thing on both client and server side. The main difference between client and server is just how the handle gets initially created. On client it is created explicitly by the app via a call to [ConnectionOpen](v1/ConnectionOpen.md). On server it is created by the listener and delivered to the app via a callback to the registered `QUIC_LISTENER_CALLBACK_HANDLER`. Just like all objects in MsQuic, the connection requires the app to be registered for event callbacks always. After the client creates the new connection, it starts the process of connecting to a remote server by calling [ConnectionStart](v1/ConnectionStart.md). If the connection attempt succeeds, the connection event handler will be invoked for a `QUIC_CONNECTION_EVENT_CONNECTED` event; otherwise a `QUIC_CONNECTION_EVENT_CLOSED` event will be received.

Once the app has a connection (either client or server) it can start opening streams and receiving events for remotely opened streams. Remotely opened streams are indicated to the callback handler via a `QUIC_CONNECTION_EVENT_NEW_STREAM` event. The app is required to immediately call [SetCallbackHandler](v1/SetCallbackHandler.md) to register a callback handler for the new stream. See [Stream](#stream) usage for more details on how stream are used.

When the app is done with the connection, it can then call [ConnectionShutdown](v1/ConnectionShutdown.md) to start the process of shutting down. This would cause the connection to immediately shutdown all open streams and send the shutdown indication to the peer over the network. When this process completes, the connection will invoke the event handler with a `QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE` event. After this, the app would be free to call [ConnectionClose](v1/ConnectionClose.md) to free up the connection resources.

## Stream

Streams are the primary means of exchanging app data over a connection. Streams can be bidirectional and unidirectional. They can also be initiated/opened by either endpoint (Client or server). Each endpoint dicates exactly how many streams of each type (unidirectional or bidirectional) their peer can open at a given time. Finally, they can be shutdown by either endpoint, in either direction.

A stream handle represents a single QUIC stream. It can be locally created by a call to [StreamOpen](v1/StreamOpen.md) or remotely created and then indicated to the app via the connection's callback handler via a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event. Locally created streams must be started (via [StreamStart](v1/StreamStart.md)) before they can practically be used. Remote streams are already started when indicated to the app.

Once the stream handle is available and started, the app can start receiving events on its callback handler (such as `QUIC_STREAM_EVENT_RECV`) and start sending on the stream (via [StreamSend](v1/StreamSend.md)). For more details see [Using Streams](Streams.md).
