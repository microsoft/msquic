MsQuic API
======

The MsQuic API is written in C (like the rest of the libary) and is cross platform. It is also possible to invoke from any other language that supports calling C (such as [C#](https://docs.microsoft.com/en-us/cpp/dotnet/how-to-call-native-dlls-from-managed-code-using-pinvoke?view=vs-2019) or [Rust](https://static.rust-lang.org/doc/master/book/ffi.html)).

The primary API header can be found in the `inc` directory: [msquic.h](../src/inc/msquic.h)

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
*app context* or<br> *context* | A (possibly null) pointer registered with an MsQuic object. It is passed to callback handlers.
*event* | An upcall to a callback handler.

# High Level Overview

## Object Model

![API Objects](images/api_objects.png)

The API supports both server and client applications. All functionality is exposed primarily via a set of different objects:

[**Api**](#library-function-table) - The top level handle and function table for all other API calls.

[**Registration**](#registration) – Manages the execution context for all child objects. An app may open multiple registrations but ideally should only open one.

[**Configuration**](#configuration) – Abstracts the configuration for a connection. This generally consists both of security related and common QUIC settings.

[**Listener**](#listener) – Server side only, this object provides the interface for an app to accept incoming connections from clients. Once the connection has been accepted, it is independent of the listener. The app may create as many of these as necessary.

[**Connection**](#connection) – Represents the actual QUIC connection state between the client and server. The app may create (and/or accept) as many of these as necessary.

[**Stream**](#stream) – The layer at which application data is exchanged. Streams may be opened by either peer of a connection and may be unidirectional or bidirectional. For a single connection, as many streams as necessary may be created.

(For more details on the inner design of MsQuic see: [TLS](./TLS.md))

## Versioning

MsQuic API follows [semantic versioning](https://semver.org/) rules for updating the library version number (seen [here](../src/inc/msquic.ver)).

The **MAJOR** version **must change** when:
- The signature of an existing function changes.
- The position of any functions in the API function table changes.
- The behavior of an existing function changes that breaks existing clients.

The **MINOR** version **may change** when:
- New values are added to existing flags or enums.
- New functions are added to the end of the API function table.
- The behavior of an existing function changes but can either be controlled via a flags field or doesn't break existing clients.

The **PATCH** version **only changes** when a servicing fix is made to an existing release.

## Execution Mode

In general, MsQuic uses a callback model for all asynchronous events up to the app. This includes things like connection state changes, new streams being created, stream data being received, and stream sends completing. All these events are indicated to the app via the callback handler, on a thread owned by MsQuic.

Apps are expected to keep any execution time in the callback **to a minimum**. MsQuic does not use separate threads for the protocol execution and upcalls to the app. Therefore, any significant delays on the callback **will delay the protocol**. Any significant time or work needed to be completed by the app must happen on its own thread.

This doesn't mean the app isn't allowed to do any work in the callback. In fact, many things are expressly designed to be most efficient when the app does them on the callback. For instance, closing a handle to a connection or stream is ideally implemented in the "shutdown complete" indications.

One important aspect of this design is that all blocking calls invoked on a callback always happen inline (to prevent deadlocks), and will supercede any calls in progress or queued from a separate thread.

## Settings and Configuration

MsQuic supports a variety of configuration options available to both application developers and administrators deploying MsQuic. See [Settings](Settings.md) for a detailed explanation of these settings and configuration options.

# API Objects

## Library Function Table

There are only two top level functions:

- [MsQuicOpenVersion](api/MsQuicOpenVersion.md) - Initializes the MsQuic library and returns a the API function table.
- [MsQuicClose](api/MsQuicClose.md) - Cleans up the function table and releases the library reference from the previous [MsQuicOpenVersion](api/MsQuicOpenVersion.md) call.

When the app is done with the MsQuic library, it **must** call [MsQuicClose](api/MsQuicClose.md) and pass in the function table it received from [MsQuicOpenVersion](api/MsQuicOpenVersion.md). This allows for the library state to be cleaned up.

Please note, there is no explicit start/stop API for this library. Each API function table has a reference on the QUIC library: the library is initialized when the first call to [MsQuicOpenVersion](api/MsQuicOpenVersion.md) succeeds and uninitialized when the last call to [MsQuicClose](api/MsQuicClose.md) completes. An app should therefore beware of repeatedly calling [MsQuicOpenVersion](api/MsQuicOpenVersion.md) and [MsQuicClose](api/MsQuicClose.md), as library setup/cleanup can be expensive.

## Registration

Generally, each app only needs a single registration. The registration represents the execution context where all logic for the app's connections run. The library will create a number of worker threads for each registration, shared for all the connections. This execution context is not shared between different registrations.

A registration is created by calling [RegistrationOpen](api/RegistrationOpen.md) and deleted by calling [RegistrationClose](api/RegistrationClose.md).

## Configuration

TODO

A configuration is created by calling [ConfigurationOpen](api/ConfigurationOpen.md) and deleted by calling [ConfigurationClose](api/ConfigurationClose.md).

## Listener

To create a QUIC server, a server must create a listener via [ListenerOpen](api/ListenerOpen.md). This will return a new listener handle that is ready to start accepting incoming connections. Then, the server must call [ListenerStart](api/ListenerStart.md) to get callbacks for new incoming connections. [ListenerStart](api/ListenerStart.md) takes the network address and ALPNs the server wants to listener on.

When a new connection is started by a client, the server will get a callback allowing it to accept the connection. This happens via the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback event, which contains all the currently known information in the `QUIC_NEW_CONNECTION_INFO` struct. The server then returns either a success or failure status to indicate if the connection was accepted or not.

If the server accepts the connection, it now has ownership of the connection object. It **must** set the callback handler via [SetCallbackHandler](api/SetCallbackHandler.md) before the callback returns. Additionally, when it’s done with the connection, the app must call [ConnectionClose](api/ConnectionClose.md) on the connection to clean it up.

For an accepted connection to actually continue with its handshake, the server must call [ConnectionSetConfiguration](api/ConnectionSetConfiguration.md) to configure the necessary security (TLS) parameters. This may be called either on the callback (before it returns) or later on a different thread.

When the server wishes to stop accepting new connections and stop further callbacks to the registered handler, it can call [ListenerStop](api/ListenerStop.md). This call will block while any existing callbacks complete, and when it returns no future callbacks will occur. Therefore, the server **must not** call this on any other library callbacks. The server may call [ListenerStart](api/ListenerStart.md) again on the listener to start listening for incoming connections again.

To clean up the listener object, the server calls [ListenerClose](api/ListenerClose.md). If the listener was not previously stopped, this function implicitly calls [ListenerStop](api/ListenerStop.md), so all the same restrictions to that call apply.

## Connection

A connection handle represents a single QUIC connection and is generally the same thing on both client and server side. The main difference between client and server is just how the handle gets initially created. On client it is created explicitly by the app via a call to [ConnectionOpen](api/ConnectionOpen.md). On server it is created by the listener and delivered to the app via a callback to the registered `QUIC_LISTENER_CALLBACK_HANDLER`. Just like all objects in MsQuic, the connection requires the app to always be registered for event callbacks. After the client creates the new connection, it starts the process of connecting to a remote server by calling [ConnectionStart](api/ConnectionStart.md). If the connection attempt succeeds, the connection event handler will be invoked for a `QUIC_CONNECTION_EVENT_CONNECTED` event; otherwise a `QUIC_CONNECTION_EVENT_CLOSED` event will be received.

Once the app has a connection (either client or server) it can start opening streams and receiving events for remotely opened streams. Remotely opened streams are indicated to the callback handler via a `QUIC_CONNECTION_EVENT_NEW_STREAM` event. The app is required to immediately call [SetCallbackHandler](api/SetCallbackHandler.md) to register a callback handler for the new stream. See [Stream](#stream) usage for more details on how stream are used.

When the app is done with the connection, it can then call [ConnectionShutdown](api/ConnectionShutdown.md) to start the process of shutting down. This would cause the connection to immediately shutdown all open streams and send the shutdown indication to the peer over the network. When this process completes, the connection will invoke the event handler with a `QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE` event. After this, the app would be free to call [ConnectionClose](api/ConnectionClose.md) to free up the connection resources.

## Stream

Streams are the primary means of exchanging app data over a connection. Streams can be bidirectional or unidirectional. They can also be initiated/opened by either endpoint (Client or server). Each endpoint dictates exactly how many streams of each type (unidirectional or bidirectional) their peer can open at a given time. Finally, they can be shutdown by either endpoint, in either direction.

A stream handle represents a single QUIC stream. It can be locally created by a call to [StreamOpen](api/StreamOpen.md) or remotely created and then indicated to the app via the connection's callback handler via a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event. Locally created streams must be started (via [StreamStart](api/StreamStart.md)) before they can send or receive data. Remote streams are already started when indicated to the app.

Once the stream handle is available and started, the app can start receiving events on its callback handler (such as `QUIC_STREAM_EVENT_RECEIVE`) and start sending on the stream (via [StreamSend](api/StreamSend.md)). For more details see [Using Streams](Streams.md).

## Datagrams

MsQuic supports the [unreliable datagram extension](https://tools.ietf.org/html/draft-ietf-quic-datagram) which allows for the app to send and receive unreliable (i.e. not retransmitted on packet loss) data securely. To enable support for receiving datagrams, the app must set `DatagramReceiveEnabled` to `TRUE` in its [QUIC_SETTINGS](api/QUIC_SETTINGS.md). During the handshake, support for receiving datagrams is negotiated between endpoints. The app receives the `QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED` event to indicate if the peer supports receiving datagrams (and what the current maximum size is).

If the peer has enabled receiving datagrams, then an app may call [DatagramSend](api/DatagramSend.md). If/when the app receives a datagram from the peer it will receive a `QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED` event.
