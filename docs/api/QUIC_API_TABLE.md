QUIC_API_TABLE structure
======

The function table for all MsQuic APIs.

# Syntax

```C
typedef struct QUIC_API_TABLE {

    QUIC_SET_CONTEXT_FN                 SetContext;
    QUIC_GET_CONTEXT_FN                 GetContext;
    QUIC_SET_CALLBACK_HANDLER_FN        SetCallbackHandler;

    QUIC_SET_PARAM_FN                   SetParam;
    QUIC_GET_PARAM_FN                   GetParam;

    QUIC_REGISTRATION_OPEN_FN           RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN          RegistrationClose;

    QUIC_SEC_CONFIG_CREATE_FN           SecConfigCreate;
    QUIC_SEC_CONFIG_DELETE_FN           SecConfigDelete;

    QUIC_SESSION_OPEN_FN                SessionOpen;
    QUIC_SESSION_CLOSE_FN               SessionClose;
    QUIC_SESSION_SHUTDOWN_FN            SessionShutdown;

    QUIC_LISTENER_OPEN_FN               ListenerOpen;
    QUIC_LISTENER_CLOSE_FN              ListenerClose;
    QUIC_LISTENER_START_FN              ListenerStart;
    QUIC_LISTENER_STOP_FN               ListenerStop;

    QUIC_CONNECTION_OPEN_FN             ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN            ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    QUIC_CONNECTION_START_FN            ConnectionStart;

    QUIC_STREAM_OPEN_FN                 StreamOpen;
    QUIC_STREAM_CLOSE_FN                StreamClose;
    QUIC_STREAM_START_FN                StreamStart;
    QUIC_STREAM_SHUTDOWN_FN             StreamShutdown;
    QUIC_STREAM_SEND_FN                 StreamSend;
    QUIC_STREAM_RECEIVE_COMPLETE_FN     StreamReceiveComplete;
    QUIC_STREAM_RECEIVE_SET_ENABLED_FN  StreamReceiveSetEnabled;

    QUIC_DATAGRAM_SEND_FN               DatagramSend;

} QUIC_API_TABLE;
```

# Members

`SetContext`

See [SetContext](SetContext.md)

`GetContext`

See [GetContext](GetContext.md)

`SetCallbackHandler`

See [SetCallbackHandler](SetCallbackHandler.md)

`SetParam`

See [SetParam](SetParam.md)

`GetParam`

See [GetParam](GetParam.md)

`RegistrationOpen`

See [RegistrationOpen](RegistrationOpen.md)

`RegistrationClose`

See [RegistrationClose](RegistrationClose.md)

`SecConfigCreate`

See [SecConfigCreate](SecConfigCreate.md)

`SecConfigDelete`

See [SecConfigDelete](SecConfigDelete.md)

`SessionOpen`

See [SessionOpen](SessionOpen.md)

`SessionClose`

See [SessionClose](SessionClose.md)

`SessionShutdown`

See [SessionShutdown](SessionShutdown.md)

`ListenerOpen`

See [ListenerOpen](ListenerOpen.md)

`ListenerClose`

See [ListenerClose](ListenerClose.md)

`ListenerStart`

See [ListenerStart](ListenerStart.md)

`ListenerStop`

See [ListenerStop](ListenerStop.md)

`ConnectionOpen`

See [ConnectionOpen](ConnectionOpen.md)

`ConnectionClose`

See [ConnectionClose](ConnectionClose.md)

`ConnectionShutdown`

See [ConnectionShutdown](ConnectionShutdown.md)

`ConnectionStart`

See [ConnectionStart](ConnectionStart.md)

`StreamOpen`

See [StreamOpen](StreamOpen.md)

`StreamClose`

See [StreamClose](StreamClose.md)

`StreamStart`

See [StreamStart](StreamStart.md)

`StreamShutdown`

See [StreamShutdown](StreamShutdown.md)

`StreamSend`

See [StreamSend](StreamSend.md)

`StreamReceiveComplete`

See [StreamReceiveComplete](StreamReceiveComplete.md)

`StreamReceiveSetEnabled`

See [StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)

`DatagramSend`

See [DatagramSend](DatagramSend.md)

# See Also

[MsQuicOpen](MsQuicOpen.md)<br>
