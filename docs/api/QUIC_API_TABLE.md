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
    QUIC_REGISTRATION_SHUTDOWN_FN       RegistrationShutdown;

    QUIC_CONFIGURATION_OPEN_FN          ConfigurationOpen;
    QUIC_CONFIGURATION_CLOSE_FN         ConfigurationClose;
    QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN
                                        ConfigurationLoadCredential;

    QUIC_LISTENER_OPEN_FN               ListenerOpen;
    QUIC_LISTENER_CLOSE_FN              ListenerClose;
    QUIC_LISTENER_START_FN              ListenerStart;
    QUIC_LISTENER_STOP_FN               ListenerStop;

    QUIC_CONNECTION_OPEN_FN             ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN            ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    QUIC_CONNECTION_START_FN            ConnectionStart;
    QUIC_CONNECTION_SET_CONFIGURATION_FN
                                        ConnectionSetConfiguration;
    QUIC_CONNECTION_SEND_RESUMPTION_FN  ConnectionSendResumptionTicket;

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

`RegistrationShutdown`

See [RegistrationShutdown](RegistrationShutdown.md)

`ConfigurationOpen`

See [ConfigurationOpen](ConfigurationOpen.md)

`ConfigurationClose`

See [ConfigurationClose](ConfigurationClose.md)

`ConfigurationLoadCredential`

See [ConfigurationLoadCredential](ConfigurationLoadCredential.md)

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

`ConnectionSetConfiguration`

See [ConnectionSetConfiguration](ConnectionSetConfiguration.md)

`ConnectionSendResumptionTicket`

See [ConnectionSendResumptionTicket](ConnectionSendResumptionTicket.md)

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

[MsQuicOpen2](MsQuicOpen2.md)<br>
