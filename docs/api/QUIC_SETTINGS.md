QUIC_SETTINGS structure
======

The set of all customizable parameters for the library.

# Syntax

```C
typedef struct QUIC_SETTINGS {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey                 : 1;
            uint64_t HandshakeIdleTimeoutMs         : 1;
            uint64_t IdleTimeoutMs                  : 1;
            uint64_t TlsClientMaxSendBuffer         : 1;
            uint64_t TlsServerMaxSendBuffer         : 1;
            uint64_t StreamRecvWindowDefault        : 1;
            uint64_t StreamRecvBufferDefault        : 1;
            uint64_t ConnFlowControlWindow          : 1;
            uint64_t MaxWorkerQueueDelayUs          : 1;
            uint64_t MaxStatelessOperations         : 1;
            uint64_t InitialWindowPackets           : 1;
            uint64_t SendIdleTimeoutMs              : 1;
            uint64_t InitialRttMs                   : 1;
            uint64_t MaxAckDelayMs                  : 1;
            uint64_t DisconnectTimeoutMs            : 1;
            uint64_t KeepAliveIntervalMs            : 1;
            uint64_t PeerBidiStreamCount            : 1;
            uint64_t PeerUnidiStreamCount           : 1;
            uint64_t RetryMemoryLimit               : 1;
            uint64_t LoadBalancingMode              : 1;
            uint64_t MaxOperationsPerDrain          : 1;
            uint64_t SendBufferingEnabled           : 1;
            uint64_t PacingEnabled                  : 1;
            uint64_t MigrationEnabled               : 1;
            uint64_t DatagramReceiveEnabled         : 1;
            uint64_t ServerResumptionLevel          : 1;
            uint64_t DesiredVersionsList            : 1;
            uint64_t VersionNegotiationExtEnabled   : 1;
            uint64_t RESERVED                       : 36;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t RetryMemoryLimit;
    uint16_t LoadBalancingMode;
    uint8_t MaxOperationsPerDrain;
    uint8_t SendBufferingEnabled            : 1;
    uint8_t PacingEnabled                   : 1;
    uint8_t MigrationEnabled                : 1;
    uint8_t DatagramReceiveEnabled          : 1;
    uint8_t ServerResumptionLevel           : 2;
    uint8_t VersionNegotiationExtEnabled    : 1;
    uint8_t RESERVED                        : 1;
    const uint32_t* DesiredVersionsList;
    uint32_t DesiredVersionsListLength;

} QUIC_SETTINGS;
```

# Members

`IsSetFlags`

The set of flags that indicate which other struct members are valid.

`MaxBytesPerKey`

The maximum number of bytes that can be encryped with a key before it should be changed/updated.

`IdleTimeoutMs`

TODO

`TlsClientMaxSendBuffer`

TODO

`TlsServerMaxSendBuffer`

TODO

`StreamRecvWindowDefault`

TODO

`StreamRecvBufferDefault`

TODO

`ConnFlowControlWindow`

TODO

`MaxWorkerQueueDelayUs`

TODO

`MaxStatelessOperations`

TODO

`InitialWindowPackets`

TODO

`SendIdleTimeoutMs`

TODO

`InitialRttMs`

TODO

`MaxAckDelayMs`

TODO

`DisconnectTimeoutMs`

TODO

`KeepAliveIntervalMs`

TODO

`PeerBidiStreamCount`

TODO

`PeerUnidiStreamCount`

TODO

`RetryMemoryLimit`

TODO

`LoadBalancingMode`

TODO

`MaxOperationsPerDrain`

TODO

`SendBufferingEnabled`

TODO

`PacingEnabled`

TODO

`MigrationEnabled`

TODO

`DatagramReceiveEnabled`

TODO

`ServerResumptionLevel`

TODO

`VersionNegotiationExtEnabled`

TODO

`DesiredVersionsList`

TODO

`DesiredVersionsListLength`

TODO

# Remarks

When setting new values for the settings, the app must set the corresponding `.IsSet.*` parameter for each actual parameter that is being set or updated. For example:

```C
QUIC_SETTINGS Settings {0};

//
// Configures the server's idle timeout.
//
Settings.IdleTimeoutMs = 60000; // 60 seconds
Settings.IsSet.IdleTimeoutMs = TRUE;

//
// Configures the server's resumption level to allow for resumption and 0-RTT.
//
Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
Settings.IsSet.ServerResumptionLevel = TRUE;
```

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[GetParam](GetParam.md)<br>
[SetParam](SetParam.md)<br>
