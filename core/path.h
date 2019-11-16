/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Represents all the per-path information of a connection.
//
typedef struct QUIC_PATH {

    //
    // Unique identifier;
    //
    uint8_t ID;

    //
    // Indicates this is the primary path being used by the connection.
    //
    BOOLEAN IsActive : 1;

    //
    // Indicates whether this connection initiated a CID change, and therefore
    // shouldn't respond to the peer's next CID change with one of its own.
    //
    BOOLEAN InitiatedCidUpdate : 1;

    //
    // This flag indicates that the first RTT sample has been taken. Until this
    // is set, the RTT estimate is set to a default value.
    //
    BOOLEAN GotFirstRttSample : 1;

    //
    // Indicates the peer's source IP address has been validated.
    //
    BOOLEAN IsValidated : 1;

    //
    // Current value to encode in the short header spin bit field.
    //
    BOOLEAN SpinBit : 1;

    //
    // The currently calculated path MTU.
    //
    uint16_t Mtu;

    //
    // The binding used for sending/receiving UDP packets.
    //
    QUIC_BINDING* Binding;

    //
    // The locally bound source IP address.
    //
    QUIC_ADDR LocalAddress;

    //
    // The peer's source IP address.
    //
    QUIC_ADDR RemoteAddress;

    //
    // The destination CID used for sending on this path.
    //
    QUIC_CID_QUIC_LIST_ENTRY* DestCid;

    //
    // Used on the server side until the client's IP address has been validated
    // to prevent the server from being used for amplification attacks. A value
    // of UINT32_MAX indicates this variable does not apply.
    //
    uint32_t Allowance;

    //
    // RTT moving average, computed as in RFC6298. Units of microseconds.
    //
    uint32_t SmoothedRtt;
    uint32_t MinRtt;
    uint32_t MaxRtt;
    uint32_t RttVariance;
    uint32_t LatestRttSample;

    //
    // The last path challenge we received and need to echo back in a path
    // response frame.
    //
    uint8_t LastPathChallengeReceived[8];

} QUIC_PATH;

QUIC_STATIC_ASSERT(
    sizeof(QUIC_PATH) < 256,
    "Ensure path struct stays small since we prealloc them");
