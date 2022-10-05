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
    // Indicates that the first RTT sample has been taken. Until this is set,
    // the RTT estimate is set to a default value.
    //
    BOOLEAN GotFirstRttSample : 1;

    //
    // Indicates a valid (not dropped) packet has been received on this path.
    //
    BOOLEAN GotValidPacket : 1;

    //
    // Indicates the peer's source IP address has been validated.
    //
    BOOLEAN IsPeerValidated : 1;

    //
    // Indicates the minimum MTU has been validated.
    //
    BOOLEAN IsMinMtuValidated : 1;

    //
    // Current value to encode in the short header spin bit field.
    //
    BOOLEAN SpinBit : 1;

    //
    // The current path challenge needs to be sent out.
    //
    BOOLEAN SendChallenge : 1;

    //
    // The current path response needs to be sent out.
    //
    BOOLEAN SendResponse : 1;

    //
    // Indicates the partition has updated for this path.
    //
    uint8_t PartitionUpdated : 1;

    //
    // The currently calculated path MTU.
    //
    uint16_t Mtu;

    //
    // The local socket MTU.
    //
    uint16_t LocalMtu;

    //
    // MTU Discovery logic.
    //
    QUIC_MTU_DISCOVERY MtuDiscovery;

    //
    // The binding used for sending/receiving UDP packets.
    //
    QUIC_BINDING* Binding;

    //
    // The network route.
    //
    CXPLAT_ROUTE Route;

    //
    // The destination CID used for sending on this path.
    //
    QUIC_CID_LIST_ENTRY* DestCid;

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
    // The last path challenge we received and needs to be sent back as in a
    // PATH_RESPONSE frame.
    //
    uint8_t Response[8];

    //
    // The current path challenge to send and wait for the peer to echo back.
    //
    uint8_t Challenge[8];

    //
    // Time when path validation was begun. Used for timing out path validation.
    //
    uint32_t PathValidationStartTime;

} QUIC_PATH;

#if DEBUG
#define QuicPathValidate(Path) \
    CXPLAT_DBG_ASSERT( \
        (Path)->DestCid == NULL || \
        (Path)->DestCid->CID.Length == 0 || \
        ((Path)->DestCid->AssignedPath == (Path) && \
         (Path)->DestCid->CID.UsedLocally))
#else
#define QuicPathValidate(Path) UNREFERENCED_PARAMETER(Path)
#endif

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_PATH) < 256,
    "Ensure path struct stays small since we prealloc them");

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t NewAllowance
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicPathIncrementAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t Amount
    )
{
    QuicPathSetAllowance(Connection, Path, Path->Allowance + Amount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicPathDecrementAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t Amount
    )
{
    QuicPathSetAllowance(
        Connection,
        Path,
        Path->Allowance <= Amount ? 0 : (Path->Allowance - Amount));
}

//
// Calculates the maximum size datagram payload from the path's MTU.
//
inline
uint16_t
QuicPathGetDatagramPayloadSize(
    _In_ const QUIC_PATH* Path
    )
{
    return
        MaxUdpPayloadSizeForFamily(
            QuicAddrGetFamily(&Path->Route.RemoteAddress), Path->Mtu);
}

typedef enum QUIC_PATH_VALID_REASON {
    QUIC_PATH_VALID_INITIAL_TOKEN,
    QUIC_PATH_VALID_HANDSHAKE_PACKET,
    QUIC_PATH_VALID_PATH_RESPONSE
} QUIC_PATH_VALID_REASON;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetValid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_PATH_VALID_REASON Reason
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
_Success_(return != NULL)
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t ID,
    _Out_ uint8_t* Index
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForDatagram(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const CXPLAT_RECV_DATA* Datagram
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    );
