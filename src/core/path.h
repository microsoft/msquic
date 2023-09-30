/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// ECN validation state transition:
//
// ECN_VALIDATION_TESTING: when a new path is created AND ECN is enabled.
//
// ECN_VALIDATION_TESTING -> ECN_VALIDATION_UNKNOWN: after sending packets with ECT bit set for 3 PTOs.
//
// {ECN_VALIDATION_TESTING | ECN_VALIDATION_UNKNOWN} -> ECN_VALIDATION_CAPABLE:
// when ECN validation passes.
//
// {ANY} -> ECN_VALIDATION_FAILED: when ECN validation fails.
//
// In ECN_VALIDATION_TESTING or ECN_VALIDATION_CAPABLE state, packets sent are marked with ECT bit.
//
// This algorithm is a slightly simplified and relaxed version of the sample ECN validation in
// RFC9000 A.4. The main differences are:
//
// 1. Our algorithm can transition into capable state right from testing state if ECN validation passes.
//
// 2. The sample algorithm fails ECN validation when all packets sent in testing are considered lost.
// Our algorithm does not do that. However, in that case, our algorithm stays in unknown state, where
// we send packets without ECT mark, which is effectively the same as failing the validation.
//

//
// Different state of ECN validation for the network path.
//
typedef enum ECN_VALIDATION_STATE {
    ECN_VALIDATION_TESTING,
    ECN_VALIDATION_UNKNOWN,
    ECN_VALIDATION_CAPABLE,
    ECN_VALIDATION_FAILED, // or not enabled by the app.
} ECN_VALIDATION_STATE;

//
// Represents all the per-path information of a connection.
//
typedef struct QUIC_PATH {

    //
    // Unique identifier;
    //
    uint8_t ID;

    //
    // Indicates the path object is actively in use.
    //
    BOOLEAN InUse : 1;

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
    // ECN validation state.
    //
    uint8_t EcnValidationState : 2;

    //
    // Indicates whether this connection offloads encryption workload to HW
    //
    BOOLEAN EncryptionOffloading : 1;

    //
    // The ending time of ECN validation testing state in microseconds.
    //
    uint64_t EcnTestingEndingTime;

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
    // RTT moving average, computed as in RFC6298. Units of microseconds.
    //
    uint64_t SmoothedRtt;
    uint64_t LatestRttSample;
    uint64_t MinRtt;
    uint64_t MaxRtt;
    uint64_t RttVariance;
    uint64_t OneWayDelay;
    uint64_t OneWayDelayLatest;

    //
    // Used on the server side until the client's IP address has been validated
    // to prevent the server from being used for amplification attacks. A value
    // of UINT32_MAX indicates this variable does not apply.
    //
    uint32_t Allowance;

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
    uint64_t PathValidationStartTime;

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
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    );

//
// Plumbs new or removes existing QUIC encryption offload information.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    );
