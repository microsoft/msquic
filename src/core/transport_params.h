/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Helpers for reading and writing QUIC Transport Parameters TLS extension.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

//
// The configuration parameters that QUIC exchanges in the TLS handshake.
//
typedef struct QUIC_TRANSPORT_PARAMETERS {

    //
    // Flags listing which parameters below are set.
    //
    uint32_t Flags; // Set of QUIC_TP_FLAG_*

    //
    // The initial timeout (in milliseconds) for the idle timeout of the
    // connection.
    //
    QUIC_VAR_INT IdleTimeout;

    //
    // The initial per-stream max data flow control value.
    //
    QUIC_VAR_INT InitialMaxStreamDataBidiLocal;
    QUIC_VAR_INT InitialMaxStreamDataBidiRemote;
    QUIC_VAR_INT InitialMaxStreamDataUni;

    //
    // The initial connection-wide max data flow control value.
    //
    QUIC_VAR_INT InitialMaxData;

    //
    // The initial maximum number of bi-directional streams allowed.
    //
    _Field_range_(0, QUIC_TP_MAX_STREAMS_MAX)
    QUIC_VAR_INT InitialMaxBidiStreams;

    //
    // The initial maximum number of uni-directional streams allowed.
    //
    _Field_range_(0, QUIC_TP_MAX_STREAMS_MAX)
    QUIC_VAR_INT InitialMaxUniStreams;

    //
    // The maximum UDP payload size, in bytes, the receiver is willing to
    // receive. Valid values are between 1200 and 65527, inclusive.
    //
    _Field_range_(QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN, QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX)
    QUIC_VAR_INT MaxUdpPayloadSize;

    //
    // Indicates the exponent used to decode the ACK Delay field in the ACK
    // frame. If not present, a default value of 3 is assumed.
    //
    _Field_range_(0, QUIC_TP_ACK_DELAY_EXPONENT_MAX)
    QUIC_VAR_INT AckDelayExponent;

    //
    // Indicates the maximum amount of time in milliseconds by which it will
    // delay sending of acknowledgments. If this value is absent, a default of
    // 25 milliseconds is assumed.
    //
    _Field_range_(0, QUIC_TP_MAX_ACK_DELAY_MAX)
    QUIC_VAR_INT MaxAckDelay;

    //
    // A variable-length integer representing the minimum amount of time in
    // microseconds by which the endpoint can delay an acknowledgment. Values
    // of 2^24 or greater are invalid.
    //
    // The presence of the parameter also advertises support of the ACK
    // Frequency extension.
    //
    _Field_range_(0, QUIC_TP_MIN_ACK_DELAY_MAX)
    QUIC_VAR_INT MinAckDelay;

    //
    // The maximum number connection IDs from the peer that an endpoint is
    // willing to store. This value includes only connection IDs sent in
    // NEW_CONNECTION_ID frames. If this parameter is absent, a default of 2 is
    // assumed.
    //
    _Field_range_(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN, QUIC_VAR_INT_MAX)
    QUIC_VAR_INT ActiveConnectionIdLimit;

    //
    // The maximum size of a DATAGRAM frame (including the frame type, length,
    // and payload) the endpoint is willing to receive, in bytes.
    //
    QUIC_VAR_INT MaxDatagramFrameSize;

    //
    // The value that the endpoint included in the Source Connection ID field
    // of the first Initial packet it sends for the connection.
    //
    uint8_t InitialSourceConnectionID[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
    _Field_range_(0, QUIC_MAX_CONNECTION_ID_LENGTH_V1)
    uint8_t InitialSourceConnectionIDLength;

    //
    // The offset and length of the well-known CIBIR idenfitier.
    //
    QUIC_VAR_INT CibirLength;
    QUIC_VAR_INT CibirOffset;

    //
    // Server specific.
    //

    //
    // Used in verifying the stateless reset scenario.
    //
    uint8_t StatelessResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];

    //
    // The server's preferred address.
    //
    QUIC_ADDR PreferredAddress;

    //
    // The value of the Destination Connection ID field from the first Initial
    // packet sent by the client. This transport parameter is only sent by a
    // server.
    //
    uint8_t OriginalDestinationConnectionID[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
    _Field_range_(0, QUIC_MAX_CONNECTION_ID_LENGTH_V1)
    uint8_t OriginalDestinationConnectionIDLength;

    //
    // The value that the server included in the Source Connection ID field
    // of a Retry packet.
    //
    uint8_t RetrySourceConnectionID[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
    _Field_range_(0, QUIC_MAX_CONNECTION_ID_LENGTH_V1)
    uint8_t RetrySourceConnectionIDLength;

    //
    // The version_information transport parameter opaque blob.
    //
    uint32_t VersionInfoLength;
    const uint8_t* VersionInfo;

} QUIC_TRANSPORT_PARAMETERS;

//
// Allocates and encodes the QUIC TP buffer. Free with CXPLAT_FREE.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicCryptoTlsEncodeTransportParameters(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerTP,
    _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams,
    _In_opt_ const QUIC_PRIVATE_TRANSPORT_PARAMETER* TestParam,
    _Out_ uint32_t* TPLen
    );

//
// Decodes QUIC TP buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoTlsDecodeTransportParameters(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerTP,
    _In_reads_(TPLen)
        const uint8_t* TPBuf,
    _In_ uint16_t TPLen,
    _Inout_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    );

//
// Deep copies allocated transport parameters.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicCryptoTlsCopyTransportParameters(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Source,
    _In_ QUIC_TRANSPORT_PARAMETERS* Destination
    );

//
// Frees allocation transport parameters.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCryptoTlsCleanupTransportParameters(
    _In_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    );

#if defined(__cplusplus)
}
#endif
