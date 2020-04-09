/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Helpers for reading and writing QUIC Transport Parameters TLS extension.

--*/

#define QUIC_TP_FLAG_INITIAL_MAX_DATA                       0x0001
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL       0x0002
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE      0x0004
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI              0x0008
#define QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI                 0x0010
#define QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI                  0x0020
#define QUIC_TP_FLAG_MAX_PACKET_SIZE                        0x0040
#define QUIC_TP_FLAG_ACK_DELAY_EXPONENT                     0x0080
#define QUIC_TP_FLAG_STATELESS_RESET_TOKEN                  0x0100
#define QUIC_TP_FLAG_PREFERRED_ADDRESS                      0x0200
#define QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION               0x0400
#define QUIC_TP_FLAG_IDLE_TIMEOUT                           0x0800
#define QUIC_TP_FLAG_MAX_ACK_DELAY                          0x1000
#define QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID                 0x2000
#define QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT             0x4000

#define QUIC_TP_MAX_PACKET_SIZE_DEFAULT                     65527
#define QUIC_TP_MAX_PACKET_SIZE_MIN                         1200
#define QUIC_TP_MAX_PACKET_SIZE_MAX                         65527

#define QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT                  3
#define QUIC_TP_ACK_DELAY_EXPONENT_MAX                      20

#define QUIC_TP_MAX_ACK_DELAY_DEFAULT                       25 // ms
#define QUIC_TP_MAX_ACK_DELAY_MAX                           ((1 << 14) - 1)

#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT          2
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN              2

//
// Max allowed value of a MAX_STREAMS frame or transport parameter.
// Any larger value would allow a max stream ID that cannot be expressed
// as a variable-length integer.
//
#define QUIC_TP_MAX_STREAMS_MAX                             ((1ULL << 60) - 1)

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
    // The maximum size, in bytes, the receiver is willing to receive. Valid
    // values are between 1200 and 65527, inclusive. Limit only applied to
    // protected packets.
    //
    _Field_range_(QUIC_TP_MAX_PACKET_SIZE_MIN, QUIC_TP_MAX_PACKET_SIZE_MAX)
    QUIC_VAR_INT MaxPacketSize;

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
    // The maximum number connection IDs from the peer that an endpoint is
    // willing to store. This value includes only connection IDs sent in
    // NEW_CONNECTION_ID frames. If this parameter is absent, a default of 2 is
    // assumed.
    //
    _Field_range_(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN, QUIC_VAR_INT_MAX)
    QUIC_VAR_INT ActiveConnectionIdLimit;

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
    // packet sent by the client.
    //
    uint8_t OriginalConnectionID[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
    _Field_range_(0, QUIC_MAX_CONNECTION_ID_LENGTH_V1)
    uint8_t OriginalConnectionIDLength;

} QUIC_TRANSPORT_PARAMETERS;

//
// Allocates and encodes the QUIC TP buffer. Free with QUIC_FREE.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicCryptoTlsEncodeTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams,
    _Out_ uint32_t* TPLen
    );

//
// Decodes QUIC TP buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoTlsDecodeTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(TPLen)
        const uint8_t* TPBuf,
    _In_ uint16_t TPLen,
    _Out_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    );
