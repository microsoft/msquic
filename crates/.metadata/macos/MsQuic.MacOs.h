#define ERROR_BASE                          200000000                       // 0xBEBC200
#define TLS_ERROR_BASE                      256 + ERROR_BASE                // 0xBEBC300
#define CERT_ERROR_BASE                     512 + ERROR_BASE                // 0xBEBC400

typedef enum {
    QUIC_STATUS_SUCCESS = 0,                // 0
    QUIC_STATUS_PENDING = -2,               // -2
    QUIC_STATUS_CONTINUE = -1,              // -1
    QUIC_STATUS_OUT_OF_MEMORY = 12,         // 12
    QUIC_STATUS_INVALID_PARAMETER = 22,     // 22
    QUIC_STATUS_INVALID_STATE = 1,          // 1
    QUIC_STATUS_NOT_SUPPORTED = 102,        // 102   (95 on Linux)
    QUIC_STATUS_NOT_FOUND = 2,              // 2
    QUIC_STATUS_BUFFER_TOO_SMALL = 84,      // 84   (75 on Linux)
    QUIC_STATUS_HANDSHAKE_FAILURE = 53,     // 53   (103 on Linux)
    QUIC_STATUS_ABORTED = 89,               // 89   (125 on Linux)
    QUIC_STATUS_ADDRESS_IN_USE = 48,        // 48   (98 on Linux)
    QUIC_STATUS_INVALID_ADDRESS = 47,       // 47   (97 on Linux)
    QUIC_STATUS_CONNECTION_TIMEOUT = 60,    // 60   (110 on Linux)
    QUIC_STATUS_CONNECTION_IDLE = 101,      // 101   (62 on Linux)
    QUIC_STATUS_INTERNAL_ERROR = 5,         // 5
    QUIC_STATUS_CONNECTION_REFUSED = 61,    // 61   (111 on Linux)
    QUIC_STATUS_PROTOCOL_ERROR = 100,       // 100   (71 on Linux)
    QUIC_STATUS_VER_NEG_ERROR = 43,         // 43   (93 on Linux)
    QUIC_STATUS_UNREACHABLE = 65,           // 65   (113 on Linux)
    QUIC_STATUS_TLS_ERROR = 126,            // 126
    QUIC_STATUS_USER_CANCELED = 105,        // 105   (130 on Linux)
    QUIC_STATUS_ALPN_NEG_FAILURE = 42,      // 42   (92 on Linux)
    QUIC_STATUS_STREAM_LIMIT_REACHED = 86,  // 86
    QUIC_STATUS_ALPN_IN_USE = 41,           // 41   (91 on Linux)
    QUIC_STATUS_ADDRESS_NOT_AVAILABLE = 47, // 47   (99 on Linux)

    QUIC_STATUS_CLOSE_NOTIFY = (0xff & 0) + TLS_ERROR_BASE,        // 0xBEBC300 - Close notify
    QUIC_STATUS_BAD_CERTIFICATE = (0xff & 42) + TLS_ERROR_BASE,    // 0xBEBC32A - Bad Certificate
    QUIC_STATUS_UNSUPPORTED_CERTIFICATE = (0xff & 43) + TLS_ERROR_BASE, // 0xBEBC32B - Unsupported Certificate
    QUIC_STATUS_REVOKED_CERTIFICATE = (0xff & 44) + TLS_ERROR_BASE,     // 0xBEBC32C - Revoked Certificate
    QUIC_STATUS_EXPIRED_CERTIFICATE = (0xff & 45) + TLS_ERROR_BASE,     // 0xBEBC32D - Expired Certificate
    QUIC_STATUS_UNKNOWN_CERTIFICATE = (0xff & 46) + TLS_ERROR_BASE,     // 0xBEBC32E - Unknown Certificate
    QUIC_STATUS_REQUIRED_CERTIFICATE = (0xff & 116) + TLS_ERROR_BASE,   // 0xBEBC374 - Required Certificate

    QUIC_STATUS_CERT_EXPIRED = 1 + CERT_ERROR_BASE,    // 0xBEBC401
    QUIC_STATUS_CERT_UNTRUSTED_ROOT = 2 + CERT_ERROR_BASE, // 0xBEBC402
    QUIC_STATUS_CERT_NO_CERT = 3 + CERT_ERROR_BASE,    // 0xBEBC403
} QUIC_STATUS;
