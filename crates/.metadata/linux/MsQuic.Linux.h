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
    QUIC_STATUS_NOT_SUPPORTED = 95,         // 95   (102 on macOS)
    QUIC_STATUS_NOT_FOUND = 2,              // 2
    QUIC_STATUS_BUFFER_TOO_SMALL = 75,      // 75   (84 on macOS)
    QUIC_STATUS_HANDSHAKE_FAILURE = 103,    // 103  (53 on macOS)
    QUIC_STATUS_ABORTED = 125,              // 125  (89 on macOS)
    QUIC_STATUS_ADDRESS_IN_USE = 98,        // 98   (48 on macOS)
    QUIC_STATUS_INVALID_ADDRESS = 97,       // 97   (47 on macOS)
    QUIC_STATUS_CONNECTION_TIMEOUT = 110,   // 110  (60 on macOS)
    QUIC_STATUS_CONNECTION_IDLE = 62,       // 62   (101 on macOS)
    QUIC_STATUS_INTERNAL_ERROR = 5,         // 5
    QUIC_STATUS_CONNECTION_REFUSED = 111,   // 111  (61 on macOS)
    QUIC_STATUS_PROTOCOL_ERROR = 71,        // 71   (100 on macOS)
    QUIC_STATUS_VER_NEG_ERROR = 93,         // 93   (43 on macOS)
    QUIC_STATUS_UNREACHABLE = 113,          // 113  (65 on macOS)
    QUIC_STATUS_TLS_ERROR = 126,            // 126
    QUIC_STATUS_USER_CANCELED = 130,        // 130  (105 on macOS)
    QUIC_STATUS_ALPN_NEG_FAILURE = 92,      // 92   (42 on macOS)
    QUIC_STATUS_STREAM_LIMIT_REACHED = 86,  // 86
    QUIC_STATUS_ALPN_IN_USE = 91,           // 91   (41 on macOS)
    QUIC_STATUS_ADDRESS_NOT_AVAILABLE = 99, // 99   (47 on macOS)

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
