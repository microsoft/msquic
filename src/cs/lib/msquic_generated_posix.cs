//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//


using System.Runtime.InteropServices;

namespace Microsoft.Quic
{
    public static unsafe partial class MsQuic_Posix
    {
        [NativeTypeName("#define ERROR_BASE 200000000")]
        public const int ERROR_BASE = 200000000;

        [NativeTypeName("#define TLS_ERROR_BASE 256 + ERROR_BASE")]
        public const int TLS_ERROR_BASE = 256 + 200000000;

        [NativeTypeName("#define CERT_ERROR_BASE 512 + ERROR_BASE")]
        public const int CERT_ERROR_BASE = 512 + 200000000;

        [NativeTypeName("#define QUIC_STATUS_SUCCESS ((QUIC_STATUS)0)")]
        public const uint QUIC_STATUS_SUCCESS = ((uint)(0));

        [NativeTypeName("#define QUIC_STATUS_PENDING ((QUIC_STATUS)-2)")]
        public const uint QUIC_STATUS_PENDING = unchecked((uint)(-2));

        [NativeTypeName("#define QUIC_STATUS_CONTINUE ((QUIC_STATUS)-1)")]
        public const uint QUIC_STATUS_CONTINUE = unchecked((uint)(-1));

        [NativeTypeName("#define QUIC_STATUS_OUT_OF_MEMORY ((QUIC_STATUS)ENOMEM)")]
        public const uint QUIC_STATUS_OUT_OF_MEMORY = ((uint)(12));

        [NativeTypeName("#define QUIC_STATUS_INVALID_PARAMETER ((QUIC_STATUS)EINVAL)")]
        public const uint QUIC_STATUS_INVALID_PARAMETER = ((uint)(22));

        [NativeTypeName("#define QUIC_STATUS_INVALID_STATE ((QUIC_STATUS)EPERM)")]
        public const uint QUIC_STATUS_INVALID_STATE = ((uint)(1));

        [NativeTypeName("#define QUIC_STATUS_NOT_SUPPORTED ((QUIC_STATUS)EOPNOTSUPP)")]
        public const uint QUIC_STATUS_NOT_SUPPORTED = ((uint)(95));

        [NativeTypeName("#define QUIC_STATUS_NOT_FOUND ((QUIC_STATUS)ENOENT)")]
        public const uint QUIC_STATUS_NOT_FOUND = ((uint)(2));

        [NativeTypeName("#define QUIC_STATUS_BUFFER_TOO_SMALL ((QUIC_STATUS)EOVERFLOW)")]
        public const uint QUIC_STATUS_BUFFER_TOO_SMALL = ((uint)(75));

        [NativeTypeName("#define QUIC_STATUS_HANDSHAKE_FAILURE ((QUIC_STATUS)ECONNABORTED)")]
        public const uint QUIC_STATUS_HANDSHAKE_FAILURE = ((uint)(103));

        [NativeTypeName("#define QUIC_STATUS_ABORTED ((QUIC_STATUS)ECANCELED)")]
        public const uint QUIC_STATUS_ABORTED = ((uint)(125));

        [NativeTypeName("#define QUIC_STATUS_ADDRESS_IN_USE ((QUIC_STATUS)EADDRINUSE)")]
        public const uint QUIC_STATUS_ADDRESS_IN_USE = ((uint)(98));

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_TIMEOUT ((QUIC_STATUS)ETIMEDOUT)")]
        public const uint QUIC_STATUS_CONNECTION_TIMEOUT = ((uint)(110));

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_IDLE ((QUIC_STATUS)ETIME)")]
        public const uint QUIC_STATUS_CONNECTION_IDLE = ((uint)(62));

        [NativeTypeName("#define QUIC_STATUS_INTERNAL_ERROR ((QUIC_STATUS)EIO)")]
        public const uint QUIC_STATUS_INTERNAL_ERROR = ((uint)(5));

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_REFUSED ((QUIC_STATUS)ECONNREFUSED)")]
        public const uint QUIC_STATUS_CONNECTION_REFUSED = ((uint)(111));

        [NativeTypeName("#define QUIC_STATUS_PROTOCOL_ERROR ((QUIC_STATUS)EPROTO)")]
        public const uint QUIC_STATUS_PROTOCOL_ERROR = ((uint)(71));

        [NativeTypeName("#define QUIC_STATUS_VER_NEG_ERROR ((QUIC_STATUS)EPROTONOSUPPORT)")]
        public const uint QUIC_STATUS_VER_NEG_ERROR = ((uint)(93));

        [NativeTypeName("#define QUIC_STATUS_UNREACHABLE ((QUIC_STATUS)EHOSTUNREACH)")]
        public const uint QUIC_STATUS_UNREACHABLE = ((uint)(113));

        [NativeTypeName("#define QUIC_STATUS_TLS_ERROR ((QUIC_STATUS)ENOKEY)")]
        public const uint QUIC_STATUS_TLS_ERROR = ((uint)(126));

        [NativeTypeName("#define QUIC_STATUS_USER_CANCELED ((QUIC_STATUS)EOWNERDEAD)")]
        public const uint QUIC_STATUS_USER_CANCELED = ((uint)(130));

        [NativeTypeName("#define QUIC_STATUS_ALPN_NEG_FAILURE ((QUIC_STATUS)ENOPROTOOPT)")]
        public const uint QUIC_STATUS_ALPN_NEG_FAILURE = ((uint)(92));

        [NativeTypeName("#define QUIC_STATUS_STREAM_LIMIT_REACHED ((QUIC_STATUS)ESTRPIPE)")]
        public const uint QUIC_STATUS_STREAM_LIMIT_REACHED = ((uint)(86));

        [NativeTypeName("#define QUIC_STATUS_CLOSE_NOTIFY QUIC_STATUS_TLS_ALERT(0)")]
        public const uint QUIC_STATUS_CLOSE_NOTIFY = ((uint)(0xff & 0) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_BAD_CERTIFICATE QUIC_STATUS_TLS_ALERT(42)")]
        public const uint QUIC_STATUS_BAD_CERTIFICATE = ((uint)(0xff & 42) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_UNSUPPORTED_CERTIFICATE QUIC_STATUS_TLS_ALERT(43)")]
        public const uint QUIC_STATUS_UNSUPPORTED_CERTIFICATE = ((uint)(0xff & 43) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_REVOKED_CERTIFICATE QUIC_STATUS_TLS_ALERT(44)")]
        public const uint QUIC_STATUS_REVOKED_CERTIFICATE = ((uint)(0xff & 44) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_EXPIRED_CERTIFICATE QUIC_STATUS_TLS_ALERT(45)")]
        public const uint QUIC_STATUS_EXPIRED_CERTIFICATE = ((uint)(0xff & 45) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_UNKNOWN_CERTIFICATE QUIC_STATUS_TLS_ALERT(46)")]
        public const uint QUIC_STATUS_UNKNOWN_CERTIFICATE = ((uint)(0xff & 46) + 256 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_CERT_EXPIRED QUIC_STATUS_CERT_ERROR(1)")]
        public const uint QUIC_STATUS_CERT_EXPIRED = ((uint)(1) + 512 + 200000000);

        [NativeTypeName("#define QUIC_STATUS_CERT_UNTRUSTED_ROOT QUIC_STATUS_CERT_ERROR(2)")]
        public const uint QUIC_STATUS_CERT_UNTRUSTED_ROOT = ((uint)(2) + 512 + 200000000);

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_UNSPEC 0")]
        public const int QUIC_ADDRESS_FAMILY_UNSPEC = 0;

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_INET 2")]
        public const int QUIC_ADDRESS_FAMILY_INET = 2;

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_INET6 23")]
        public const int QUIC_ADDRESS_FAMILY_INET6 = 23;

        [NativeTypeName("#define FALSE 0")]
        public const int FALSE = 0;

        [NativeTypeName("#define TRUE 1")]
        public const int TRUE = 1;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_REVOCATION 0x00000080")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_REVOCATION = 0x00000080;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA 0x00000100")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA = 0x00000100;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_WRONG_USAGE 0x00000200")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_WRONG_USAGE = 0x00000200;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID 0x00001000")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID = 0x00001000;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_DATE_INVALID 0x00002000")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_DATE_INVALID = 0x00002000;

        [NativeTypeName("#define QUIC_CERTIFICATE_FLAG_IGNORE_WEAK_SIGNATURE 0x00010000")]
        public const int QUIC_CERTIFICATE_FLAG_IGNORE_WEAK_SIGNATURE = 0x00010000;
    }
}
