namespace Microsoft.Quic
{
    public unsafe partial struct QUIC_ADDR_STR
    {
        [NativeTypeName("char [64]")]
        public fixed sbyte Address[64];
    }

    public static unsafe partial class MsQuic
    {
        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrIsValid([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr)
        {
            return (byte)((Addr->si_family == 0 || Addr->si_family == 2 || Addr->si_family == 23) ? 1 : 0);
        }

        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrCompareIp([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr1, [NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr2)
        {
            if (Addr1->si_family == 2)
            {
                return (byte)((memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(in_addr)) == 0) ? 1 : 0);
            }
            else
            {
                return (byte)((memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(in6_addr)) == 0) ? 1 : 0);
            }
        }

        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrCompare([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr1, [NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr2)
        {
            if (Addr1->si_family != Addr2->si_family || Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port)
            {
                return 0;
            }

            return QuicAddrCompareIp(Addr1, Addr2);
        }

        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrIsWildCard([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr)
        {
            if (Addr->si_family == 0)
            {
                return 1;
            }
            else if (Addr->si_family == 2)
            {
                in_addr ZeroAddr = new in_addr
                {
                    S_un = new _S_un_e__Union
                    {
                        S_un_b = new _S_un_b_e__Struct
                        {
                            s_b1 = 0,
                        },
                    },
                };

                return (byte)((memcmp(&Addr->Ipv4.sin_addr, &ZeroAddr, sizeof(in_addr)) == 0) ? 1 : 0);
            }
            else
            {
                in6_addr ZeroAddr = new in6_addr
                {
                    u = new _u_e__Union
                    {
                        Byte = new byte[16]
                        {
                            0,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                            default,
                        },
                    },
                };

                return (byte)((memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(in6_addr)) == 0) ? 1 : 0);
            }
        }

        [return: NativeTypeName("QUIC_ADDRESS_FAMILY")]
        public static ushort QuicAddrGetFamily([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr)
        {
            return (ushort)(Addr->si_family);
        }

        public static void QuicAddrSetFamily([NativeTypeName("QUIC_ADDR *")] _SOCKADDR_INET* Addr, [NativeTypeName("QUIC_ADDRESS_FAMILY")] ushort Family)
        {
            Addr->si_family = (ushort)(Family);
        }

        [return: NativeTypeName("uint16_t")]
        public static ushort QuicAddrGetPort([NativeTypeName("const QUIC_ADDR *const")] _SOCKADDR_INET* Addr)
        {
            return ((ushort)((((Addr->Ipv4.sin_port) & 0x00ff) << 8) | (((Addr->Ipv4.sin_port) & 0xff00) >> 8)));
        }

        public static void QuicAddrSetPort([NativeTypeName("QUIC_ADDR *")] _SOCKADDR_INET* Addr, [NativeTypeName("uint16_t")] ushort Port)
        {
            Addr->Ipv4.sin_port = ((ushort)((((Port) & 0x00ff) << 8) | (((Port) & 0xff00) >> 8)));
        }

        public static void QuicAddrSetToLoopback([NativeTypeName("QUIC_ADDR *")] _SOCKADDR_INET* Addr)
        {
            if (Addr->si_family == 2)
            {
                Addr->Ipv4.sin_addr.S_un.S_un_b.s_b1 = 127;
                Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4 = 1;
            }
            else
            {
                Addr->Ipv6.sin6_addr.u.Byte[15] = 1;
            }
        }

        public static void QuicAddrIncrement([NativeTypeName("QUIC_ADDR *")] _SOCKADDR_INET* Addr)
        {
            if (Addr->si_family == 2)
            {
                Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4++;
            }
            else
            {
                Addr->Ipv6.sin6_addr.u.Byte[15]++;
            }
        }

        [return: NativeTypeName("uint32_t")]
        public static uint QuicAddrHash([NativeTypeName("const QUIC_ADDR *")] _SOCKADDR_INET* Addr)
        {
            uint Hash = 5387;

            if (Addr->si_family == 2)
            {
                Hash = ((Hash << 5) - Hash) + (Addr->Ipv4.sin_port & 0xFF);
                Hash = ((Hash << 5) - Hash) + (Addr->Ipv4.sin_port >> 8);
                for (byte i = 0; i < sizeof(in_addr); ++i)
                {
                    Hash = ((Hash << 5) - Hash) + (i[((byte*)(&Addr->Ipv4.sin_addr))]);
                }
            }
            else
            {
                Hash = ((Hash << 5) - Hash) + (Addr->Ipv6.sin6_port & 0xFF);
                Hash = ((Hash << 5) - Hash) + (Addr->Ipv6.sin6_port >> 8);
                for (byte i = 0; i < sizeof(in6_addr); ++i)
                {
                    Hash = ((Hash << 5) - Hash) + (i[((byte*)(&Addr->Ipv6.sin6_addr))]);
                }
            }

            return Hash;
        }

        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrFromString([NativeTypeName("const char *")] sbyte* AddrStr, [NativeTypeName("uint16_t")] ushort Port, [NativeTypeName("QUIC_ADDR *")] _SOCKADDR_INET* Addr)
        {
            Addr->Ipv4.sin_port = ((ushort)((((Port) & 0x00ff) << 8) | (((Port) & 0xff00) >> 8)));
            if (RtlIpv4StringToAddressExA(AddrStr, 0, &Addr->Ipv4.sin_addr, &Addr->Ipv4.sin_port) == 0)
            {
                Addr->si_family = 2;
            }
            else if (RtlIpv6StringToAddressExA(AddrStr, &Addr->Ipv6.sin6_addr, &Addr->Ipv6.Anonymous.sin6_scope_id, &Addr->Ipv6.sin6_port) == 0)
            {
                Addr->si_family = 23;
            }
            else
            {
                return 0;
            }

            return 1;
        }

        [return: NativeTypeName("BOOLEAN")]
        public static byte QuicAddrToString([NativeTypeName("const QUIC_ADDR *")] _SOCKADDR_INET* Addr, [NativeTypeName("QUIC_ADDR_STR *")] QUIC_ADDR_STR* AddrStr)
        {
            int Status;
            uint AddrStrLen = unchecked(64);

            if (Addr->si_family == 2)
            {
                Status = RtlIpv4AddressToStringExA(&Addr->Ipv4.sin_addr, Addr->Ipv4.sin_port, AddrStr->Address, &AddrStrLen);
            }
            else
            {
                Status = RtlIpv6AddressToStringExA(&Addr->Ipv6.sin6_addr, 0, Addr->Ipv6.sin6_port, AddrStr->Address, &AddrStrLen);
            }

            return (byte)((Status == 0) ? 1 : 0);
        }

        [NativeTypeName("#define ERROR_QUIC_USER_CANCELED _HRESULT_TYPEDEF_(0x80410002L)")]
        public const int ERROR_QUIC_USER_CANCELED = unchecked((int)(0x80410002));

        [NativeTypeName("#define ERROR_QUIC_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x80410003L)")]
        public const int ERROR_QUIC_INTERNAL_ERROR = unchecked((int)(0x80410003));

        [NativeTypeName("#define ERROR_QUIC_PROTOCOL_VIOLATION _HRESULT_TYPEDEF_(0x80410004L)")]
        public const int ERROR_QUIC_PROTOCOL_VIOLATION = unchecked((int)(0x80410004));

        [NativeTypeName("#define ERROR_QUIC_CONNECTION_IDLE _HRESULT_TYPEDEF_(0x80410005L)")]
        public const int ERROR_QUIC_CONNECTION_IDLE = unchecked((int)(0x80410005));

        [NativeTypeName("#define ERROR_QUIC_CONNECTION_TIMEOUT _HRESULT_TYPEDEF_(0x80410006L)")]
        public const int ERROR_QUIC_CONNECTION_TIMEOUT = unchecked((int)(0x80410006));

        [NativeTypeName("#define ERROR_QUIC_ALPN_NEG_FAILURE _HRESULT_TYPEDEF_(0x80410007L)")]
        public const int ERROR_QUIC_ALPN_NEG_FAILURE = unchecked((int)(0x80410007));

        [NativeTypeName("#define ERROR_QUIC_STREAM_LIMIT_REACHED _HRESULT_TYPEDEF_(0x80410008L)")]
        public const int ERROR_QUIC_STREAM_LIMIT_REACHED = unchecked((int)(0x80410008));

        [NativeTypeName("#define QUIC_TLS_ALERT_HRESULT_PREFIX _HRESULT_TYPEDEF_(0x80410100L)")]
        public const int QUIC_TLS_ALERT_HRESULT_PREFIX = unchecked((int)(0x80410100));

        [NativeTypeName("#define QUIC_STATUS_SUCCESS S_OK")]
        public const int QUIC_STATUS_SUCCESS = ((int)(0));

        [NativeTypeName("#define QUIC_STATUS_PENDING SUCCESS_HRESULT_FROM_WIN32(ERROR_IO_PENDING)")]
        public const int QUIC_STATUS_PENDING = ((int)(((997) & 0x0000FFFF) | (7 << 16)));

        [NativeTypeName("#define QUIC_STATUS_CONTINUE SUCCESS_HRESULT_FROM_WIN32(ERROR_CONTINUE)")]
        public const int QUIC_STATUS_CONTINUE = ((int)(((1246) & 0x0000FFFF) | (7 << 16)));

        [NativeTypeName("#define QUIC_STATUS_OUT_OF_MEMORY E_OUTOFMEMORY")]
        public const int QUIC_STATUS_OUT_OF_MEMORY = unchecked((int)(0x8007000E));

        [NativeTypeName("#define QUIC_STATUS_INVALID_PARAMETER E_INVALIDARG")]
        public const int QUIC_STATUS_INVALID_PARAMETER = unchecked((int)(0x80070057));

        [NativeTypeName("#define QUIC_STATUS_INVALID_STATE E_NOT_VALID_STATE")]
        public static readonly int QUIC_STATUS_INVALID_STATE = HRESULT_FROM_WIN32(5023);

        [NativeTypeName("#define QUIC_STATUS_NOT_SUPPORTED E_NOINTERFACE")]
        public const int QUIC_STATUS_NOT_SUPPORTED = unchecked((int)(0x80004002));

        [NativeTypeName("#define QUIC_STATUS_NOT_FOUND HRESULT_FROM_WIN32(ERROR_NOT_FOUND)")]
        public static readonly int QUIC_STATUS_NOT_FOUND = HRESULT_FROM_WIN32(1168);

        [NativeTypeName("#define QUIC_STATUS_BUFFER_TOO_SMALL E_NOT_SUFFICIENT_BUFFER")]
        public static readonly int QUIC_STATUS_BUFFER_TOO_SMALL = HRESULT_FROM_WIN32(122);

        [NativeTypeName("#define QUIC_STATUS_HANDSHAKE_FAILURE ERROR_QUIC_HANDSHAKE_FAILURE")]
        public const int QUIC_STATUS_HANDSHAKE_FAILURE = unchecked((int)(0x80410000));

        [NativeTypeName("#define QUIC_STATUS_ABORTED E_ABORT")]
        public const int QUIC_STATUS_ABORTED = unchecked((int)(0x80004004));

        [NativeTypeName("#define QUIC_STATUS_ADDRESS_IN_USE HRESULT_FROM_WIN32(WSAEADDRINUSE)")]
        public static readonly int QUIC_STATUS_ADDRESS_IN_USE = HRESULT_FROM_WIN32(10048);

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_TIMEOUT ERROR_QUIC_CONNECTION_TIMEOUT")]
        public const int QUIC_STATUS_CONNECTION_TIMEOUT = unchecked((int)(0x80410006));

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_IDLE ERROR_QUIC_CONNECTION_IDLE")]
        public const int QUIC_STATUS_CONNECTION_IDLE = unchecked((int)(0x80410005));

        [NativeTypeName("#define QUIC_STATUS_UNREACHABLE HRESULT_FROM_WIN32(ERROR_HOST_UNREACHABLE)")]
        public static readonly int QUIC_STATUS_UNREACHABLE = HRESULT_FROM_WIN32(1232);

        [NativeTypeName("#define QUIC_STATUS_INTERNAL_ERROR ERROR_QUIC_INTERNAL_ERROR")]
        public const int QUIC_STATUS_INTERNAL_ERROR = unchecked((int)(0x80410003));

        [NativeTypeName("#define QUIC_STATUS_CONNECTION_REFUSED HRESULT_FROM_WIN32(ERROR_CONNECTION_REFUSED)")]
        public static readonly int QUIC_STATUS_CONNECTION_REFUSED = HRESULT_FROM_WIN32(1225);

        [NativeTypeName("#define QUIC_STATUS_PROTOCOL_ERROR ERROR_QUIC_PROTOCOL_VIOLATION")]
        public const int QUIC_STATUS_PROTOCOL_ERROR = unchecked((int)(0x80410004));

        [NativeTypeName("#define QUIC_STATUS_VER_NEG_ERROR ERROR_QUIC_VER_NEG_FAILURE")]
        public const int QUIC_STATUS_VER_NEG_ERROR = unchecked((int)(0x80410001));

        [NativeTypeName("#define QUIC_STATUS_TLS_ERROR HRESULT_FROM_WIN32(WSA_SECURE_HOST_NOT_FOUND)")]
        public static readonly int QUIC_STATUS_TLS_ERROR = HRESULT_FROM_WIN32(11032);

        [NativeTypeName("#define QUIC_STATUS_USER_CANCELED ERROR_QUIC_USER_CANCELED")]
        public const int QUIC_STATUS_USER_CANCELED = unchecked((int)(0x80410002));

        [NativeTypeName("#define QUIC_STATUS_ALPN_NEG_FAILURE ERROR_QUIC_ALPN_NEG_FAILURE")]
        public const int QUIC_STATUS_ALPN_NEG_FAILURE = unchecked((int)(0x80410007));

        [NativeTypeName("#define QUIC_STATUS_STREAM_LIMIT_REACHED ERROR_QUIC_STREAM_LIMIT_REACHED")]
        public const int QUIC_STATUS_STREAM_LIMIT_REACHED = unchecked((int)(0x80410008));

        [NativeTypeName("#define QUIC_STATUS_CLOSE_NOTIFY QUIC_STATUS_TLS_ALERT(0)")]
        public const int QUIC_STATUS_CLOSE_NOTIFY = unchecked(((int)(0x80410100)) | (0xff & 0));

        [NativeTypeName("#define QUIC_STATUS_BAD_CERTIFICATE QUIC_STATUS_TLS_ALERT(42)")]
        public const int QUIC_STATUS_BAD_CERTIFICATE = unchecked(((int)(0x80410100)) | (0xff & 42));

        [NativeTypeName("#define QUIC_STATUS_EXPIRED_CERTIFICATE QUIC_STATUS_TLS_ALERT(45)")]
        public const int QUIC_STATUS_EXPIRED_CERTIFICATE = unchecked(((int)(0x80410100)) | (0xff & 45));

        [NativeTypeName("#define QUIC_ADDR_V4_PORT_OFFSET FIELD_OFFSET(SOCKADDR_IN, sin_port)")]
        public static readonly int QUIC_ADDR_V4_PORT_OFFSET = ((int)((long)(&(((sockaddr_in*)(0))->sin_port))));

        [NativeTypeName("#define QUIC_ADDR_V4_IP_OFFSET FIELD_OFFSET(SOCKADDR_IN, sin_addr)")]
        public static readonly int QUIC_ADDR_V4_IP_OFFSET = ((int)((long)(&(((sockaddr_in*)(0))->sin_addr))));

        [NativeTypeName("#define QUIC_ADDR_V6_PORT_OFFSET FIELD_OFFSET(SOCKADDR_IN6, sin6_port)")]
        public static readonly int QUIC_ADDR_V6_PORT_OFFSET = ((int)((long)(&(((sockaddr_in6*)(0))->sin6_port))));

        [NativeTypeName("#define QUIC_ADDR_V6_IP_OFFSET FIELD_OFFSET(SOCKADDR_IN6, sin6_addr)")]
        public static readonly int QUIC_ADDR_V6_IP_OFFSET = ((int)((long)(&(((sockaddr_in6*)(0))->sin6_addr))));

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_UNSPEC AF_UNSPEC")]
        public const int QUIC_ADDRESS_FAMILY_UNSPEC = 0;

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_INET AF_INET")]
        public const int QUIC_ADDRESS_FAMILY_INET = 2;

        [NativeTypeName("#define QUIC_ADDRESS_FAMILY_INET6 AF_INET6")]
        public const int QUIC_ADDRESS_FAMILY_INET6 = 23;
    }
}
