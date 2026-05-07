


/*----------------------------------------------------------
// Decoder Ring for TlsLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        TlsLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix = arg2
// arg3 = arg3 = Length = arg3
// arg4 = arg4 = SecretStr = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_C, TlsLogSecret,
    TP_ARGS(
        const char *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
// arg2 = arg2 = "QUIC_PACKET_KEY" = arg2
// arg3 = arg3 = PacketKeyLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPT_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
