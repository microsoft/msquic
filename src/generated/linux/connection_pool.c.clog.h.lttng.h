


/*----------------------------------------------------------
// Decoder Ring for ConnPoolLocalAddressNotFound
// [conp] Failed to find local address, 0x%x
// QuicTraceLogError(
            ConnPoolLocalAddressNotFound,
            "[conp] Failed to find local address, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolLocalAddressNotFound,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolInvalidParam
// [conp] Invalid parameter, 0x%x
// QuicTraceLogError(
            ConnPoolInvalidParam,
            "[conp] Invalid parameter, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolInvalidParam,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolServerNameTooLong
// [conp] ServerName too long (%llu bytes)
// QuicTraceLogError(
            ConnPoolServerNameTooLong,
            "[conp] ServerName too long (%llu bytes)",
            ServerNameLength);
// arg2 = arg2 = ServerNameLength = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolServerNameTooLong,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolResolveAddress
// [conp] Failed to resolve address, 0x%x
// QuicTraceLogError(
                ConnPoolResolveAddress,
                "[conp] Failed to resolve address, 0x%x",
                Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolResolveAddress,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolGetLocalAddress
// [conp] Failed to get local address, 0x%x
// QuicTraceLogError(
            ConnPoolGetLocalAddress,
            "[conp] Failed to get local address, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolGetLocalAddress,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolGetRssConfig
// [conp] Failed to get RSS config, 0x%x
// QuicTraceLogError(
            ConnPoolGetRssConfig,
            "[conp] Failed to get RSS config, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolGetRssConfig,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssNotConfigured
// [conp] RSS not configured, 0x%x
// QuicTraceLogError(
            ConnPoolRssNotConfigured,
            "[conp] RSS not configured, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolRssNotConfigured,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssSecretKeyTooLong
// [conp] RSS secret key too long (%u bytes), 0x%x
// QuicTraceLogError(
            ConnPoolRssSecretKeyTooLong,
            "[conp] RSS secret key too long (%u bytes), 0x%x",
            RssConfig->RssSecretKeyLength,
            Status);
// arg2 = arg2 = RssConfig->RssSecretKeyLength = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolRssSecretKeyTooLong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssSecretKeyTooShort
// [conp] RSS secret key too short (%u bytes), 0x%x
// QuicTraceLogError(
            ConnPoolRssSecretKeyTooShort,
            "[conp] RSS secret key too short (%u bytes), 0x%x",
            RssConfig->RssSecretKeyLength,
            Status);
// arg2 = arg2 = RssConfig->RssSecretKeyLength = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolRssSecretKeyTooShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolOpenConnection
// [conp] Failed to open connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolOpenConnection,
                    "[conp] Failed to open connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolOpenConnection,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetShareBinding
// [conp] Failed to set share binding on connection[%u], 0x%x
// QuicTraceLogError(
                        ConnPoolSetShareBinding,
                        "[conp] Failed to set share binding on connection[%u], 0x%x",
                        i,
                        Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolSetShareBinding,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetCibirId
// [conp] Failed to set CIBIR ID on connection[%u], 0x%x
// QuicTraceLogError(
                        ConnPoolSetCibirId,
                        "[conp] Failed to set CIBIR ID on connection[%u], 0x%x",
                        i,
                        Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolSetCibirId,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetRemoteAddress
// [conp] Failed to set remote address on connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolSetRemoteAddress,
                    "[conp] Failed to set remote address on connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolSetRemoteAddress,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetLocalAddress
// [conp] Failed to set local address on connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolSetLocalAddress,
                    "[conp] Failed to set local address on connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolSetLocalAddress,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolStartConnection
// [conp] Failed to start connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolStartConnection,
                    "[conp] Failed to start connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolStartConnection,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolMaxRetries
// [conp] Ran out of retries. MaxRetries %u, Iteration %u, Port %u, 0x%x
// QuicTraceLogError(
                ConnPoolMaxRetries,
                "[conp] Ran out of retries. MaxRetries %u, Iteration %u, Port %u, 0x%x",
                MaxCreationRetries,
                i,
                QuicAddrGetPort(&LocalAddress),
                Status);
// arg2 = arg2 = MaxCreationRetries = arg2
// arg3 = arg3 = i = arg3
// arg4 = arg4 = QuicAddrGetPort(&LocalAddress) = arg4
// arg5 = arg5 = Status = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolMaxRetries,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server name",
                ServerNameLength + 1);
// arg2 = arg2 = "Server name" = arg2
// arg3 = arg3 = ServerNameLength + 1 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_POOL_CREATE,
        Config->Registration);
// arg2 = arg2 = QUIC_TRACE_API_CONNECTION_POOL_CREATE = arg2
// arg3 = arg3 = Config->Registration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ApiEnter,
    TP_ARGS(
        unsigned int, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, (uint64_t)arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ApiExitStatus,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)
