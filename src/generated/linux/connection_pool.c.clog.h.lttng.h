


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
// Decoder Ring for ConnPoolInvalidParamNeedRemoteAddress
// [conp] Neither ServerName nor ServerAddress were set, 0x%x
// QuicTraceLogError(
            ConnPoolInvalidParamNeedRemoteAddress,
            "[conp] Neither ServerName nor ServerAddress were set, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolInvalidParamNeedRemoteAddress,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolCreateSocket
// [conp] Failed to create socket, 0x%x
// QuicTraceLogError(
            ConnPoolCreateSocket,
            "[conp] Failed to create socket, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolCreateSocket,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolGetLocalAddresses
// [conp] Failed to get local address info, 0x%x
// QuicTraceLogError(
            ConnPoolGetLocalAddresses,
            "[conp] Failed to get local address info, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolGetLocalAddresses,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



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
// Decoder Ring for ConnPoolRssNotSupported
// [conp] RSS not supported, 0x%x
// QuicTraceLogError(
            ConnPoolRssNotSupported,
            "[conp] RSS not supported, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolRssNotSupported,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssSecretKeyTooLong
// [conp] RSS secret key too long, 0x%x
// QuicTraceLogError(
            ConnPoolRssSecretKeyTooLong,
            "[conp] RSS secret key too long, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_POOL_C, ConnPoolRssSecretKeyTooLong,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSS Processor List",
            RssConfig->RssIndirectionTableLength);
// arg2 = arg2 = "RSS Processor List" = arg2
// arg3 = arg3 = RssConfig->RssIndirectionTableLength = arg3
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
