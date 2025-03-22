


/*----------------------------------------------------------
// Decoder Ring for DatapathInitFail
// [  dp] Failed to initialize datapath, status:%d
// QuicTraceLogVerbose(
            DatapathInitFail,
            "[  dp] Failed to initialize datapath, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, DatapathInitFail,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RawDatapathInitFail
// [ raw] Failed to initialize raw datapath, status:%d
// QuicTraceLogVerbose(
                RawDatapathInitFail,
                "[ raw] Failed to initialize raw datapath, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, RawDatapathInitFail,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SockCreateFail
// [sock] Failed to create socket, status:%d
// QuicTraceLogVerbose(
            SockCreateFail,
            "[sock] Failed to create socket, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, SockCreateFail,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SockStatus
// [sock] Allocated socket. IsServer: %d, UseQTIP: %d:
// QuicTraceLogVerbose(
        SockStatus,
        "[sock] Allocated socket. IsServer: %d, UseQTIP: %d:", (*NewSocket)->IsServer, Config->UseQTIP);
// arg2 = arg2 = (*NewSocket)->IsServer = arg2
// arg3 = arg3 = Config->UseQTIP = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, SockStatus,
    TP_ARGS(
        int, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RawSockCreateFail
// [sock] Failed to create raw socket, status:%d
// QuicTraceLogVerbose(
                RawSockCreateFail,
                "[sock] Failed to create raw socket, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, RawSockCreateFail,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)
