


/*----------------------------------------------------------
// Decoder Ring for WarnFallbackToOs
// [sock] Warning: failed to plumb XDP rules. Falling back to using normal OS sockets.
// QuicTraceLogWarning(
                        WarnFallbackToOs,
                        "[sock] Warning: failed to plumb XDP rules. Falling back to using normal OS sockets.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, WarnFallbackToOs,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for ErrNoXdpForRaw
// [sock] Error: app requested QTIP but XDP not enabled/available/initialized.
// QuicTraceLogWarning(
                ErrNoXdpForRaw,
                "[sock] Error: app requested QTIP but XDP not enabled/available/initialized.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, ErrNoXdpForRaw,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WarnNoXdpForCibir
// [sock] Warning: app requested CIBIR but XDP not enabled/available/initialized. \
                Falling back to normal OS sockets to allow for CIBIR TP parameter negotiation.
// QuicTraceLogWarning(
                WarnNoXdpForCibir,
                "[sock] Warning: app requested CIBIR but XDP not enabled/available/initialized. \
                Falling back to normal OS sockets to allow for CIBIR TP parameter negotiation.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, WarnNoXdpForCibir,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



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
