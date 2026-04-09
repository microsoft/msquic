


/*----------------------------------------------------------
// Decoder Ring for WarnFallbackToOsSockets
// [sock] Warning: XDP successfully initialized but failed to plumb XDP rules. Falling back to using normal OS sockets.
// QuicTraceLogWarning(
                        WarnFallbackToOsSockets,
                        "[sock] Warning: XDP successfully initialized but failed to plumb XDP rules. Falling back to using normal OS sockets.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, WarnFallbackToOsSockets,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WarnNoXdpForCibirSockets
// [sock] Warning: app requested CIBIR but XDP not enabled/available/initialized. \
                Falling back to normal OS sockets to allow for CIBIR transport parameter negotiation.
// QuicTraceLogWarning(
                WarnNoXdpForCibirSockets,
                "[sock] Warning: app requested CIBIR but XDP not enabled/available/initialized. \
                Falling back to normal OS sockets to allow for CIBIR transport parameter negotiation.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, WarnNoXdpForCibirSockets,
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



/*----------------------------------------------------------
// Decoder Ring for ErrNoXdpForQtip
// [sock] Error: app requested QTIP but XDP not enabled/available/initialized.
// QuicTraceLogError(
                ErrNoXdpForQtip,
                "[sock] Error: app requested QTIP but XDP not enabled/available/initialized.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_XPLAT_C, ErrNoXdpForQtip,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)
