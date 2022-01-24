


/*----------------------------------------------------------
// Decoder Ring for PerfTcpCreateClient
// [perf][tcp][%p] Client created
// QuicTraceLogVerbose(
        PerfTcpCreateClient,
        "[perf][tcp][%p] Client created",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpCreateClient,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpCreateServer
// [perf][tcp][%p] Server created
// QuicTraceLogVerbose(
        PerfTcpCreateServer,
        "[perf][tcp][%p] Server created",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpCreateServer,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpDestroyed
// [perf][tcp][%p] Destroyed
// QuicTraceLogVerbose(
        PerfTcpDestroyed,
        "[perf][tcp][%p] Destroyed",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpConnectCallback
// [perf][tcp][%p] Connect callback %hhu
// QuicTraceLogVerbose(
        PerfTcpConnectCallback,
        "[perf][tcp][%p] Connect callback %hhu",
        This,
        Connected);
// arg2 = arg2 = This = arg2
// arg3 = arg3 = Connected = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpConnectCallback,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpReceiveCallback
// [perf][tcp][%p] Receive callback
// QuicTraceLogVerbose(
        PerfTcpReceiveCallback,
        "[perf][tcp][%p] Receive callback",
        This);
// arg2 = arg2 = This = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpReceiveCallback,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpSendCompleteCallback
// [perf][tcp][%p] SendComplete callback
// QuicTraceLogVerbose(
        PerfTcpSendCompleteCallback,
        "[perf][tcp][%p] SendComplete callback",
        This);
// arg2 = arg2 = This = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpSendCompleteCallback,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppAccept
// [perf][tcp][%p] App Accept
// QuicTraceLogVerbose(
            PerfTcpAppAccept,
            "[perf][tcp][%p] App Accept",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppAccept,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppConnect
// [perf][tcp][%p] App Connect
// QuicTraceLogVerbose(
            PerfTcpAppConnect,
            "[perf][tcp][%p] App Connect",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppConnect,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpStartTls
// [perf][tcp][%p] Start TLS
// QuicTraceLogVerbose(
            PerfTcpStartTls,
            "[perf][tcp][%p] Start TLS",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpStartTls,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppDisconnect
// [perf][tcp][%p] App Disconnect
// QuicTraceLogVerbose(
            PerfTcpAppDisconnect,
            "[perf][tcp][%p] App Disconnect",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppDisconnect,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppReceive
// [perf][tcp][%p] App Receive %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
            PerfTcpAppReceive,
            "[perf][tcp][%p] App Receive %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
            this,
            (uint16_t)(Frame->Length - sizeof(TcpStreamFrame)),
            (uint8_t)StreamFrame->Open,
            (uint8_t)StreamFrame->Fin,
            (uint8_t)StreamFrame->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = (uint16_t)(Frame->Length - sizeof(TcpStreamFrame)) = arg3
// arg4 = arg4 = (uint8_t)StreamFrame->Open = arg4
// arg5 = arg5 = (uint8_t)StreamFrame->Fin = arg5
// arg6 = arg6 = (uint8_t)StreamFrame->Abort = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppReceive,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3,
        unsigned char, arg4,
        unsigned char, arg5,
        unsigned char, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
        ctf_integer(unsigned char, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpSendFrame
// [perf][tcp][%p] Send frame %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
                PerfTcpSendFrame,
                "[perf][tcp][%p] Send frame %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
                this,
                (uint16_t)StreamLength,
                (uint8_t)StreamFrame->Open,
                (uint8_t)StreamFrame->Fin,
                (uint8_t)StreamFrame->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = (uint16_t)StreamLength = arg3
// arg4 = arg4 = (uint8_t)StreamFrame->Open = arg4
// arg5 = arg5 = (uint8_t)StreamFrame->Fin = arg5
// arg6 = arg6 = (uint8_t)StreamFrame->Abort = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpSendFrame,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3,
        unsigned char, arg4,
        unsigned char, arg5,
        unsigned char, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
        ctf_integer(unsigned char, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppSendComplete
// [perf][tcp][%p] App Send complete %u bytes
// QuicTraceLogVerbose(
            PerfTcpAppSendComplete,
            "[perf][tcp][%p] App Send complete %u bytes",
            this,
            Data->Length);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = Data->Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppSendComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppSend
// [perf][tcp][%p] App Send %u bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
        PerfTcpAppSend,
        "[perf][tcp][%p] App Send %u bytes, Open=%hhu Fin=%hhu Abort=%hhu",
        this,
        Data->Length,
        (uint8_t)Data->Open,
        (uint8_t)Data->Fin,
        (uint8_t)Data->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = Data->Length = arg3
// arg4 = arg4 = (uint8_t)Data->Open = arg4
// arg5 = arg5 = (uint8_t)Data->Fin = arg5
// arg6 = arg6 = (uint8_t)Data->Abort = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppSend,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned char, arg4,
        unsigned char, arg5,
        unsigned char, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
        ctf_integer(unsigned char, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppClose
// [perf][tcp][%p] App Close
// QuicTraceLogVerbose(
        PerfTcpAppClose,
        "[perf][tcp][%p] App Close",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TCP_CPP, PerfTcpAppClose,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)
