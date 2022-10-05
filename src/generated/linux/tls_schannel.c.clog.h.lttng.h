


/*----------------------------------------------------------
// Decoder Ring for SchannelAchAsync
// [ tls] Calling SspiAcquireCredentialsHandleAsyncW
// QuicTraceLogVerbose(
        SchannelAchAsync,
        "[ tls] Calling SspiAcquireCredentialsHandleAsyncW");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelAchAsync,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelAchWorkerStart
// [ tls] Starting ACH worker
// QuicTraceLogVerbose(
        SchannelAchWorkerStart,
        "[ tls] Starting ACH worker");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelAchWorkerStart,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelAch
// [ tls] Calling AcquireCredentialsHandleW
// QuicTraceLogVerbose(
        SchannelAch,
        "[ tls] Calling AcquireCredentialsHandleW");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelAch,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelAchCompleteInline
// [ tls] Invoking security config completion callback inline, 0x%x
// QuicTraceLogVerbose(
        SchannelAchCompleteInline,
        "[ tls] Invoking security config completion callback inline, 0x%x",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelAchCompleteInline,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelHandshakeComplete
// [conn][%p] Handshake complete (resume=%hu)
// QuicTraceLogConnInfo(
                SchannelHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete (resume=%hu)",
                State->SessionResumed);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->SessionResumed = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelHandshakeComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelConsumedBytes
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnInfo(
            SchannelConsumedBytes,
            TlsContext->Connection,
            "Consumed %u bytes",
            *InBufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *InBufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelConsumedBytes,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelReadHandshakeStart
// [conn][%p] Reading Handshake data starts now
// QuicTraceLogConnInfo(
                        SchannelReadHandshakeStart,
                        TlsContext->Connection,
                        "Reading Handshake data starts now");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelReadHandshakeStart,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelRead1RttStart
// [conn][%p] Reading 1-RTT data starts now
// QuicTraceLogConnInfo(
                        SchannelRead1RttStart,
                        TlsContext->Connection,
                        "Reading 1-RTT data starts now");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelRead1RttStart,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelWriteHandshakeStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                        SchannelWriteHandshakeStart,
                        TlsContext->Connection,
                        "Writing Handshake data starts at %u",
                        State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffsetHandshake = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelWriteHandshakeStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelWrite1RttStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                            SchannelWrite1RttStart,
                            TlsContext->Connection,
                            "Writing 1-RTT data starts at %u",
                            State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffset1Rtt = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelWrite1RttStart,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelProducedData
// [conn][%p] Produced %u bytes
// QuicTraceLogConnInfo(
                SchannelProducedData,
                TlsContext->Connection,
                "Produced %u bytes",
                OutputTokenBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = OutputTokenBuffer->cbBuffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelProducedData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelMissingData
// [conn][%p] TLS message missing %u bytes of data
// QuicTraceLogConnInfo(
                SchannelMissingData,
                TlsContext->Connection,
                "TLS message missing %u bytes of data",
                MissingBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = MissingBuffer->cbBuffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelMissingData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelTransParamsBufferTooSmall
// [conn][%p] Peer TP too large for available buffer (%u vs. %u)
// QuicTraceLogConnInfo(
                        SchannelTransParamsBufferTooSmall,
                        TlsContext->Connection,
                        "Peer TP too large for available buffer (%u vs. %u)",
                        OutSecBufferDesc.pBuffers[i].cbBuffer,
                        (TlsContext->PeerTransportParams != NULL) ?
                            TlsContext->PeerTransportParamsLength :
                            *InBufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = OutSecBufferDesc.pBuffers[i].cbBuffer = arg3
// arg4 = arg4 = (TlsContext->PeerTransportParams != NULL) ?
                            TlsContext->PeerTransportParamsLength :
                            *InBufferLength = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelTransParamsBufferTooSmall,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        SchannelContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelContextCreated,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            SchannelContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelContextCleaningUp,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelKeyReady
// [conn][%p] Key Ready Type, %u [%hu to %hu]
// QuicTraceLogConnVerbose(
                SchannelKeyReady,
                TlsContext->Connection,
                "Key Ready Type, %u [%hu to %hu]",
                (uint32_t)TrafficSecret->TrafficSecretType,
                TrafficSecret->MsgSequenceStart,
                TrafficSecret->MsgSequenceEnd);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)TrafficSecret->TrafficSecretType = arg3
// arg4 = arg4 = TrafficSecret->MsgSequenceStart = arg4
// arg5 = arg5 = TrafficSecret->MsgSequenceEnd = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelKeyReady,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned short, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelIgnoringTicket
// [conn][%p] Ignoring %u ticket bytes
// QuicTraceLogConnVerbose(
            SchannelIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelIgnoringTicket,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SchannelProcessingData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
        SchannelProcessingData,
        TlsContext->Connection,
        "Processing %u received bytes",
        *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, SchannelProcessingData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Get unicode string size");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "Get unicode string size" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "unicode string",
            RequiredSize);
// arg2 = arg2 = "unicode string" = arg2
// arg3 = arg3 = RequiredSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NULL CallbackData to CxPlatTlsSspiNotifyCallback");
// arg2 = arg2 = "NULL CallbackData to CxPlatTlsSspiNotifyCallback" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            Config->Connection,
            "Mismatched SEC_CONFIG IsServer state");
// arg2 = arg2 = Config->Connection = arg2
// arg3 = arg3 = "Mismatched SEC_CONFIG IsServer state" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, TlsError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Convert SNI to unicode");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Convert SNI to unicode" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TLS_SCHANNEL_C, TlsErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
