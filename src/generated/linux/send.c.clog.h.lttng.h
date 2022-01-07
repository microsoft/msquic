


/*----------------------------------------------------------
// Decoder Ring for SetSendFlag
// [strm][%p] Setting flags 0x%x (existing flags: 0x%x)
// QuicTraceLogStreamVerbose(
            SetSendFlag,
            Stream,
            "Setting flags 0x%x (existing flags: 0x%x)",
            (SendFlags & (uint32_t)(~Stream->SendFlags)),
            Stream->SendFlags);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (SendFlags & (uint32_t)(~Stream->SendFlags)) = arg3
// arg4 = arg4 = Stream->SendFlags = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, SetSendFlag,
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
// Decoder Ring for ClearSendFlags
// [strm][%p] Removing flags %x
// QuicTraceLogStreamVerbose(
            ClearSendFlags,
            Stream,
            "Removing flags %x",
            (SendFlags & Stream->SendFlags));
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (SendFlags & Stream->SendFlags) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, ClearSendFlags,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ScheduleSendFlags
// [conn][%p] Scheduling flags 0x%x to 0x%x
// QuicTraceLogConnVerbose(
            ScheduleSendFlags,
            Connection,
            "Scheduling flags 0x%x to 0x%x",
            SendFlags,
            Send->SendFlags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = SendFlags = arg3
// arg4 = arg4 = Send->SendFlags = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, ScheduleSendFlags,
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
// Decoder Ring for RemoveSendFlagsMsg
// [conn][%p] Removing flags %x
// QuicTraceLogConnVerbose(
            RemoveSendFlagsMsg,
            QuicSendGetConnection(Send),
            "Removing flags %x",
            (SendFlags & Send->SendFlags));
// arg1 = arg1 = QuicSendGetConnection(Send) = arg1
// arg3 = arg3 = (SendFlags & Send->SendFlags) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, RemoveSendFlagsMsg,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AmplificationProtectionBlocked
// [conn][%p] Cannot send any more because of amplification protection
// QuicTraceLogConnVerbose(
                AmplificationProtectionBlocked,
                Connection,
                "Cannot send any more because of amplification protection");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, AmplificationProtectionBlocked,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendFlushComplete
// [conn][%p] Flush complete flags=0x%x
// QuicTraceLogConnVerbose(
        SendFlushComplete,
        Connection,
        "Flush complete flags=0x%x",
        Send->SendFlags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Send->SendFlags = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, SendFlushComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StartAckDelayTimer
// [conn][%p] Starting ACK_DELAY timer for %u ms
// QuicTraceLogConnVerbose(
            StartAckDelayTimer,
            Connection,
            "Starting ACK_DELAY timer for %u ms",
            Connection->Settings.MaxAckDelayMs);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Settings.MaxAckDelayMs = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, StartAckDelayTimer,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnQueueSendFlush
// [conn][%p] Queueing send flush, reason=%u
// QuicTraceEvent(
                ConnQueueSendFlush,
                "[conn][%p] Queueing send flush, reason=%u",
                Connection,
                Reason);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Reason = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, ConnQueueSendFlush,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnFlushSend
// [conn][%p] Flushing Send. Allowance=%u bytes
// QuicTraceEvent(
        ConnFlushSend,
        "[conn][%p] Flushing Send. Allowance=%u bytes",
        Connection,
        Builder.SendAllowance);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Builder.SendAllowance = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_C, ConnFlushSend,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)
