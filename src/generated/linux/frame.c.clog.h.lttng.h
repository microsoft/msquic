


/*----------------------------------------------------------
// Decoder Ring for FrameLogUnknownType
// [%c][%cX][%llu]   unknown frame (%llu)
// QuicTraceLogVerbose(
            FrameLogUnknownType,
            "[%c][%cX][%llu]   unknown frame (%llu)",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            FrameType);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = FrameType = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogUnknownType,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPadding
// [%c][%cX][%llu]   PADDING Len:%hu
// QuicTraceLogVerbose(
            FrameLogPadding,
            "[%c][%cX][%llu]   PADDING Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)((*Offset - Start) + 1));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = (uint16_t)((*Offset - Start) + 1) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPadding,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPing
// [%c][%cX][%llu]   PING
// QuicTraceLogVerbose(
            FrameLogPing,
            "[%c][%cX][%llu]   PING",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPing,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckInvalid
// [%c][%cX][%llu]   ACK [Invalid]
// QuicTraceLogVerbose(
                FrameLogAckInvalid,
                "[%c][%cX][%llu]   ACK [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAck
// [%c][%cX][%llu]   ACK Largest:%llu Delay:%llu
// QuicTraceLogVerbose(
            FrameLogAck,
            "[%c][%cX][%llu]   ACK Largest:%llu Delay:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.LargestAcknowledged,
            Frame.AckDelay);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.LargestAcknowledged = arg5
// arg6 = arg6 = Frame.AckDelay = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAck,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckSingleBlock
// [%c][%cX][%llu]     %llu
// QuicTraceLogVerbose(
                FrameLogAckSingleBlock,
                "[%c][%cX][%llu]     %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.LargestAcknowledged = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckSingleBlock,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckMultiBlock
// [%c][%cX][%llu]     %llu - %llu
// QuicTraceLogVerbose(
                FrameLogAckMultiBlock,
                "[%c][%cX][%llu]     %llu - %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged - Frame.FirstAckBlock,
                Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.LargestAcknowledged - Frame.FirstAckBlock = arg5
// arg6 = arg6 = Frame.LargestAcknowledged = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckMultiBlock,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckInvalidBlock
// [%c][%cX][%llu]     [Invalid Block]
// QuicTraceLogVerbose(
                    FrameLogAckInvalidBlock,
                    "[%c][%cX][%llu]     [Invalid Block]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckInvalidBlock,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckEcnInvalid
// [%c][%cX][%llu]     ECN [Invalid]
// QuicTraceLogVerbose(
                    FrameLogAckEcnInvalid,
                    "[%c][%cX][%llu]     ECN [Invalid]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckEcnInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckEcn
// [%c][%cX][%llu]     ECN [ECT0=%llu,ECT1=%llu,CE=%llu]
// QuicTraceLogVerbose(
                FrameLogAckEcn,
                "[%c][%cX][%llu]     ECN [ECT0=%llu,ECT1=%llu,CE=%llu]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Ecn.ECT_0_Count,
                Ecn.ECT_1_Count,
                Ecn.CE_Count);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Ecn.ECT_0_Count = arg5
// arg6 = arg6 = Ecn.ECT_1_Count = arg6
// arg7 = arg7 = Ecn.CE_Count = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckEcn,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogResetStreamInvalid
// [%c][%cX][%llu]   RESET_STREAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogResetStreamInvalid,
                "[%c][%cX][%llu]   RESET_STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogResetStreamInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogResetStream
// [%c][%cX][%llu]   RESET_STREAM ID:%llu ErrorCode:0x%llX FinalSize:%llu
// QuicTraceLogVerbose(
            FrameLogResetStream,
            "[%c][%cX][%llu]   RESET_STREAM ID:%llu ErrorCode:0x%llX FinalSize:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode,
            Frame.FinalSize);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.ErrorCode = arg6
// arg7 = arg7 = Frame.FinalSize = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogResetStream,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStopSendingInvalid
// [%c][%cX][%llu]   STOP_SENDING [Invalid]
// QuicTraceLogVerbose(
                FrameLogStopSendingInvalid,
                "[%c][%cX][%llu]   STOP_SENDING [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStopSendingInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStopSending
// [%c][%cX][%llu]   STOP_SENDING ID:%llu Error:0x%llX
// QuicTraceLogVerbose(
            FrameLogStopSending,
            "[%c][%cX][%llu]   STOP_SENDING ID:%llu Error:0x%llX",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.ErrorCode = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStopSending,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogCryptoInvalid
// [%c][%cX][%llu]   CRYPTO [Invalid]
// QuicTraceLogVerbose(
                FrameLogCryptoInvalid,
                "[%c][%cX][%llu]   CRYPTO [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogCryptoInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogCrypto
// [%c][%cX][%llu]   CRYPTO Offset:%llu Len:%hu
// QuicTraceLogVerbose(
            FrameLogCrypto,
            "[%c][%cX][%llu]   CRYPTO Offset:%llu Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Offset,
            (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.Offset = arg5
// arg6 = arg6 = (uint16_t)Frame.Length = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogCrypto,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned short, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(unsigned short, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewTokenInvalid
// [%c][%cX][%llu]   NEW_TOKEN [Invalid]
// QuicTraceLogVerbose(
                FrameLogNewTokenInvalid,
                "[%c][%cX][%llu]   NEW_TOKEN [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogNewTokenInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewToken
// [%c][%cX][%llu]   NEW_TOKEN Length:%llu
// QuicTraceLogVerbose(
            FrameLogNewToken,
            "[%c][%cX][%llu]   NEW_TOKEN Length:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.TokenLength);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.TokenLength = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogNewToken,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamInvalid
// [%c][%cX][%llu]   STREAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamInvalid,
                "[%c][%cX][%llu]   STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamFin
// [%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu Fin
// QuicTraceLogVerbose(
                FrameLogStreamFin,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu Fin",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.Offset = arg6
// arg7 = arg7 = (uint16_t)Frame.Length = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamFin,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned short, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(unsigned short, arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStream
// [%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu
// QuicTraceLogVerbose(
                FrameLogStream,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.Offset = arg6
// arg7 = arg7 = (uint16_t)Frame.Length = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStream,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned short, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(unsigned short, arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxDataInvalid
// [%c][%cX][%llu]   MAX_DATA [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxDataInvalid,
                "[%c][%cX][%llu]   MAX_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxDataInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxData
// [%c][%cX][%llu]   MAX_DATA Max:%llu
// QuicTraceLogVerbose(
            FrameLogMaxData,
            "[%c][%cX][%llu]   MAX_DATA Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.MaximumData);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.MaximumData = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxData,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamDataInvalid
// [%c][%cX][%llu]   MAX_STREAM_DATA [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxStreamDataInvalid,
                "[%c][%cX][%llu]   MAX_STREAM_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxStreamDataInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamData
// [%c][%cX][%llu]   MAX_STREAM_DATA ID:%llu Max:%llu
// QuicTraceLogVerbose(
            FrameLogMaxStreamData,
            "[%c][%cX][%llu]   MAX_STREAM_DATA ID:%llu Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.MaximumData);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.MaximumData = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxStreamData,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamsInvalid
// [%c][%cX][%llu]   MAX_STREAMS [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxStreamsInvalid,
                "[%c][%cX][%llu]   MAX_STREAMS [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxStreamsInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreams
// [%c][%cX][%llu]   MAX_STREAMS[%hu] Count:%llu
// QuicTraceLogVerbose(
            FrameLogMaxStreams,
            "[%c][%cX][%llu]   MAX_STREAMS[%hu] Count:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.MaximumStreams);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.BidirectionalStreams = arg5
// arg6 = arg6 = Frame.MaximumStreams = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogMaxStreams,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned short, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogDataBlockedInvalid
// [%c][%cX][%llu]   DATA_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogDataBlockedInvalid,
                "[%c][%cX][%llu]   DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogDataBlockedInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogDataBlocked
// [%c][%cX][%llu]   DATA_BLOCKED Limit:%llu
// QuicTraceLogVerbose(
            FrameLogDataBlocked,
            "[%c][%cX][%llu]   DATA_BLOCKED Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.DataLimit);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.DataLimit = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogDataBlocked,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamDataBlockedInvalid
// [%c][%cX][%llu]   STREAM_DATA_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamDataBlockedInvalid,
                "[%c][%cX][%llu]   STREAM_DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamDataBlockedInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamDataBlocked
// [%c][%cX][%llu]   STREAM_DATA_BLOCKED ID:%llu Limit:%llu
// QuicTraceLogVerbose(
            FrameLogStreamDataBlocked,
            "[%c][%cX][%llu]   STREAM_DATA_BLOCKED ID:%llu Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.StreamDataLimit);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.StreamID = arg5
// arg6 = arg6 = Frame.StreamDataLimit = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamDataBlocked,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamsBlockedInvalid
// [%c][%cX][%llu]   STREAMS_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamsBlockedInvalid,
                "[%c][%cX][%llu]   STREAMS_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamsBlockedInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamsBlocked
// [%c][%cX][%llu]   STREAMS_BLOCKED[%hu] ID:%llu
// QuicTraceLogVerbose(
            FrameLogStreamsBlocked,
            "[%c][%cX][%llu]   STREAMS_BLOCKED[%hu] ID:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.StreamLimit);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.BidirectionalStreams = arg5
// arg6 = arg6 = Frame.StreamLimit = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogStreamsBlocked,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned short, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewConnectionIDInvalid
// [%c][%cX][%llu]   NEW_CONN_ID [Invalid]
// QuicTraceLogVerbose(
                FrameLogNewConnectionIDInvalid,
                "[%c][%cX][%llu]   NEW_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogNewConnectionIDInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewConnectionID
// [%c][%cX][%llu]   NEW_CONN_ID Seq:%llu RPT:%llu CID:%s Token:%s
// QuicTraceLogVerbose(
            FrameLogNewConnectionID,
            "[%c][%cX][%llu]   NEW_CONN_ID Seq:%llu RPT:%llu CID:%s Token:%s",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence,
            Frame.RetirePriorTo,
            QuicCidBufToStr(Frame.Buffer, Frame.Length).Buffer,
            QuicCidBufToStr(Frame.Buffer + Frame.Length, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.Sequence = arg5
// arg6 = arg6 = Frame.RetirePriorTo = arg6
// arg7 = arg7 = QuicCidBufToStr(Frame.Buffer, Frame.Length).Buffer = arg7
// arg8 = arg8 = QuicCidBufToStr(Frame.Buffer + Frame.Length, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg8
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogNewConnectionID,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        const char *, arg7,
        const char *, arg8), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_string(arg7, arg7)
        ctf_string(arg8, arg8)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogRetireConnectionIDInvalid
// [%c][%cX][%llu]   RETIRE_CONN_ID [Invalid]
// QuicTraceLogVerbose(
                FrameLogRetireConnectionIDInvalid,
                "[%c][%cX][%llu]   RETIRE_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogRetireConnectionIDInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogRetireConnectionID
// [%c][%cX][%llu]   RETIRE_CONN_ID Seq:%llu
// QuicTraceLogVerbose(
            FrameLogRetireConnectionID,
            "[%c][%cX][%llu]   RETIRE_CONN_ID Seq:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.Sequence = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogRetireConnectionID,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathChallengeInvalid
// [%c][%cX][%llu]   PATH_CHALLENGE [Invalid]
// QuicTraceLogVerbose(
                FrameLogPathChallengeInvalid,
                "[%c][%cX][%llu]   PATH_CHALLENGE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPathChallengeInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathChallenge
// [%c][%cX][%llu]   PATH_CHALLENGE [%llu]
// QuicTraceLogVerbose(
            FrameLogPathChallenge,
            "[%c][%cX][%llu]   PATH_CHALLENGE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = CxPlatByteSwapUint64(*(uint64_t*)Frame.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPathChallenge,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathResponseInvalid
// [%c][%cX][%llu]   PATH_RESPONSE [Invalid]
// QuicTraceLogVerbose(
                FrameLogPathResponseInvalid,
                "[%c][%cX][%llu]   PATH_RESPONSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPathResponseInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathResponse
// [%c][%cX][%llu]   PATH_RESPONSE [%llu]
// QuicTraceLogVerbose(
            FrameLogPathResponse,
            "[%c][%cX][%llu]   PATH_RESPONSE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = CxPlatByteSwapUint64(*(uint64_t*)Frame.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogPathResponse,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionCloseInvalid
// [%c][%cX][%llu]   CONN_CLOSE [Invalid]
// QuicTraceLogVerbose(
                FrameLogConnectionCloseInvalid,
                "[%c][%cX][%llu]   CONN_CLOSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogConnectionCloseInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionCloseApp
// [%c][%cX][%llu]   CONN_CLOSE (App) ErrorCode:0x%llX
// QuicTraceLogVerbose(
                FrameLogConnectionCloseApp,
                "[%c][%cX][%llu]   CONN_CLOSE (App) ErrorCode:0x%llX",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.ErrorCode = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogConnectionCloseApp,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionClose
// [%c][%cX][%llu]   CONN_CLOSE ErrorCode:0x%llX FrameType:%llu
// QuicTraceLogVerbose(
                FrameLogConnectionClose,
                "[%c][%cX][%llu]   CONN_CLOSE ErrorCode:0x%llX FrameType:%llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode,
                Frame.FrameType);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.ErrorCode = arg5
// arg6 = arg6 = Frame.FrameType = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogConnectionClose,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogHandshakeDone
// [%c][%cX][%llu]   HANDSHAKE_DONE
// QuicTraceLogVerbose(
            FrameLogHandshakeDone,
            "[%c][%cX][%llu]   HANDSHAKE_DONE",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogHandshakeDone,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogDatagramInvalid
// [%c][%cX][%llu]   DATAGRAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogDatagramInvalid,
                "[%c][%cX][%llu]   DATAGRAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogDatagramInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogDatagram
// [%c][%cX][%llu]   DATAGRAM Len:%hu
// QuicTraceLogVerbose(
            FrameLogDatagram,
            "[%c][%cX][%llu]   DATAGRAM Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = (uint16_t)Frame.Length = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogDatagram,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckFrequencyInvalid
// [%c][%cX][%llu]   ACK_FREQUENCY [Invalid]
// QuicTraceLogVerbose(
                FrameLogAckFrequencyInvalid,
                "[%c][%cX][%llu]   ACK_FREQUENCY [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckFrequencyInvalid,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckFrequency
// [%c][%cX][%llu]   ACK_FREQUENCY SeqNum:%llu PktTolerance:%llu MaxAckDelay:%llu IgnoreOrder:%hhu IgnoreCE:%hhu
// QuicTraceLogVerbose(
            FrameLogAckFrequency,
            "[%c][%cX][%llu]   ACK_FREQUENCY SeqNum:%llu PktTolerance:%llu MaxAckDelay:%llu IgnoreOrder:%hhu IgnoreCE:%hhu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.SequenceNumber,
            Frame.PacketTolerance,
            Frame.UpdateMaxAckDelay,
            Frame.IgnoreOrder,
            Frame.IgnoreCE);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Frame.SequenceNumber = arg5
// arg6 = arg6 = Frame.PacketTolerance = arg6
// arg7 = arg7 = Frame.UpdateMaxAckDelay = arg7
// arg8 = arg8 = Frame.IgnoreOrder = arg8
// arg9 = arg9 = Frame.IgnoreCE = arg9
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogAckFrequency,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7,
        unsigned char, arg8,
        unsigned char, arg9), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
        ctf_integer(unsigned char, arg8, arg8)
        ctf_integer(unsigned char, arg9, arg9)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FrameLogImmediateAck
// [%c][%cX][%llu]   IMMEDIATE_ACK
// QuicTraceLogVerbose(
            FrameLogImmediateAck,
            "[%c][%cX][%llu]   IMMEDIATE_ACK",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, FrameLogImmediateAck,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Frame type decode failure");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Frame type decode failure" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_FRAME_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
