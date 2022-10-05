


/*----------------------------------------------------------
// Decoder Ring for PacketTxDiscarded
// [%c][TX][%llu] Thrown away on shutdown
// QuicTraceLogVerbose(
                PacketTxDiscarded,
                "[%c][TX][%llu] Thrown away on shutdown",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxDiscarded,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostDiscarded
// [%c][TX][%llu] Thrown away on shutdown (lost packet)
// QuicTraceLogVerbose(
            PacketTxLostDiscarded,
            "[%c][TX][%llu] Thrown away on shutdown (lost packet)",
            PtkConnPre(Connection),
            Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxLostDiscarded,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxForget
// [%c][TX][%llu] Forgetting
// QuicTraceLogVerbose(
                PacketTxForget,
                "[%c][TX][%llu] Forgetting",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxForget,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostFack
// [%c][TX][%llu] Lost: FACK %llu packets
// QuicTraceLogVerbose(
                        PacketTxLostFack,
                        "[%c][TX][%llu] Lost: FACK %llu packets",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        LossDetection->LargestAck - Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = LossDetection->LargestAck - Packet->PacketNumber = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxLostFack,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostRack
// [%c][TX][%llu] Lost: RACK %u ms
// QuicTraceLogVerbose(
                        PacketTxLostRack,
                        "[%c][TX][%llu] Lost: RACK %u ms",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        CxPlatTimeDiff32(Packet->SentTime, TimeNow));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = CxPlatTimeDiff32(Packet->SentTime, TimeNow) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxLostRack,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxAckedImplicit
// [%c][TX][%llu] ACKed (implicit)
// QuicTraceLogVerbose(
                PacketTxAckedImplicit,
                "[%c][TX][%llu] ACKed (implicit)",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxAckedImplicit,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTx0RttRejected
// [%c][TX][%llu] Rejected
// QuicTraceLogVerbose(
                PacketTx0RttRejected,
                "[%c][TX][%llu] Rejected",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTx0RttRejected,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxSpuriousLoss
// [%c][TX][%llu] Spurious loss detected
// QuicTraceLogVerbose(
                    PacketTxSpuriousLoss,
                    "[%c][TX][%llu] Spurious loss detected",
                    PtkConnPre(Connection),
                    (*End)->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = (*End)->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxSpuriousLoss,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxAcked
// [%c][TX][%llu] ACKed (%u.%03u ms)
// QuicTraceLogVerbose(
            PacketTxAcked,
            "[%c][TX][%llu] ACKed (%u.%03u ms)",
            PtkConnPre(Connection),
            Packet->PacketNumber,
            PacketRtt / 1000,
            PacketRtt % 1000);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = PacketRtt / 1000 = arg4
// arg5 = arg5 = PacketRtt % 1000 = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxAcked,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxProbeRetransmit
// [%c][TX][%llu] Probe Retransmit
// QuicTraceLogVerbose(
                PacketTxProbeRetransmit,
                "[%c][TX][%llu] Probe Retransmit",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PacketTxProbeRetransmit,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedAck
// [conn][%p] Handshake confirmed (ack)
// QuicTraceLogConnInfo(
            HandshakeConfirmedAck,
            Connection,
            "Handshake confirmed (ack)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, HandshakeConfirmedAck,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathMinMtuValidated
// [conn][%p] Path[%hhu] Minimum MTU validated
// QuicTraceLogConnInfo(
                PathMinMtuValidated,
                Connection,
                "Path[%hhu] Minimum MTU validated",
                Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PathMinMtuValidated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathValidationTimeout
// [conn][%p] Path[%hhu] validation timed out
// QuicTraceLogConnInfo(
                        PathValidationTimeout,
                        Connection,
                        "Path[%hhu] validation timed out",
                        Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, PathValidationTimeout,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ScheduleProbe
// [conn][%p] probe round %hu
// QuicTraceLogConnInfo(
        ScheduleProbe,
        Connection,
        "probe round %hu",
        LossDetection->ProbeCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = LossDetection->ProbeCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, ScheduleProbe,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for KeyChangeConfirmed
// [conn][%p] Key change confirmed by peer
// QuicTraceLogConnVerbose(
            KeyChangeConfirmed,
            Connection,
            "Key change confirmed by peer");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, KeyChangeConfirmed,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnLossDetectionTimerSet
// [conn][%p] Setting loss detection %hhu timer for %u us. (ProbeCount=%hu)
// QuicTraceEvent(
            ConnLossDetectionTimerSet,
            "[conn][%p] Setting loss detection %hhu timer for %u us. (ProbeCount=%hu)",
            Connection,
            TimeoutType,
            Delay,
            LossDetection->ProbeCount);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = TimeoutType = arg3
// arg4 = arg4 = Delay = arg4
// arg5 = arg5 = LossDetection->ProbeCount = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, ConnLossDetectionTimerSet,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned int, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Sent packet metadata",
            SIZEOF_QUIC_SENT_PACKET_METADATA(TempSentPacket->FrameCount));
// arg2 = arg2 = "Sent packet metadata" = arg2
// arg3 = arg3 = SIZEOF_QUIC_SENT_PACKET_METADATA(TempSentPacket->FrameCount) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPacketLost
// [conn][%p][TX][%llu] %hhu Lost: %hhu
// QuicTraceEvent(
                        ConnPacketLost,
                        "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                        Connection,
                        Packet->PacketNumber,
                        QuicPacketTraceType(Packet),
                        QUIC_TRACE_PACKET_LOSS_FACK);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = QuicPacketTraceType(Packet) = arg4
// arg5 = arg5 = QUIC_TRACE_PACKET_LOSS_FACK = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, ConnPacketLost,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPacketACKed
// [conn][%p][TX][%llu] %hhu ACKed
// QuicTraceEvent(
                ConnPacketACKed,
                "[conn][%p][TX][%llu] %hhu ACKed",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = QuicPacketTraceType(Packet) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, ConnPacketACKed,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Incorrect ACK encryption level");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Incorrect ACK encryption level" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOSS_DETECTION_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
