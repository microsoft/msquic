


/*----------------------------------------------------------
// Decoder Ring for LogPacketVersionNegotiation
// [%c][%cX][-] VerNeg DestCid:%s SrcCid:%s (Payload %hu bytes)
// QuicTraceLogVerbose(
                LogPacketVersionNegotiation,
                "[%c][%cX][-] VerNeg DestCid:%s SrcCid:%s (Payload %hu bytes)",
                PtkConnPre(Connection),
                (uint8_t)PktRxPre(Rx),
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                (uint16_t)(PacketLength - Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = (uint8_t)PktRxPre(Rx) = arg3
// arg4 = arg4 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg4
// arg5 = arg5 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg5
// arg6 = arg6 = (uint16_t)(PacketLength - Offset) = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketVersionNegotiation,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        const char *, arg4,
        const char *, arg5,
        unsigned short, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_string(arg4, arg4)
        ctf_string(arg5, arg5)
        ctf_integer(unsigned short, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketVersionNegotiationVersion
// [%c][%cX][-]   Ver:0x%x
// QuicTraceLogVerbose(
                    LogPacketVersionNegotiationVersion,
                    "[%c][%cX][-]   Ver:0x%x",
                    PtkConnPre(Connection),
                    (uint8_t)PktRxPre(Rx),
                    *(uint32_t*)(Packet + Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = (uint8_t)PktRxPre(Rx) = arg3
// arg4 = arg4 = *(uint32_t*)(Packet + Offset) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketVersionNegotiationVersion,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketRetry
// [%c][%cX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R (Token %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketRetry,
                    "[%c][%cX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R (Token %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    (uint16_t)(PacketLength - (Offset + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = LongHdr->Version = arg4
// arg5 = arg5 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg5
// arg6 = arg6 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg6
// arg7 = arg7 = (uint16_t)(PacketLength - (Offset + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)) = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketRetry,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned int, arg4,
        const char *, arg5,
        const char *, arg6,
        unsigned short, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_string(arg5, arg5)
        ctf_string(arg6, arg6)
        ctf_integer(unsigned short, arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeaderInitial
// [%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:I (Token %hu bytes) (Payload %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketLongHeaderInitial,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:I (Token %hu bytes) (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    (uint16_t)TokenLength,
                    (uint16_t)Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = LongHdr->Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
// arg8 = arg8 = (uint16_t)TokenLength = arg8
// arg9 = arg9 = (uint16_t)Length = arg9
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketLongHeaderInitial,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned int, arg5,
        const char *, arg6,
        const char *, arg7,
        unsigned short, arg8,
        unsigned short, arg9), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_string(arg6, arg6)
        ctf_string(arg7, arg7)
        ctf_integer(unsigned short, arg8, arg8)
        ctf_integer(unsigned short, arg9, arg9)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeader
// [%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:%s (Payload %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketLongHeader,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:%s (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    LongHdr->Version == QUIC_VERSION_2 ?
                        QuicLongHeaderTypeToStringV2(LongHdr->Type) :
                        QuicLongHeaderTypeToStringV1(LongHdr->Type),
                    (uint16_t)Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = LongHdr->Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
// arg8 = arg8 = LongHdr->Version == QUIC_VERSION_2 ?
                        QuicLongHeaderTypeToStringV2(LongHdr->Type) :
                        QuicLongHeaderTypeToStringV1(LongHdr->Type) = arg8
// arg9 = arg9 = (uint16_t)Length = arg9
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketLongHeader,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned int, arg5,
        const char *, arg6,
        const char *, arg7,
        const char *, arg8,
        unsigned short, arg9), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_string(arg6, arg6)
        ctf_string(arg7, arg7)
        ctf_string(arg8, arg8)
        ctf_integer(unsigned short, arg9, arg9)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeaderUnsupported
// [%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCid:%s SrcCid:%s
// QuicTraceLogVerbose(
                LogPacketLongHeaderUnsupported,
                "[%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCid:%s SrcCid:%s",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Invariant->LONG_HDR.Version,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Invariant->LONG_HDR.Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketLongHeaderUnsupported,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        unsigned int, arg5,
        const char *, arg6,
        const char *, arg7), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_string(arg6, arg6)
        ctf_string(arg7, arg7)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LogPacketShortHeader
// [%c][%cX][%llu] SH DestCid:%s KP:%hu SB:%hu (Payload %hu bytes)
// QuicTraceLogVerbose(
                LogPacketShortHeader,
                "[%c][%cX][%llu] SH DestCid:%s KP:%hu SB:%hu (Payload %hu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                Header->KeyPhase,
                Header->SpinBit,
                (uint16_t)(PacketLength - Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg5
// arg6 = arg6 = Header->KeyPhase = arg6
// arg7 = arg7 = Header->SpinBit = arg7
// arg8 = arg8 = (uint16_t)(PacketLength - Offset) = arg8
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, LogPacketShortHeader,
    TP_ARGS(
        unsigned char, arg2,
        unsigned char, arg3,
        unsigned long long, arg4,
        const char *, arg5,
        unsigned short, arg6,
        unsigned short, arg7,
        unsigned short, arg8), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_string(arg5, arg5)
        ctf_integer(unsigned short, arg6, arg6)
        ctf_integer(unsigned short, arg7, arg7)
        ctf_integer(unsigned short, arg8, arg8)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RetryPseudoPacket",
            RetryPseudoPacketLength);
// arg2 = arg2 = "RetryPseudoPacket" = arg2
// arg3 = arg3 = RetryPseudoPacketLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDropPacket
// [conn][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            ConnDropPacket,
            "[conn][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg4
// arg5 = arg5 = Reason = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, ConnDropPacket,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        const char *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_string(arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingDropPacket
// [bind][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            BindingDropPacket,
            "[bind][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg4
// arg5 = arg5 = Reason = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, BindingDropPacket,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        const char *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_string(arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDropPacketEx
// [conn][%p] DROP packet Value=%llu Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            ConnDropPacketEx,
            "[conn][%p] DROP packet Value=%llu Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            Value,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = Value = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg5
// arg6 = arg6 = Reason = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, ConnDropPacketEx,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        unsigned int, arg5_len,
        const void *, arg5,
        const char *, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
        ctf_string(arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingDropPacketEx
// [bind][%p] DROP packet %llu. Dst=%!ADDR! Src=%!ADDR! Reason=%s
// QuicTraceEvent(
            BindingDropPacketEx,
            "[bind][%p] DROP packet %llu. Dst=%!ADDR! Src=%!ADDR! Reason=%s",
            Owner,
            Value,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = Value = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg5
// arg6 = arg6 = Reason = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_C, BindingDropPacketEx,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        unsigned int, arg5_len,
        const void *, arg5,
        const char *, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
        ctf_string(arg6, arg6)
    )
)
