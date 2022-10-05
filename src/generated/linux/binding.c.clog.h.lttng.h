


/*----------------------------------------------------------
// Decoder Ring for BindingListenerAlreadyRegistered
// [bind][%p] Listener (%p) already registered on ALPN
// QuicTraceLogWarning(
                BindingListenerAlreadyRegistered,
                "[bind][%p] Listener (%p) already registered on ALPN",
                Binding, ExistingListener);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = ExistingListener = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingListenerAlreadyRegistered,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingSendFailed
// [bind][%p] Send failed, 0x%x
// QuicTraceLogWarning(
                    BindingSendFailed,
                    "[bind][%p] Send failed, 0x%x",
                    Binding,
                    Status);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingSendFailed,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxVersionNegotiation
// [S][TX][-] VN
// QuicTraceLogVerbose(
            PacketTxVersionNegotiation,
            "[S][TX][-] VN");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, PacketTxVersionNegotiation,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxStatelessReset
// [S][TX][-] SR %s
// QuicTraceLogVerbose(
            PacketTxStatelessReset,
            "[S][TX][-] SR %s",
            QuicCidBufToStr(
                SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
                QUIC_STATELESS_RESET_TOKEN_LENGTH
            ).Buffer);
// arg2 = arg2 = QuicCidBufToStr(
                SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
                QUIC_STATELESS_RESET_TOKEN_LENGTH
            ).Buffer = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, PacketTxStatelessReset,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketTxRetry
// [S][TX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R OrigDestCid:%s (Token %hu bytes)
// QuicTraceLogVerbose(
            PacketTxRetry,
            "[S][TX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R OrigDestCid:%s (Token %hu bytes)",
            RecvPacket->LH->Version,
            QuicCidBufToStr(RecvPacket->SourceCid, RecvPacket->SourceCidLen).Buffer,
            QuicCidBufToStr(NewDestCid, MsQuicLib.CidTotalLength).Buffer,
            QuicCidBufToStr(RecvPacket->DestCid, RecvPacket->DestCidLen).Buffer,
            (uint16_t)sizeof(Token));
// arg2 = arg2 = RecvPacket->LH->Version = arg2
// arg3 = arg3 = QuicCidBufToStr(RecvPacket->SourceCid, RecvPacket->SourceCidLen).Buffer = arg3
// arg4 = arg4 = QuicCidBufToStr(NewDestCid, MsQuicLib.CidTotalLength).Buffer = arg4
// arg5 = arg5 = QuicCidBufToStr(RecvPacket->DestCid, RecvPacket->DestCidLen).Buffer = arg5
// arg6 = arg6 = (uint16_t)sizeof(Token) = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, PacketTxRetry,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3,
        const char *, arg4,
        const char *, arg5,
        unsigned short, arg6), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
        ctf_string(arg4, arg4)
        ctf_string(arg5, arg5)
        ctf_integer(unsigned short, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingSendTestDrop
// [bind][%p] Test dropped packet
// QuicTraceLogVerbose(
                BindingSendTestDrop,
                "[bind][%p] Test dropped packet",
                Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingSendTestDrop,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_BINDING",
            sizeof(QUIC_BINDING));
// arg2 = arg2 = "QUIC_BINDING" = arg2
// arg3 = arg3 = sizeof(QUIC_BINDING) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingErrorStatus
// [bind][%p] ERROR, %u, %s.
// QuicTraceEvent(
                BindingErrorStatus,
                "[bind][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set current compartment Id");
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Set current compartment Id" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingErrorStatus,
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



/*----------------------------------------------------------
// Decoder Ring for BindingCreated
// [bind][%p] Created, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!
// QuicTraceEvent(
        BindingCreated,
        "[bind][%p] Created, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Binding->Socket = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingCreated,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        unsigned int, arg5_len,
        const void *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingCleanup
// [bind][%p] Cleaning up
// QuicTraceEvent(
        BindingCleanup,
        "[bind][%p] Cleaning up",
        Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingCleanup,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingDestroyed
// [bind][%p] Destroyed
// QuicTraceEvent(
        BindingDestroyed,
        "[bind][%p] Destroyed",
        Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingRundown
// [bind][%p] Rundown, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!
// QuicTraceEvent(
        BindingRundown,
        "[bind][%p] Rundown, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Binding->Socket = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingRundown,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4,
        unsigned int, arg5_len,
        const void *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnNoListenerIp
// [conn][%p] No Listener for IP address: %!ADDR!
// QuicTraceEvent(
            ConnNoListenerIp,
            "[conn][%p] No Listener for IP address: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(*Addr), Addr));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(*Addr), Addr) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, ConnNoListenerIp,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnNoListenerAlpn
// [conn][%p] No listener matching ALPN: %!ALPN!
// QuicTraceEvent(
            ConnNoListenerAlpn,
            "[conn][%p] No listener matching ALPN: %!ALPN!",
            Connection,
            CASTED_CLOG_BYTEARRAY(Info->ClientAlpnListLength, Info->ClientAlpnList));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Info->ClientAlpnListLength, Info->ClientAlpnList) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, ConnNoListenerAlpn,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "No listener found for connection");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "No listener found for connection" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindingExecOper
// [bind][%p] Execute: %u
// QuicTraceEvent(
        BindingExecOper,
        "[bind][%p] Execute: %u",
        Binding,
        OperationType);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = OperationType = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, BindingExecOper,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketReceive
// [pack][%llu] Received
// QuicTraceEvent(
            PacketReceive,
            "[pack][%llu] Received",
            Packet->PacketId);
// arg2 = arg2 = Packet->PacketId = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_BINDING_C, PacketReceive,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)
