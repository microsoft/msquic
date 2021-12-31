


/*----------------------------------------------------------
// Decoder Ring for IgnoreCryptoFrame
// [conn][%p] Ignoring received crypto after cleanup
// QuicTraceLogConnWarning(
            IgnoreCryptoFrame,
            Connection,
            "Ignoring received crypto after cleanup");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, IgnoreCryptoFrame,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DiscardKeyType
// [conn][%p] Discarding key type = %hhu
// QuicTraceLogConnInfo(
        DiscardKeyType,
        Connection,
        "Discarding key type = %hhu",
        (uint8_t)KeyType);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)KeyType = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, DiscardKeyType,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ZeroRttAccepted
// [conn][%p] 0-RTT accepted
// QuicTraceLogConnInfo(
            ZeroRttAccepted,
            Connection,
            "0-RTT accepted");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ZeroRttAccepted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ZeroRttRejected
// [conn][%p] 0-RTT rejected
// QuicTraceLogConnInfo(
            ZeroRttRejected,
            Connection,
            "0-RTT rejected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ZeroRttRejected,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedServer
// [conn][%p] Handshake confirmed (server)
// QuicTraceLogConnInfo(
                HandshakeConfirmedServer,
                Connection,
                "Handshake confirmed (server)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, HandshakeConfirmedServer,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CustomCertValidationSuccess
// [conn][%p] Custom cert validation succeeded
// QuicTraceLogConnInfo(
            CustomCertValidationSuccess,
            QuicCryptoGetConnection(Crypto),
            "Custom cert validation succeeded");
// arg1 = arg1 = QuicCryptoGetConnection(Crypto) = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, CustomCertValidationSuccess,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CryptoDump
// [conn][%p] QS:%u MAX:%u UNA:%u NXT:%u RECOV:%u-%u
// QuicTraceLogConnVerbose(
            CryptoDump,
            Connection,
            "QS:%u MAX:%u UNA:%u NXT:%u RECOV:%u-%u",
            Crypto->TlsState.BufferTotalLength,
            Crypto->MaxSentLength,
            Crypto->UnAckedOffset,
            Crypto->NextSendOffset,
            Crypto->InRecovery ? Crypto->RecoveryNextOffset : 0,
            Crypto->InRecovery ? Crypto->RecoveryEndOffset : 0);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Crypto->TlsState.BufferTotalLength = arg3
// arg4 = arg4 = Crypto->MaxSentLength = arg4
// arg5 = arg5 = Crypto->UnAckedOffset = arg5
// arg6 = arg6 = Crypto->NextSendOffset = arg6
// arg7 = arg7 = Crypto->InRecovery ? Crypto->RecoveryNextOffset : 0 = arg7
// arg8 = arg8 = Crypto->InRecovery ? Crypto->RecoveryEndOffset : 0 = arg8
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, CryptoDump,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6,
        unsigned int, arg7,
        unsigned int, arg8), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
        ctf_integer(unsigned int, arg7, arg7)
        ctf_integer(unsigned int, arg8, arg8)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CryptoDumpUnacked
// [conn][%p]   unACKed: [%llu, %llu]
// QuicTraceLogConnVerbose(
                CryptoDumpUnacked,
                Connection,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = UnAcked = arg3
// arg4 = arg4 = Sack->Low = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, CryptoDumpUnacked,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CryptoDumpUnacked2
// [conn][%p]   unACKed: [%llu, %u]
// QuicTraceLogConnVerbose(
                CryptoDumpUnacked2,
                Connection,
                "  unACKed: [%llu, %u]",
                UnAcked,
                Crypto->MaxSentLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = UnAcked = arg3
// arg4 = arg4 = Crypto->MaxSentLength = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, CryptoDumpUnacked2,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NoMoreRoomForCrypto
// [conn][%p] No room for CRYPTO frame
// QuicTraceLogConnVerbose(
            NoMoreRoomForCrypto,
            Connection,
            "No room for CRYPTO frame");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, NoMoreRoomForCrypto,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AddCryptoFrame
// [conn][%p] Sending %hu crypto bytes, offset=%u
// QuicTraceLogConnVerbose(
        AddCryptoFrame,
        Connection,
        "Sending %hu crypto bytes, offset=%u",
        (uint16_t)Frame.Length,
        CryptoOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame.Length = arg3
// arg4 = arg4 = CryptoOffset = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, AddCryptoFrame,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecoverCrypto
// [conn][%p] Recovering crypto from %llu up to %llu
// QuicTraceLogConnVerbose(
            RecoverCrypto,
            Connection,
            "Recovering crypto from %llu up to %llu",
            Start,
            End);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Start = arg3
// arg4 = arg4 = End = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, RecoverCrypto,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AckCrypto
// [conn][%p] Received ack for %u crypto bytes, offset=%u
// QuicTraceLogConnVerbose(
        AckCrypto,
        Connection,
        "Received ack for %u crypto bytes, offset=%u",
        Length,
        Offset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Length = arg3
// arg4 = arg4 = Offset = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, AckCrypto,
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
// Decoder Ring for RecvCrypto
// [conn][%p] Received %hu crypto bytes, offset=%llu Ready=%hhu
// QuicTraceLogConnVerbose(
        RecvCrypto,
        Connection,
        "Received %hu crypto bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        *DataReady);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame->Length = arg3
// arg4 = arg4 = Frame->Offset = arg4
// arg5 = arg5 = *DataReady = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, RecvCrypto,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateConnected
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)
// QuicTraceLogConnVerbose(
            IndicateConnected,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
            Event.CONNECTED.SessionResumed);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.CONNECTED.SessionResumed = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, IndicateConnected,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DrainCrypto
// [conn][%p] Draining %u crypto bytes
// QuicTraceLogConnVerbose(
            DrainCrypto,
            QuicCryptoGetConnection(Crypto),
            "Draining %u crypto bytes",
            RecvBufferConsumed);
// arg1 = arg1 = QuicCryptoGetConnection(Crypto) = arg1
// arg3 = arg3 = RecvBufferConsumed = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, DrainCrypto,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CryptoNotReady
// [conn][%p] No complete TLS messages to process
// QuicTraceLogConnVerbose(
                CryptoNotReady,
                Connection,
                "No complete TLS messages to process");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, CryptoNotReady,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "crypto send buffer",
            SendBufferLength);
// arg2 = arg2 = "crypto send buffer" = arg2
// arg3 = arg3 = SendBufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "Creating initial keys");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Creating initial keys" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnErrorStatus,
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
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Tried to write beyond crypto flow control limit.");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Tried to write beyond crypto flow control limit." = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnWriteKeyUpdated
// [conn][%p] Write Key Updated, %hhu.
// QuicTraceEvent(
            ConnWriteKeyUpdated,
            "[conn][%p] Write Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.WriteKey);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Crypto->TlsState.WriteKey = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnWriteKeyUpdated,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnReadKeyUpdated
// [conn][%p] Read Key Updated, %hhu.
// QuicTraceEvent(
            ConnReadKeyUpdated,
            "[conn][%p] Read Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.ReadKey);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Crypto->TlsState.ReadKey = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnReadKeyUpdated,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnHandshakeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                ConnSourceCidRemoved,
                "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                Connection,
                InitialSourceCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(InitialSourceCid->CID.Length, InitialSourceCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = InitialSourceCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(InitialSourceCid->CID.Length, InitialSourceCid->CID.Data) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnSourceCidRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnNewPacketKeys
// [conn][%p] New packet keys created successfully.
// QuicTraceEvent(
            ConnNewPacketKeys,
            "[conn][%p] New packet keys created successfully.",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnNewPacketKeys,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnKeyPhaseChange
// [conn][%p] Key phase change (locally initiated=%hhu).
// QuicTraceEvent(
        ConnKeyPhaseChange,
        "[conn][%p] Key phase change (locally initiated=%hhu).",
        Connection,
        LocalUpdate);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = LocalUpdate = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_C, ConnKeyPhaseChange,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)
