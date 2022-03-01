


/*----------------------------------------------------------
// Decoder Ring for NoSniPresent
// [conn][%p] No SNI extension present
// QuicTraceLogConnWarning(
            NoSniPresent,
            Connection,
            "No SNI extension present");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, NoSniPresent,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPReserved
// [conn][%p] TP: Reserved ID %llu, length %hu
// QuicTraceLogConnWarning(
                    DecodeTPReserved,
                    Connection,
                    "TP: Reserved ID %llu, length %hu",
                    Id,
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Id = arg3
// arg4 = arg4 = Length = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPReserved,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPUnknown
// [conn][%p] TP: Unknown ID %llu, length %hu
// QuicTraceLogConnWarning(
                    DecodeTPUnknown,
                    Connection,
                    "TP: Unknown ID %llu, length %hu",
                    Id,
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Id = arg3
// arg4 = arg4 = Length = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPUnknown,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPStart
// [conn][%p] Encoding Transport Parameters (Server = %hhu)
// QuicTraceLogConnVerbose(
        EncodeTPStart,
        Connection,
        "Encoding Transport Parameters (Server = %hhu)",
        IsServerTP);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = IsServerTP = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPStart,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPOriginalDestinationCID
// [conn][%p] TP: Original Destination Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPOriginalDestinationCID,
            Connection,
            "TP: Original Destination Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->OriginalDestinationConnectionID,
                TransportParams->OriginalDestinationConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->OriginalDestinationConnectionID,
                TransportParams->OriginalDestinationConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPOriginalDestinationCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPIdleTimeout
// [conn][%p] TP: Idle Timeout (%llu ms)
// QuicTraceLogConnVerbose(
            EncodeTPIdleTimeout,
            Connection,
            "TP: Idle Timeout (%llu ms)",
            TransportParams->IdleTimeout);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->IdleTimeout = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPIdleTimeout,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPStatelessResetToken
// [conn][%p] TP: Stateless Reset Token (%s)
// QuicTraceLogConnVerbose(
            EncodeTPStatelessResetToken,
            Connection,
            "TP: Stateless Reset Token (%s)",
            QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPStatelessResetToken,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxUdpPayloadSize
// [conn][%p] TP: Max Udp Payload Size (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPMaxUdpPayloadSize,
            Connection,
            "TP: Max Udp Payload Size (%llu bytes)",
            TransportParams->MaxUdpPayloadSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxUdpPayloadSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPMaxUdpPayloadSize,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxData
// [conn][%p] TP: Max Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxData,
            Connection,
            "TP: Max Data (%llu bytes)",
            TransportParams->InitialMaxData);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxData = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxData,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamDataBidiLocal
// [conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamDataBidiLocal,
            Connection,
            "TP: Max Local Bidirectional Stream Data (%llu bytes)",
            TransportParams->InitialMaxStreamDataBidiLocal);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiLocal = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamDataBidiLocal,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamDataBidiRemote
// [conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamDataBidiRemote,
            Connection,
            "TP: Max Remote Bidirectional Stream Data (%llu bytes)",
            TransportParams->InitialMaxStreamDataBidiRemote);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiRemote = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamDataBidiRemote,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamUni
// [conn][%p] TP: Max Unidirectional Stream Data (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamUni,
            Connection,
            "TP: Max Unidirectional Stream Data (%llu)",
            TransportParams->InitialMaxStreamDataUni);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataUni = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamUni,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxBidiStreams
// [conn][%p] TP: Max Bidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPMaxBidiStreams,
            Connection,
            "TP: Max Bidirectional Streams (%llu)",
            TransportParams->InitialMaxBidiStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxBidiStreams = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPMaxBidiStreams,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxUniStreams
// [conn][%p] TP: Max Unidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPMaxUniStreams,
            Connection,
            "TP: Max Unidirectional Streams (%llu)",
            TransportParams->InitialMaxUniStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxUniStreams = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPMaxUniStreams,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPAckDelayExponent
// [conn][%p] TP: ACK Delay Exponent (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPAckDelayExponent,
            Connection,
            "TP: ACK Delay Exponent (%llu)",
            TransportParams->AckDelayExponent);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->AckDelayExponent = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPAckDelayExponent,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxAckDelay
// [conn][%p] TP: Max ACK Delay (%llu ms)
// QuicTraceLogConnVerbose(
            EncodeTPMaxAckDelay,
            Connection,
            "TP: Max ACK Delay (%llu ms)",
            TransportParams->MaxAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxAckDelay = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPMaxAckDelay,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPDisableMigration
// [conn][%p] TP: Disable Active Migration
// QuicTraceLogConnVerbose(
            EncodeTPDisableMigration,
            Connection,
            "TP: Disable Active Migration");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPDisableMigration,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPPreferredAddress
// [conn][%p] TP: Preferred Address
// QuicTraceLogConnVerbose(
            EncodeTPPreferredAddress,
            Connection,
            "TP: Preferred Address");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPPreferredAddress,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPCIDLimit
// [conn][%p] TP: Connection ID Limit (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPCIDLimit,
            Connection,
            "TP: Connection ID Limit (%llu)",
            TransportParams->ActiveConnectionIdLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->ActiveConnectionIdLimit = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPCIDLimit,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPOriginalCID
// [conn][%p] TP: Initial Source Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPOriginalCID,
            Connection,
            "TP: Initial Source Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->InitialSourceConnectionID,
                TransportParams->InitialSourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->InitialSourceConnectionID,
                TransportParams->InitialSourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPOriginalCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPRetrySourceCID
// [conn][%p] TP: Retry Source Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPRetrySourceCID,
            Connection,
            "TP: Retry Source Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->RetrySourceConnectionID,
                TransportParams->RetrySourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->RetrySourceConnectionID,
                TransportParams->RetrySourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPRetrySourceCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeMaxDatagramFrameSize
// [conn][%p] TP: Max Datagram Frame Size (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeMaxDatagramFrameSize,
            Connection,
            "TP: Max Datagram Frame Size (%llu bytes)",
            TransportParams->MaxDatagramFrameSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxDatagramFrameSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeMaxDatagramFrameSize,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPDisable1RttEncryption
// [conn][%p] TP: Disable 1-RTT Encryption
// QuicTraceLogConnVerbose(
            EncodeTPDisable1RttEncryption,
            Connection,
            "TP: Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPDisable1RttEncryption,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPVersionNegotiationExt
// [conn][%p] TP: Version Negotiation Extension (%u bytes)
// QuicTraceLogConnVerbose(
            EncodeTPVersionNegotiationExt,
            Connection,
            "TP: Version Negotiation Extension (%u bytes)",
            TransportParams->VersionInfoLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->VersionInfoLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPVersionNegotiationExt,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPMinAckDelay
// [conn][%p] TP: Min ACK Delay (%llu us)
// QuicTraceLogConnVerbose(
            EncodeTPMinAckDelay,
            Connection,
            "TP: Min ACK Delay (%llu us)",
            TransportParams->MinAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MinAckDelay = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPMinAckDelay,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPCibirEncoding
// [conn][%p] TP: CIBIR Encoding (%llu length, %llu offset)
// QuicTraceLogConnVerbose(
            EncodeTPCibirEncoding,
            Connection,
            "TP: CIBIR Encoding (%llu length, %llu offset)",
            TransportParams->CibirLength,
            TransportParams->CibirOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->CibirLength = arg3
// arg4 = arg4 = TransportParams->CibirOffset = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPCibirEncoding,
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
// Decoder Ring for EncodeTPTest
// [conn][%p] TP: TEST TP (Type %hu, Length %hu)
// QuicTraceLogConnVerbose(
            EncodeTPTest,
            Connection,
            "TP: TEST TP (Type %hu, Length %hu)",
            TestParam->Type,
            TestParam->Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TestParam->Type = arg3
// arg4 = arg4 = TestParam->Length = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPTest,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EncodeTPEnd
// [conn][%p] Encoded %hu bytes for QUIC TP
// QuicTraceLogConnVerbose(
        EncodeTPEnd,
        Connection,
        "Encoded %hu bytes for QUIC TP",
        (uint16_t)FinalTPLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)FinalTPLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, EncodeTPEnd,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPStart
// [conn][%p] Decoding Transport Parameters (Server = %hhu) (%hu bytes)
// QuicTraceLogConnVerbose(
        DecodeTPStart,
        Connection,
        "Decoding Transport Parameters (Server = %hhu) (%hu bytes)",
        IsServerTP,
        TPLen);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = IsServerTP = arg3
// arg4 = arg4 = TPLen = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPStart,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPOriginalDestinationCID
// [conn][%p] TP: Original Connection Destination ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPOriginalDestinationCID,
                Connection,
                "TP: Original Connection Destination ID (%s)",
                QuicCidBufToStr(
                    TransportParams->OriginalDestinationConnectionID,
                    TransportParams->OriginalDestinationConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->OriginalDestinationConnectionID,
                    TransportParams->OriginalDestinationConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPOriginalDestinationCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPIdleTimeout
// [conn][%p] TP: Idle Timeout (%llu ms)
// QuicTraceLogConnVerbose(
                DecodeTPIdleTimeout,
                Connection,
                "TP: Idle Timeout (%llu ms)",
                TransportParams->IdleTimeout);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->IdleTimeout = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPIdleTimeout,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPStatelessResetToken
// [conn][%p] TP: Stateless Reset Token (%s)
// QuicTraceLogConnVerbose(
                DecodeTPStatelessResetToken,
                Connection,
                "TP: Stateless Reset Token (%s)",
                QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPStatelessResetToken,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxUdpPayloadSize
// [conn][%p] TP: Max Udp Payload Size (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPMaxUdpPayloadSize,
                Connection,
                "TP: Max Udp Payload Size (%llu bytes)",
                TransportParams->MaxUdpPayloadSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxUdpPayloadSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMaxUdpPayloadSize,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxData
// [conn][%p] TP: Max Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxData,
                Connection,
                "TP: Max Data (%llu bytes)",
                TransportParams->InitialMaxData);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxData = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxData,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiLocal
// [conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiLocal,
                Connection,
                "TP: Max Local Bidirectional Stream Data (%llu bytes)",
                TransportParams->InitialMaxStreamDataBidiLocal);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiLocal = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiLocal,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiRemote
// [conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiRemote,
                Connection,
                "TP: Max Remote Bidirectional Stream Data (%llu bytes)",
                TransportParams->InitialMaxStreamDataBidiRemote);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiRemote = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiRemote,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiUni
// [conn][%p] TP: Max Unidirectional Stream Data (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiUni,
                Connection,
                "TP: Max Unidirectional Stream Data (%llu)",
                TransportParams->InitialMaxStreamDataUni);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataUni = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiUni,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxBidiStreams
// [conn][%p] TP: Max Bidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPMaxBidiStreams,
                Connection,
                "TP: Max Bidirectional Streams (%llu)",
                TransportParams->InitialMaxBidiStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxBidiStreams = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMaxBidiStreams,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxUniStreams
// [conn][%p] TP: Max Unidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPMaxUniStreams,
                Connection,
                "TP: Max Unidirectional Streams (%llu)",
                TransportParams->InitialMaxUniStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxUniStreams = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMaxUniStreams,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPAckDelayExponent
// [conn][%p] TP: ACK Delay Exponent (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPAckDelayExponent,
                Connection,
                "TP: ACK Delay Exponent (%llu)",
                TransportParams->AckDelayExponent);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->AckDelayExponent = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPAckDelayExponent,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxAckDelay
// [conn][%p] TP: Max ACK Delay (%llu ms)
// QuicTraceLogConnVerbose(
                DecodeTPMaxAckDelay,
                Connection,
                "TP: Max ACK Delay (%llu ms)",
                TransportParams->MaxAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxAckDelay = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMaxAckDelay,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPDisableActiveMigration
// [conn][%p] TP: Disable Active Migration
// QuicTraceLogConnVerbose(
                DecodeTPDisableActiveMigration,
                Connection,
                "TP: Disable Active Migration");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPDisableActiveMigration,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPPreferredAddress
// [conn][%p] TP: Preferred Address
// QuicTraceLogConnVerbose(
                DecodeTPPreferredAddress,
                Connection,
                "TP: Preferred Address");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPPreferredAddress,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPCIDLimit
// [conn][%p] TP: Connection ID Limit (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPCIDLimit,
                Connection,
                "TP: Connection ID Limit (%llu)",
                TransportParams->ActiveConnectionIdLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->ActiveConnectionIdLimit = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPCIDLimit,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitialSourceCID
// [conn][%p] TP: Initial Source Connection ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPInitialSourceCID,
                Connection,
                "TP: Initial Source Connection ID (%s)",
                QuicCidBufToStr(
                    TransportParams->InitialSourceConnectionID,
                    TransportParams->InitialSourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->InitialSourceConnectionID,
                    TransportParams->InitialSourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPInitialSourceCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPRetrySourceCID
// [conn][%p] TP: Retry Source Connection ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPRetrySourceCID,
                Connection,
                "TP: Retry Source Connection ID (%s)",
                QuicCidBufToStr(
                    TransportParams->RetrySourceConnectionID,
                    TransportParams->RetrySourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->RetrySourceConnectionID,
                    TransportParams->RetrySourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPRetrySourceCID,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxDatagramFrameSize
// [conn][%p] TP: Max Datagram Frame Size (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPMaxDatagramFrameSize,
                Connection,
                "TP: Max Datagram Frame Size (%llu bytes)",
                TransportParams->MaxDatagramFrameSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxDatagramFrameSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMaxDatagramFrameSize,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPCibirEncoding
// [conn][%p] TP: CIBIR Encoding (%llu length, %llu offset)
// QuicTraceLogConnVerbose(
                DecodeTPCibirEncoding,
                Connection,
                "TP: CIBIR Encoding (%llu length, %llu offset)",
                TransportParams->CibirLength,
                TransportParams->CibirOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->CibirLength = arg3
// arg4 = arg4 = TransportParams->CibirOffset = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPCibirEncoding,
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
// Decoder Ring for DecodeTPDisable1RttEncryption
// [conn][%p] TP: Disable 1-RTT Encryption
// QuicTraceLogConnVerbose(
                DecodeTPDisable1RttEncryption,
                Connection,
                "TP: Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPDisable1RttEncryption,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPVersionNegotiationInfo
// [conn][%p] TP: Version Negotiation Info (%hu bytes)
// QuicTraceLogConnVerbose(
                    DecodeTPVersionNegotiationInfo,
                    Connection,
                    "TP: Version Negotiation Info (%hu bytes)",
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPVersionNegotiationInfo,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecodeTPMinAckDelay
// [conn][%p] TP: Min ACK Delay (%llu us)
// QuicTraceLogConnVerbose(
                DecodeTPMinAckDelay,
                Connection,
                "TP: Min ACK Delay (%llu us)",
                TransportParams->MinAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MinAckDelay = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, DecodeTPMinAckDelay,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Parse error. ReadTlsSni #1");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Parse error. ReadTlsSni #1" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "TP buffer",
            CxPlatTlsTPHeaderSize + RequiredTPLen);
// arg2 = arg2 = "TP buffer" = arg2
// arg3 = arg3 = CxPlatTlsTPHeaderSize + RequiredTPLen = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, AllocFailure,
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
                    Length,
                    "Invalid length of QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Length = arg3
// arg4 = arg4 = "Invalid length of QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CRYPTO_TLS_C, ConnErrorStatus,
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
