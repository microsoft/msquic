


/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed1
// [conn][%p] Client version negotiation info too short to contain Current Version (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Client version negotiation info too short to contain Current Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed1,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed2
// [conn][%p] Client version negotiation info too short to contain Previous Version (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Client version negotiation info too short to contain Previous Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed2,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed3
// [conn][%p] Client version negotiation info too short to contain Recv Negotiation Version count (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed3,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed4
// [conn][%p] Client version negotiation info too short to contain Recv Negotiation Version list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed4,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed5
// [conn][%p] Client version negotiation info too short to contain Compatible Version count (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Client version negotiation info too short to contain Compatible Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed5,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed6
// [conn][%p] Client version negotiation info too short to contain Compatible Version list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed6,
            Connection,
            "Client version negotiation info too short to contain Compatible Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->CompatibleVersionCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ClientVNI->CompatibleVersionCount * sizeof(uint32_t)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed6,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed7
// [conn][%p] Client version negotiation info has empty Compatible Version list
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed7,
            Connection,
            "Client version negotiation info has empty Compatible Version list");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed7,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed8
// [conn][%p] Client version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed8,
            Connection,
            "Client version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Offset
// arg4 = arg4 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed8,
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
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed1
// [conn][%p] Server version negotiation info too short to contain Negotiated Version (%hu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Server version negotiation info too short to contain Negotiated Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed1,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed2
// [conn][%p] Server version negotiation info too short to contain Supported Version count (%hu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Server version negotiation info too short to contain Supported Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed2,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed3
// [conn][%p] Server version negotiation info too short to contain Supported Versions list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Server version negotiation info too short to contain Supported Versions list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ServerVNI->SupportedVersionCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ServerVNI->SupportedVersionCount * sizeof(uint32_t)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed3,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed4
// [conn][%p] Server version negotiation info has empty Supported Versions list
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Server version negotiation info has empty Supported Versions list");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed4,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed5
// [conn][%p] Server version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Server version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Offset
// arg4 = arg4 = BufferLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed5,
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
// Decoder Ring for ClientVersionNegotiationInfoDecoded
// [conn][%p] Client VNI Decoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%llu Compat Ver Count:%llu
// QuicTraceLogConnInfo(
        ClientVersionNegotiationInfoDecoded,
        Connection,
        "Client VNI Decoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%llu Compat Ver Count:%llu",
        ClientVNI->CurrentVersion,
        ClientVNI->PreviousVersion,
        ClientVNI->RecvNegotiationVerCount,
        ClientVNI->CompatibleVersionCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = ClientVNI->CurrentVersion
// arg4 = arg4 = ClientVNI->PreviousVersion
// arg5 = arg5 = ClientVNI->RecvNegotiationVerCount
// arg6 = arg6 = ClientVNI->CompatibleVersionCount
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecoded,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecoded
// [conn][%p] Server VNI Decoded: Negotiated Ver:%x Supported Ver Count:%llu
// QuicTraceLogConnInfo(
        ServerVersionNegotiationInfoDecoded,
        Connection,
        "Server VNI Decoded: Negotiated Ver:%x Supported Ver Count:%llu",
        ServerVNI->NegotiatedVersion,
        ServerVNI->SupportedVersionCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = ServerVNI->NegotiatedVersion
// arg4 = arg4 = ServerVNI->SupportedVersionCount
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecoded,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoEncoded
// [conn][%p] Server VNI Encoded: Negotiated Ver:%x Supported Ver Count:%u
// QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VNI Encoded: Negotiated Ver:%x Supported Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = DesiredVersionsListLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoEncoded,
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
// Decoder Ring for ClientVersionNegotiationInfoEncoded
// [conn][%p] Client VNI Encoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%u Compat Ver Count:%u
// QuicTraceLogConnInfo(
            ClientVersionNegotiationInfoEncoded,
            Connection,
            "Client VNI Encoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%u Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            Connection->ReceivedNegotiationVersionsLength,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = Connection->PreviousQuicVersion
// arg5 = arg5 = Connection->ReceivedNegotiationVersionsLength
// arg6 = arg6 = CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t))
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoEncoded,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnClientCompatibleVersionList
// [conn][%p] Client VNI Compatible Version List: %!VNL!
// QuicTraceEvent(
        ConnClientCompatibleVersionList,
        "[conn][%p] Client VNI Compatible Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->CompatibleVersionCount * sizeof(uint32_t), ClientVNI->CompatibleVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ClientVNI->CompatibleVersionCount * sizeof(uint32_t), ClientVNI->CompatibleVersions)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ConnClientCompatibleVersionList,
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
// Decoder Ring for ConnClientReceivedVersionList
// [conn][%p] Client VNI Received Version List: %!VNL!
// QuicTraceEvent(
        ConnClientReceivedVersionList,
        "[conn][%p] Client VNI Received Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t), ClientVNI->RecvNegotiationVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t), ClientVNI->RecvNegotiationVersions)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ConnClientReceivedVersionList,
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
// Decoder Ring for ConnServerSupportedVersionList
// [conn][%p] Server VNI Supported Version List: %!VNL!
// QuicTraceEvent(
        ConnServerSupportedVersionList,
        "[conn][%p] Server VNI Supported Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ServerVNI->SupportedVersionCount * sizeof(uint32_t), ServerVNI->SupportedVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ServerVNI->SupportedVersionCount * sizeof(uint32_t), ServerVNI->SupportedVersions)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ConnServerSupportedVersionList,
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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server Version Negotiation Info",
                VNILen);
// arg2 = arg2 = "Server Version Negotiation Info"
// arg3 = arg3 = VNILen
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
