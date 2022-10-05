


/*----------------------------------------------------------
// Decoder Ring for VersionInfoDecodeFailed1
// [conn][%p] Version info too short to contain Chosen Version (%hu bytes)
// QuicTraceLogConnError(
            VersionInfoDecodeFailed1,
            Connection,
            "Version info too short to contain Chosen Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, VersionInfoDecodeFailed1,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for VersionInfoDecodeFailed2
// [conn][%p] Version info too short to contain any Other Versions (%hu bytes)
// QuicTraceLogConnError(
                VersionInfoDecodeFailed2,
                Connection,
                "Version info too short to contain any Other Versions (%hu bytes)",
                (unsigned)(BufferLength - Offset));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (unsigned)(BufferLength - Offset) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, VersionInfoDecodeFailed2,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoDecodeFailed3
// [conn][%p] Version info contains partial Other Version (%hu bytes vs. %u bytes)
// QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed3,
            Connection,
            "Version info contains partial Other Version (%hu bytes vs. %u bytes)",
            (unsigned)(BufferLength - Offset),
            (BufferLength - Offset) / (unsigned)sizeof(uint32_t));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (unsigned)(BufferLength - Offset) = arg3
// arg4 = arg4 = (BufferLength - Offset) / (unsigned)sizeof(uint32_t) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionInfoDecodeFailed3,
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
// Decoder Ring for ServerVersionInfoDecodeFailed4
// [conn][%p] Version info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed4,
            Connection,
            "Version info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Offset = arg3
// arg4 = arg4 = BufferLength = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionInfoDecodeFailed4,
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
// Decoder Ring for ServerVersionInfoDecoded
// [conn][%p] VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u
// QuicTraceLogConnInfo(
        ServerVersionInfoDecoded,
        Connection,
        "VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u",
        VersionInfo->ChosenVersion,
        VersionInfo->OtherVersionsCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = VersionInfo->ChosenVersion = arg3
// arg4 = arg4 = VersionInfo->OtherVersionsCount = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ServerVersionInfoDecoded,
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
// Decoder Ring for ServerVersionNegotiationInfoEncoded
// [conn][%p] Server VI Encoded: Chosen Ver:%x Other Ver Count:%u
// QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VI Encoded: Chosen Ver:%x Other Ver Count:%u",
            Connection->Stats.QuicVersion,
            OtherVersionsListLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
// arg4 = arg4 = OtherVersionsListLength = arg4
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
// Decoder Ring for ClientVersionInfoEncoded
// [conn][%p] Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u
// QuicTraceLogConnInfo(
            ClientVersionInfoEncoded,
            Connection,
            "Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
// arg4 = arg4 = Connection->PreviousQuicVersion = arg4
// arg5 = arg5 = CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ClientVersionInfoEncoded,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnVNEOtherVersionList
// [conn][%p] VerInfo Other Versions List: %!VNL!
// QuicTraceEvent(
        ConnVNEOtherVersionList,
        "[conn][%p] VerInfo Other Versions List: %!VNL!",
        Connection,
        CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_VERSION_NEG_C, ConnVNEOtherVersionList,
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
                "Server Version Info",
                VILen);
// arg2 = arg2 = "Server Version Info" = arg2
// arg3 = arg3 = VILen = arg3
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
