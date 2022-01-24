


/*----------------------------------------------------------
// Decoder Ring for LookupCidFound
// [look][%p] Lookup Hash=%u found %p
// QuicTraceLogVerbose(
            LookupCidFound,
            "[look][%p] Lookup Hash=%u found %p",
            Lookup,
            Hash,
            Connection);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = Hash = arg3
// arg4 = arg4 = Connection = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupCidFound,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer_hex(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupCidNotFound
// [look][%p] Lookup Hash=%u not found
// QuicTraceLogVerbose(
            LookupCidNotFound,
            "[look][%p] Lookup Hash=%u not found",
            Lookup,
            Hash);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = Hash = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupCidNotFound,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashFound
// [look][%p] Lookup RemoteHash=%u found %p
// QuicTraceLogVerbose(
                LookupRemoteHashFound,
                "[look][%p] Lookup RemoteHash=%u found %p",
                Lookup,
                Hash,
                Entry->Connection);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = Hash = arg3
// arg4 = arg4 = Entry->Connection = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupRemoteHashFound,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer_hex(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashNotFound
// [look][%p] Lookup RemoteHash=%u not found
// QuicTraceLogVerbose(
        LookupRemoteHashNotFound,
        "[look][%p] Lookup RemoteHash=%u not found",
        Lookup,
        Hash);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = Hash = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupRemoteHashNotFound,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupCidInsert
// [look][%p] Insert Conn=%p Hash=%u
// QuicTraceLogVerbose(
        LookupCidInsert,
        "[look][%p] Insert Conn=%p Hash=%u",
        Lookup,
        SourceCid->Connection,
        Hash);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = SourceCid->Connection = arg3
// arg4 = arg4 = Hash = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupCidInsert,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupRemoteHashInsert
// [look][%p] Insert Conn=%p RemoteHash=%u
// QuicTraceLogVerbose(
        LookupRemoteHashInsert,
        "[look][%p] Insert Conn=%p RemoteHash=%u",
        Lookup,
        Connection,
        Hash);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = Connection = arg3
// arg4 = arg4 = Hash = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupRemoteHashInsert,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LookupCidRemoved
// [look][%p] Remove Conn=%p
// QuicTraceLogVerbose(
        LookupCidRemoved,
        "[look][%p] Remove Conn=%p",
        Lookup,
        SourceCid->Connection);
// arg2 = arg2 = Lookup = arg2
// arg3 = arg3 = SourceCid->Connection = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_LOOKUP_C, LookupCidRemoved,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)
