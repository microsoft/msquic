


/*----------------------------------------------------------
// Decoder Ring for NotAccepted
// [strm][%p] New stream wasn't accepted, 0x%x
// QuicTraceLogStreamWarning(
                    NotAccepted,
                    Stream,
                    "New stream wasn't accepted, 0x%x",
                    Status);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, NotAccepted,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerAccepted
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_ACCEPTED
// QuicTraceLogStreamVerbose(
            IndicatePeerAccepted,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_ACCEPTED");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, IndicatePeerAccepted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for MaxStreamCountUpdated
// [conn][%p] App configured max stream count of %hu (type=%hhu).
// QuicTraceLogConnInfo(
        MaxStreamCountUpdated,
        Connection,
        "App configured max stream count of %hu (type=%hhu).",
        Count,
        Type);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Count = arg3
// arg4 = arg4 = Type = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, MaxStreamCountUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateStreamsAvailable
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE [bi=%hu uni=%hu]
// QuicTraceLogConnVerbose(
        IndicateStreamsAvailable,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE [bi=%hu uni=%hu]",
        Event.STREAMS_AVAILABLE.BidirectionalCount,
        Event.STREAMS_AVAILABLE.UnidirectionalCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.STREAMS_AVAILABLE.BidirectionalCount = arg3
// arg4 = arg4 = Event.STREAMS_AVAILABLE.UnidirectionalCount = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, IndicateStreamsAvailable,
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
// Decoder Ring for PeerStreamCountsUpdated
// [conn][%p] Peer updated max stream count (%hhu, %llu).
// QuicTraceLogConnVerbose(
            PeerStreamCountsUpdated,
            Connection,
            "Peer updated max stream count (%hhu, %llu).",
            BidirectionalStreams,
            MaxStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = BidirectionalStreams = arg3
// arg4 = arg4 = MaxStreams = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, PeerStreamCountsUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerStreamStarted
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED [%p, 0x%x]
// QuicTraceLogConnVerbose(
                IndicatePeerStreamStarted,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED [%p, 0x%x]",
                Event.PEER_STREAM_STARTED.Stream,
                Event.PEER_STREAM_STARTED.Flags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.PEER_STREAM_STARTED.Stream = arg3
// arg4 = arg4 = Event.PEER_STREAM_STARTED.Flags = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, IndicatePeerStreamStarted,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "streamset hash table",
                0);
// arg2 = arg2 = "streamset hash table" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
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
            "Peer used more streams than allowed");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Peer used more streams than allowed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SET_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
