


/*----------------------------------------------------------
// Decoder Ring for InvalidCongestionControlAlgorithm
// [conn][%p] Unknown congestion control algorithm: %hu, fallback to Cubic
// QuicTraceLogConnWarning(
            InvalidCongestionControlAlgorithm,
            QuicCongestionControlGetConnection(Cc),
            "Unknown congestion control algorithm: %hu, fallback to Cubic",
            Settings->CongestionControlAlgorithm);
// arg1 = arg1 = QuicCongestionControlGetConnection(Cc) = arg1
// arg3 = arg3 = Settings->CongestionControlAlgorithm = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONGESTION_CONTROL_C, InvalidCongestionControlAlgorithm,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)
