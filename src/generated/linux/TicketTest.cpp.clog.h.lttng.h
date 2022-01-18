


/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTpLengthShort
// [test] Attempting to decode Server TP with length %u (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Server TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = s = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTpLengthShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTpLengthEncodedWrong
// [test] Attempting to decode Server TP length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Server TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = InputTicketBuffer[5] = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTpLengthEncodedWrong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTicketLengthShort
// [test] Attempting to decode Server Ticket with length %u (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthShort,
            "[test] Attempting to decode Server Ticket with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(ServerTicket));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(ServerTicket) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTicketLengthShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTicketLengthEncodedWrong
// [test] Attempting to decode Server Ticket length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthEncodedWrong,
            "[test] Attempting to decode Server Ticket length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            (uint8_t)sizeof(ServerTicket));
// arg2 = arg2 = InputTicketBuffer[6] = arg2
// arg3 = arg3 = (uint8_t)sizeof(ServerTicket) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTicketLengthEncodedWrong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAlpnLengthShort
// [test] Attempting to decode Negotiated ALPN with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthShort,
            "[test] Attempting to decode Negotiated ALPN with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(Alpn));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(Alpn) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAlpnLengthShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong
// [test] Attempting to decode Negotiated ALPN length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong,
            "[test] Attempting to decode Negotiated ALPN length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            (uint8_t)sizeof(Alpn));
// arg2 = arg2 = InputTicketBuffer[5] = arg2
// arg3 = arg3 = (uint8_t)sizeof(Alpn) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailTpLengthShort
// [test] Attempting to decode Handshake TP with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Handshake TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = s = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailTpLengthShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailTpLengthEncodedWrong
// [test] Attempting to decode Handshake TP length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Handshake TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = InputTicketBuffer[6] = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailTpLengthEncodedWrong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAppDataLengthShort
// [test] Attempting to decode App Data with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthShort,
            "[test] Attempting to decode App Data with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(AppData));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(AppData) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAppDataLengthShort,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong
// [test] Attempting to decode App Data length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong,
            "[test] Attempting to decode App Data length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[7],
            (uint8_t)sizeof(AppData));
// arg2 = arg2 = InputTicketBuffer[7] = arg2
// arg3 = arg3 = (uint8_t)sizeof(AppData) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)
