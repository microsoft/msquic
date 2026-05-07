


/*----------------------------------------------------------
// Decoder Ring for CertFindCertificateFriendlyName
// [test] No certificate found by FriendlyName
// QuicTraceLogWarning(
            CertFindCertificateFriendlyName,
            "[test] No certificate found by FriendlyName");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertFindCertificateFriendlyName,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertWaitForCreationEvent
// [test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)
// QuicTraceLogWarning(
                CertWaitForCreationEvent,
                "[test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)",
                WaitResult,
                GetLastError());
// arg2 = arg2 = WaitResult = arg2
// arg3 = arg3 = GetLastError() = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertWaitForCreationEvent,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCleanTestCerts
// [cert] %d test certificates found, and %d deleted
// QuicTraceLogInfo(
        CertCleanTestCerts,
        "[cert] %d test certificates found, and %d deleted",
        Found,
        Deleted);
// arg2 = arg2 = Found = arg2
// arg3 = arg3 = Deleted = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertCleanTestCerts,
    TP_ARGS(
        int, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertOpenRsaKeySuccess
// [cert] Successfully opened RSA key
// QuicTraceLogInfo(
            CertOpenRsaKeySuccess,
            "[cert] Successfully opened RSA key");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertOpenRsaKeySuccess,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCreateRsaKeySuccess
// [cert] Successfully created key
// QuicTraceLogInfo(
        CertCreateRsaKeySuccess,
        "[cert] Successfully created key");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertCreateRsaKeySuccess,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCreationEventAlreadyCreated
// [test] CreateEvent opened existing event
// QuicTraceLogInfo(
            CertCreationEventAlreadyCreated,
            "[test] CreateEvent opened existing event");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, CertCreationEventAlreadyCreated,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
// arg2 = arg2 = GetLastError() = arg2
// arg3 = arg3 = "CertOpenStore failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CryptDataBlob",
            CryptDataBlob->cbData);
// arg2 = arg2 = "CryptDataBlob" = arg2
// arg3 = arg3 = CryptDataBlob->cbData = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CreateEvent failed");
// arg2 = arg2 = "CreateEvent failed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SELFSIGN_CAPI_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
