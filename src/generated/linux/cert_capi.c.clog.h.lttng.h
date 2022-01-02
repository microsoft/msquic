


/*----------------------------------------------------------
// Decoder Ring for CertCapiVerifiedChain
// CertVerifyChain: %S 0x%x, result=0x%x
// QuicTraceLogInfo(
        CertCapiVerifiedChain,
        "CertVerifyChain: %S 0x%x, result=0x%x",
        ServerName,
        CredFlags,
        Status);
// arg2 = arg2 = ServerName = arg2
// arg3 = arg3 = CredFlags = arg3
// arg4 = arg4 = Status = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, CertCapiVerifiedChain,
    TP_ARGS(
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCapiParsedChain
// [cert] Successfully parsed chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiParsedChain,
        "[cert] Successfully parsed chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, CertCapiParsedChain,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCapiFormattedChain
// [cert] Successfully formatted chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiFormattedChain,
        "[cert] Successfully formatted chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, CertCapiFormattedChain,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCapiSign
// [cert] QuicCertSign alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiSign,
        "[cert] QuicCertSign alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, CertCapiSign,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CertCapiVerify
// [cert] QuicCertVerify alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiVerify,
        "[cert] QuicCertVerify alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, CertCapiVerify,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "Get CERT_HASH_PROP_ID failed");
// arg2 = arg2 = GetLastError() = arg2
// arg3 = arg3 = "Get CERT_HASH_PROP_ID failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Not all cert bytes were processed");
// arg2 = arg2 = "Not all cert bytes were processed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS7 data",
            Blob.cbData);
// arg2 = arg2 = "PKCS7 data" = arg2
// arg3 = arg3 = Blob.cbData = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_CAPI_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
