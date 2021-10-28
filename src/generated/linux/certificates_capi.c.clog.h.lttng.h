


/*----------------------------------------------------------
// Decoder Ring for TlsExportCapiCertChainVerifyResult
// Exported chain verification result: %u
// QuicTraceLogVerbose(
        TlsExportCapiCertChainVerifyResult,
        "Exported chain verification result: %u",
        PolicyStatus.dwError);
// arg2 = arg2 = PolicyStatus.dwError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERTIFICATES_CAPI_C, TlsExportCapiCertChainVerifyResult,
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
            "CertGetCertificateChain failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateChain failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERTIFICATES_CAPI_C, LibraryErrorStatus,
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
            "Requested certificate does not support exporting. An exportable certificate is required");
// arg2 = arg2 = "Requested certificate does not support exporting. An exportable certificate is required"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERTIFICATES_CAPI_C, LibraryError,
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
            "PFX data",
            PfxDataBlob.cbData);
// arg2 = arg2 = "PFX data"
// arg3 = arg3 = PfxDataBlob.cbData
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERTIFICATES_CAPI_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
