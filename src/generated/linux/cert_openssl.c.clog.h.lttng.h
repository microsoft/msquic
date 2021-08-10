


/*----------------------------------------------------------
// Decoder Ring for CertOpenSslGetProcessAddressFailure
// [cert] GetProcAddress failed for %s, 0x%x
// QuicTraceLogVerbose(
        CertOpenSslGetProcessAddressFailure,
        "[cert] GetProcAddress failed for %s, 0x%x",
        FuncName,
        Error);
// arg2 = arg2 = FuncName
// arg3 = arg3 = Error
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_OPENSSL_C, CertOpenSslGetProcessAddressFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Failed to Load libmipki.dll");
// arg2 = arg2 = Status
// arg3 = arg3 = "Failed to Load libmipki.dll"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_OPENSSL_C, LibraryErrorStatus,
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
            "mipki_add_root_file_or_path failed");
// arg2 = arg2 = "mipki_add_root_file_or_path failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CERT_OPENSSL_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
