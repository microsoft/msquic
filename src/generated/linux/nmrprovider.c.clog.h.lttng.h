


/*----------------------------------------------------------
// Decoder Ring for ProviderAttachClient
// [ nmr][%p] Client attached Ver %hu Size %hu Number %u ModuleID { %x-%x-%x-%llx }
// QuicTraceLogInfo(
        ProviderAttachClient,
        "[ nmr][%p] Client attached Ver %hu Size %hu Number %u ModuleID { %x-%x-%x-%llx }",
        NmrBindingHandle,
        ClientRegistrationInstance->Version,
        ClientRegistrationInstance->Size,
        ClientRegistrationInstance->Number,
        ClientRegistrationInstance->ModuleId->Guid.Data1,
        ClientRegistrationInstance->ModuleId->Guid.Data2,
        ClientRegistrationInstance->ModuleId->Guid.Data3,
        *((uint64_t*)ClientRegistrationInstance->ModuleId->Guid.Data4));
// arg2 = arg2 = NmrBindingHandle = arg2
// arg3 = arg3 = ClientRegistrationInstance->Version = arg3
// arg4 = arg4 = ClientRegistrationInstance->Size = arg4
// arg5 = arg5 = ClientRegistrationInstance->Number = arg5
// arg6 = arg6 = ClientRegistrationInstance->ModuleId->Guid.Data1 = arg6
// arg7 = arg7 = ClientRegistrationInstance->ModuleId->Guid.Data2 = arg7
// arg8 = arg8 = ClientRegistrationInstance->ModuleId->Guid.Data3 = arg8
// arg9 = arg9 = *((uint64_t*)ClientRegistrationInstance->ModuleId->Guid.Data4) = arg9
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_NMRPROVIDER_C, ProviderAttachClient,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3,
        unsigned short, arg4,
        unsigned int, arg5,
        unsigned int, arg6,
        unsigned int, arg7,
        unsigned int, arg8,
        unsigned long long, arg9), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
        ctf_integer(unsigned int, arg7, arg7)
        ctf_integer(unsigned int, arg8, arg8)
        ctf_integer(uint64_t, arg9, arg9)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ProviderDetachClient
// [ nmr][%p] Client detached
// QuicTraceLogInfo(
        ProviderDetachClient,
        "[ nmr][%p] Client detached",
        ProviderBindingContext);
// arg2 = arg2 = ProviderBindingContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_NMRPROVIDER_C, ProviderDetachClient,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NmrRegisterProvider");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "NmrRegisterProvider" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_NMRPROVIDER_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
