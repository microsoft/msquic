


/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownComplete
// [data][%p] Shut down (complete)
// QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, DatapathShutDownComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedFileFailed
// [ ndspi] CreateOverlappedFile failed, status: %d
// QuicTraceLogError(
            CreateOverlappedFileFailed,
            "[ ndspi] CreateOverlappedFile failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedFileFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateMemoryRegionFailed
// [ ndspi] CreateMemoryRegion failed, status: %d
// QuicTraceLogError(
            CreateMemoryRegionFailed,
            "[ ndspi] CreateMemoryRegion failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateMemoryRegionFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RegisterMemoryFailed
// [ ndspi] RegisterMemory failed, status: %d
// QuicTraceLogError(
            RegisterMemoryFailed,
            "[ ndspi] RegisterMemory failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, RegisterMemoryFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DeRegisterMemoryFailed
// [ ndspi] DeRegisterMemory failed, status: %d
// QuicTraceLogError(
            DeRegisterMemoryFailed,
            "[ ndspi] DeRegisterMemory failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, DeRegisterMemoryFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateMemoryWindowFailed
// [ ndspi] CreateMemoryWindow failed, status: %d
// QuicTraceLogError(
            CreateMemoryWindowFailed,
            "[ ndspi] CreateMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateCompletionQueueFailed
// [ ndspi] CreateCompletionQueueFailed failed, status: %d
// QuicTraceLogError(
            CreateCompletionQueueFailed,
            "[ ndspi] CreateCompletionQueueFailed failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateCompletionQueueFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateConnectorFailed
// [ ndspi] CreateConnector failed, status: %d
// QuicTraceLogError(
            CreateConnectorFailed,
            "[ ndspi] CreateConnector failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateConnectorFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateListenerFailed
// [ ndspi] CreateListener failed, status: %d
// QuicTraceLogError(
            CreateListenerFailed,
            "[ ndspi] CreateListener failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateListenerFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StartListenerFailed
// [ ndspi] StartListener failed, status: %d
// QuicTraceLogError(
            StartListenerFailed,
            "[ ndspi] StartListener failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, StartListenerFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateQueuePairFailed
// [ ndspi] CreateQueuePair failed, status: %d
// QuicTraceLogError(
            CreateQueuePairFailed,
            "[ ndspi] CreateQueuePair failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateQueuePairFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AcceptFailed
// [ ndspi] Accept failed, status: %d
// QuicTraceLogError(
            AcceptFailed,
            "[ ndspi] Accept failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, AcceptFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnectorBindFailed
// [ ndspi]  Connector Bind failed, status: %d
// QuicTraceLogError(
            ConnectorBindFailed,
            "[ ndspi]  Connector Bind failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, ConnectorBindFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ListenerBindFailed
// [ ndspi]  Listener Bind failed, status: %d
// QuicTraceLogError(
            ListenerBindFailed,
            "[ ndspi]  Listener Bind failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, ListenerBindFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnectFailed
// [ ndspi] Connect failed, status: %d
// QuicTraceLogError(
            ConnectFailed,
            "[ ndspi] Connect failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, ConnectFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CompleteConnectFailed
// [ ndspi] CompleteConnect failed, status: %d
// QuicTraceLogError(
            CompleteConnectFailed,
            "[ ndspi] CompleteConnect failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CompleteConnectFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindMemoryWindowFailed
// [ ndspi] BindMemoryWindow failed, status: %d
// QuicTraceLogError(
            BindMemoryWindowFailed,
            "[ ndspi] BindMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, BindMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for InvalidateMemoryWindowFailed
// [ ndspi] InvalidateMemoryWindow failed, status: %d
// QuicTraceLogError(
            InvalidateMemoryWindowFailed,
            "[ ndspi] InvalidateMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, InvalidateMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiWriteFailed
// [ ndspi] NdspiWrite failed, status: %d
// QuicTraceLogError(
            NdspiWriteFailed,
            "[ ndspi] NdspiWrite failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiWriteFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiWriteWithImmediateFailed
// [ ndspi] NdspiWriteWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiWriteWithImmediateFailed,
            "[ ndspi] NdspiWriteWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiWriteWithImmediateFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiReadFailed
// [ ndspi] NdspiRead failed, status: %d
// QuicTraceLogError(
            NdspiReadFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiReadFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiSendFailed
// [ ndspi] NdspiRead failed, status: %d
// QuicTraceLogError(
            NdspiSendFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiSendFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiSendWithImmediateFailed
// [ ndspi] NdspiSendWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiSendWithImmediateFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiSendWithImmediateFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdspiPostReceiveFailed
// [ ndspi] NdspiSendWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiPostReceiveFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdspiPostReceiveFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NdOpenAdapterFailed
// NdOpenAdapter failed, status: %d
// QuicTraceLogError(
            NdOpenAdapterFailed,
            "NdOpenAdapter failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, NdOpenAdapterFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedFile
// CreateAdapterOverlappedFile failed, status: %d
// QuicTraceLogError(
            CreateOverlappedFile,
            "CreateAdapterOverlappedFile failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedFile,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueryAdapterInfoFailed
// QueryAdapterInfo failed, status: %d
// QuicTraceLogError(
            QueryAdapterInfoFailed,
            "QueryAdapterInfo failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, QueryAdapterInfoFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateRdmaSocketFailed
// CreateRdmaSocket failed, invalid address family
// QuicTraceLogError(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid address family");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateRdmaSocketFailed,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedConnFileFailed
// CreateOverConnlappedFile failed, status:%d
// QuicTraceLogError(
            CreateOverlappedConnFileFailed,
            "CreateOverConnlappedFile failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedConnFileFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RegisterSendBufferFailed
// RegisterSendBuffer failed, status:%d
// QuicTraceLogError(
            RegisterSendBufferFailed,
            "RegisterSendBuffer failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, RegisterSendBufferFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendRingBufferInitFailed
// SendRingBufferInit failed, status: %d
// QuicTraceLogError(
            SendRingBufferInitFailed,
            "SendRingBufferInit failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, SendRingBufferInitFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecvRingBufferInitFailed
// RecvRingBufferInit failed, status:%d
// QuicTraceLogError(
            RecvRingBufferInitFailed,
            "RecvRingBufferInit failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, RecvRingBufferInitFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateSharedCompletionQueueFailed
// Create CompletionQueue failed, status:%d
// QuicTraceLogError(
            CreateSharedCompletionQueueFailed,
            "Create CompletionQueue failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateSharedCompletionQueueFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateRecvMemoryWindowFailed
// Create RecvMemoryWindow failed, status:%d
// QuicTraceLogError(
                CreateRecvMemoryWindowFailed,
                "Create RecvMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateRecvMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateSendMemoryWindowFailed
// Create SendMemoryWindow failed, status:%d
// QuicTraceLogError(
                    CreateSendMemoryWindowFailed,
                    "Create SendMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateSendMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedListenerFileFailed
// CreateOverlappedListenerFile failed, status:%d
// QuicTraceLogError(
            CreateOverlappedListenerFileFailed,
            "CreateOverlappedListenerFile failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedListenerFileFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ExchangeTokensFailed
// RdmaSocketPendingSend failed, invalid parameters
// QuicTraceLogError(
            ExchangeTokensFailed,
            "RdmaSocketPendingSend failed, invalid parameters");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, ExchangeTokensFailed,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for StartAcceptFailed
// StartAccept failed, invalid parameters
// QuicTraceLogError(
            StartAcceptFailed,
            "StartAccept failed, invalid parameters");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, StartAcceptFailed,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for GetConnectionRequestFailed
// GetConnectionRequest failed, status:%d
// QuicTraceLogError(
                GetConnectionRequestFailed,
                "GetConnectionRequest failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, GetConnectionRequestFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for BindRecvMemoryWindowFailed
// BindRecvMemoryWindow failed, status:%d
// QuicTraceLogError(
            BindRecvMemoryWindowFailed,
            "BindRecvMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, BindRecvMemoryWindowFailed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RDMA_NDSPI_ADAPTER",
            sizeof(RDMA_NDSPI_ADAPTER));
// arg2 = arg2 = "RDMA_NDSPI_ADAPTER" = arg2
// arg3 = arg3 = sizeof(RDMA_NDSPI_ADAPTER) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, DatapathCreated,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = LastError = arg3
// arg4 = arg4 = "SetFileCompletionNotificationModes" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, DatapathErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->Buffer.Length = arg3
// arg4 = arg4 = 1 = arg4
// arg5 = arg5 = (uint16_t)SendData->Buffer.Length = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINRDMA_C, DatapathSend,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned char, arg4,
        unsigned short, arg5,
        unsigned int, arg6_len,
        const void *, arg6,
        unsigned int, arg7_len,
        const void *, arg7), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
        ctf_integer(unsigned int, arg6_len, arg6_len)
        ctf_sequence(char, arg6, arg6, unsigned int, arg6_len)
        ctf_integer(unsigned int, arg7_len, arg7_len)
        ctf_sequence(char, arg7, arg7, unsigned int, arg7_len)
    )
)
