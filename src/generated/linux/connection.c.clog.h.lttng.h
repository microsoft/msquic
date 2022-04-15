


/*----------------------------------------------------------
// Decoder Ring for PacketRxStatelessReset
// [S][RX][-] SR %s
// QuicTraceLogVerbose(
                        PacketRxStatelessReset,
                        "[S][RX][-] SR %s",
                        QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PacketRxStatelessReset,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketRxNotAcked
// [%c][RX][%llu] not acked (connection is closed)
// QuicTraceLogVerbose(
            PacketRxNotAcked,
            "[%c][RX][%llu] not acked (connection is closed)",
            PtkConnPre(Connection),
            Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PacketRxNotAcked,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionInfoVersionMismatch
// [conn][%p] Client Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ClientVersionInfoVersionMismatch,
                Connection,
                "Client Chosen Version doesn't match long header. 0x%x != 0x%x",
                ClientVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ClientVI.ChosenVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ClientVersionInfoVersionMismatch,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoVersionMismatch
// [conn][%p] Server Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ServerVersionInfoVersionMismatch,
                Connection,
                "Server Chosen Version doesn't match long header. 0x%x != 0x%x",
                ServerVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ServerVI.ChosenVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ServerVersionInfoVersionMismatch,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientChosenVersionMismatchServerChosenVersion
// [conn][%p] Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x
// QuicTraceLogConnError(
                ClientChosenVersionMismatchServerChosenVersion,
                Connection,
                "Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x",
                ClientChosenVersion,
                ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ClientChosenVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ClientChosenVersionMismatchServerChosenVersion,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionIsChosenVersion
// [conn][%p] Previous Client Version is Server Chosen Version: 0x%x
// QuicTraceLogConnError(
                    ServerVersionInformationPreviousVersionIsChosenVersion,
                    Connection,
                    "Previous Client Version is Server Chosen Version: 0x%x",
                    Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PreviousQuicVersion = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionIsChosenVersion,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionInOtherVerList
// [conn][%p] Previous Client Version in Server Other Versions list: 0x%x
// QuicTraceLogConnError(
                            ServerVersionInformationPreviousVersionInOtherVerList,
                            Connection,
                            "Previous Client Version in Server Other Versions list: 0x%x",
                            Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PreviousQuicVersion = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionInOtherVerList,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationNotCompatible
// [conn][%p] Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationNotCompatible,
                    Connection,
                    "Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CompatibleVersionNegotiationNotCompatible,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationOriginalVersionNotFound
// [conn][%p] OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationOriginalVersionNotFound,
                    Connection,
                    "OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CompatibleVersionNegotiationOriginalVersionNotFound,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecvVerNegNoMatch
// [conn][%p] Version Negotation contained no supported versions
// QuicTraceLogConnError(
            RecvVerNegNoMatch,
            Connection,
            "Version Negotation contained no supported versions");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, RecvVerNegNoMatch,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecvVerNegCryptoError
// [conn][%p] Failed to update crypto on ver neg
// QuicTraceLogConnError(
            RecvVerNegCryptoError,
            Connection,
            "Failed to update crypto on ver neg");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, RecvVerNegCryptoError,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApiEventNoHandler
// [conn][%p] Event silently discarded (no handler).
// QuicTraceLogConnWarning(
            ApiEventNoHandler,
            Connection,
            "Event silently discarded (no handler).");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ApiEventNoHandler,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NoReplacementCidForRetire
// [conn][%p] Can't retire current CID because we don't have a replacement
// QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            Connection,
            "Can't retire current CID because we don't have a replacement");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, NoReplacementCidForRetire,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                Connection,
                "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, NonActivePathCidRetired,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreUnreachable
// [conn][%p] Ignoring received unreachable event (inline)
// QuicTraceLogConnWarning(
            IgnoreUnreachable,
            Connection,
            "Ignoring received unreachable event (inline)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IgnoreUnreachable,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreFrameAfterClose
// [conn][%p] Ignoring frame (%hhu) for already closed stream id = %llu
// QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)FrameType = arg3
// arg4 = arg4 = // This cast is safe because of the switch cases above.
                    StreamId = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IgnoreFrameAfterClose,
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
// Decoder Ring for InvalidInitialPackets
// [conn][%p] Aborting connection with invalid initial packets
// QuicTraceLogConnWarning(
            InvalidInitialPackets,
            Connection,
            "Aborting connection with invalid initial packets");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, InvalidInitialPackets,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UnreachableIgnore
// [conn][%p] Ignoring received unreachable event
// QuicTraceLogConnWarning(
            UnreachableIgnore,
            Connection,
            "Ignoring received unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UnreachableIgnore,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UnreachableInvalid
// [conn][%p] Received invalid unreachable event
// QuicTraceLogConnWarning(
            UnreachableInvalid,
            Connection,
            "Received invalid unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UnreachableInvalid,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CloseUserCanceled
// [conn][%p] Connection close using user canceled error
// QuicTraceLogConnInfo(
                CloseUserCanceled,
                Connection,
                "Connection close using user canceled error");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CloseUserCanceled,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CloseComplete
// [conn][%p] Connection close complete
// QuicTraceLogConnInfo(
            CloseComplete,
            Connection,
            "Connection close complete");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CloseComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Restart
// [conn][%p] Restart (CompleteReset=%hhu)
// QuicTraceLogConnInfo(
        Restart,
        Connection,
        "Restart (CompleteReset=%hhu)",
        CompleteReset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = CompleteReset = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, Restart,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CryptoStateDiscard
// [conn][%p] TLS state no longer needed
// QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CryptoStateDiscard,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SetConfiguration
// [conn][%p] Configuration set, %p
// QuicTraceLogConnInfo(
        SetConfiguration,
        Connection,
        "Configuration set, %p",
        Configuration);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Configuration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, SetConfiguration,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerTPSet
// [conn][%p] Peer Transport Parameters Set
// QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PeerTPSet,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerPreferredAddress
// [conn][%p] Peer configured preferred address %!ADDR!
// QuicTraceLogConnInfo(
                PeerPreferredAddress,
                Connection,
                "Peer configured preferred address %!ADDR!",
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PeerPreferredAddress,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NegotiatedDisable1RttEncryption
// [conn][%p] Negotiated Disable 1-RTT Encryption
// QuicTraceLogConnInfo(
                NegotiatedDisable1RttEncryption,
                Connection,
                "Negotiated Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, NegotiatedDisable1RttEncryption,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CustomCertValidationPending
// [conn][%p] Custom cert validation is pending
// QuicTraceLogConnInfo(
            CustomCertValidationPending,
            Connection,
            "Custom cert validation is pending");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CustomCertValidationPending,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecvStatelessReset
// [conn][%p] Received stateless reset
// QuicTraceLogConnInfo(
                        RecvStatelessReset,
                        Connection,
                        "Received stateless reset");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, RecvStatelessReset,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedFrame
// [conn][%p] Handshake confirmed (frame)
// QuicTraceLogConnInfo(
                    HandshakeConfirmedFrame,
                    Connection,
                    "Handshake confirmed (frame)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, HandshakeConfirmedFrame,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdatePacketTolerance
// [conn][%p] Updating packet tolerance to %hhu
// QuicTraceLogConnInfo(
                UpdatePacketTolerance,
                Connection,
                "Updating packet tolerance to %hhu",
                Connection->PacketTolerance);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PacketTolerance = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UpdatePacketTolerance,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FirstCidUsage
// [conn][%p] First usage of SrcCid: %s
// QuicTraceLogConnInfo(
                FirstCidUsage,
                Connection,
                "First usage of SrcCid: %s",
                QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, FirstCidUsage,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathDiscarded
// [conn][%p] Removing invalid path[%hhu]
// QuicTraceLogConnInfo(
                PathDiscarded,
                Connection,
                "Removing invalid path[%hhu]",
                Connection->Paths[i].ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[i].ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PathDiscarded,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Unreachable
// [conn][%p] Received unreachable event
// QuicTraceLogConnInfo(
            Unreachable,
            Connection,
            "Received unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, Unreachable,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailedRouteResolution
// [conn][%p] Route resolution failed on Path[%hhu]. Switching paths...
// QuicTraceLogConnInfo(
                    FailedRouteResolution,
                    Connection,
                    "Route resolution failed on Path[%hhu]. Switching paths...",
                    PathId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = PathId = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, FailedRouteResolution,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdatePeerPacketTolerance
// [conn][%p] Updating peer packet tolerance to %hhu
// QuicTraceLogConnInfo(
            UpdatePeerPacketTolerance,
            Connection,
            "Updating peer packet tolerance to %hhu",
            NewPacketTolerance);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = NewPacketTolerance = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UpdatePeerPacketTolerance,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdateShareBinding
// [conn][%p] Updated ShareBinding = %hhu
// QuicTraceLogConnInfo(
            UpdateShareBinding,
            Connection,
            "Updated ShareBinding = %hhu",
            Connection->State.ShareBinding);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->State.ShareBinding = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UpdateShareBinding,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdateStreamSchedulingScheme
// [conn][%p] Updated Stream Scheduling Scheme = %u
// QuicTraceLogConnInfo(
            UpdateStreamSchedulingScheme,
            Connection,
            "Updated Stream Scheduling Scheme = %u",
            (uint32_t)Scheme);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint32_t)Scheme = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UpdateStreamSchedulingScheme,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LocalInterfaceSet
// [conn][%p] Local interface set to %u
// QuicTraceLogConnInfo(
            LocalInterfaceSet,
            Connection,
            "Local interface set to %u",
            Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, LocalInterfaceSet,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CibirIdSet
// [conn][%p] CIBIR ID set (len %hhu, offset %hhu)
// QuicTraceLogConnInfo(
            CibirIdSet,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu)",
            Connection->CibirId[0],
            Connection->CibirId[1]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->CibirId[0] = arg3
// arg4 = arg4 = Connection->CibirId[1] = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CibirIdSet,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ApplySettings
// [conn][%p] Applying new settings
// QuicTraceLogConnInfo(
        ApplySettings,
        Connection,
        "Applying new settings");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ApplySettings,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RttUpdatedMsg
// [conn][%p] Updated Rtt=%u.%03u ms, Var=%u.%03u
// QuicTraceLogConnVerbose(
            RttUpdatedMsg,
            Connection,
            "Updated Rtt=%u.%03u ms, Var=%u.%03u",
            Path->SmoothedRtt / 1000, Path->SmoothedRtt % 1000,
            Path->RttVariance / 1000, Path->RttVariance % 1000);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->SmoothedRtt / 1000 = arg3
// arg4 = arg4 = Path->SmoothedRtt % 1000 = arg4
// arg5 = arg5 = Path->RttVariance / 1000 = arg5
// arg6 = arg6 = Path->RttVariance % 1000 = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, RttUpdatedMsg,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NewSrcCidNameCollision
// [conn][%p] CID collision, trying again
// QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                Connection,
                "CID collision, trying again");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, NewSrcCidNameCollision,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ZeroLengthCidRetire
// [conn][%p] Can't retire current CID because it's zero length
// QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            Connection,
            "Can't retire current CID because it's zero length");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ZeroLengthCidRetire,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByPeer
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]
// QuicTraceLogConnVerbose(
            IndicateShutdownByPeer,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]",
            Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicateShutdownByPeer,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByTransport
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]
// QuicTraceLogConnVerbose(
            IndicateShutdownByTransport,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]",
            Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicateShutdownByTransport,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateConnectionShutdownComplete
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
// QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicateConnectionShutdownComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateResumed
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMED
// QuicTraceLogConnVerbose(
            IndicateResumed,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_RESUMED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicateResumed,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateResumptionTicketReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
// QuicTraceLogConnVerbose(
                IndicateResumptionTicketReceived,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicateResumptionTicketReceived,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationCompatibleVersionUpgrade
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                        ClientVersionNegotiationCompatibleVersionUpgrade,
                        Connection,
                        "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                        Connection->Stats.QuicVersion,
                        SupportedVersions[ServerVersionIdx]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
// arg4 = arg4 = SupportedVersions[ServerVersionIdx] = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ClientVersionNegotiationCompatibleVersionUpgrade,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionUpgradeComplete
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                CompatibleVersionUpgradeComplete,
                Connection,
                "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                Connection->OriginalQuicVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, CompatibleVersionUpgradeComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerCertificateReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)
// QuicTraceLogConnVerbose(
        IndicatePeerCertificateReceived,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)",
        DeferredErrorFlags,
        DeferredStatus);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DeferredErrorFlags = arg3
// arg4 = arg4 = DeferredStatus = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicatePeerCertificateReceived,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueueDatagrams
// [conn][%p] Queuing %u UDP datagrams
// QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        DatagramChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, QueueDatagrams,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecvVerNeg
// [conn][%p] Received Version Negotation:
// QuicTraceLogConnVerbose(
        RecvVerNeg,
        Connection,
        "Received Version Negotation:");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, RecvVerNeg,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for VerNegItem
// [conn][%p]   Ver[%d]: 0x%x
// QuicTraceLogConnVerbose(
            VerNegItem,
            Connection,
            "  Ver[%d]: 0x%x",
            (int32_t)i,
            CxPlatByteSwapUint32(ServerVersion));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (int32_t)i = arg3
// arg4 = arg4 = CxPlatByteSwapUint32(ServerVersion) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, VerNegItem,
    TP_ARGS(
        const void *, arg1,
        int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DeferDatagram
// [conn][%p] Deferring datagram (type=%hu)
// QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    (uint16_t)Packet->KeyType);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Packet->KeyType = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, DeferDatagram,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DecryptOldKey
// [conn][%p] Using old key to decrypt
// QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, DecryptOldKey,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PossiblePeerKeyUpdate
// [conn][%p] Possible peer initiated key update [packet %llu]
// QuicTraceLogConnVerbose(
                PossiblePeerKeyUpdate,
                Connection,
                "Possible peer initiated key update [packet %llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PossiblePeerKeyUpdate,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdateReadKeyPhase
// [conn][%p] Updating current read key phase and packet number[%llu]
// QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UpdateReadKeyPhase,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerConnFCBlocked
// [conn][%p] Peer Connection FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.DataLimit = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PeerConnFCBlocked,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerStreamFCBlocked
// [conn][%p] Peer Streams[%hu] FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams = arg3
// arg4 = arg4 = Frame.StreamLimit = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PeerStreamFCBlocked,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerNeedStreams
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
// QuicTraceLogConnVerbose(
                IndicatePeerNeedStreams,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicatePeerNeedStreams,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerAddrChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
// QuicTraceLogConnVerbose(
            IndicatePeerAddrChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, IndicatePeerAddrChanged,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UdpRecvBatch
// [conn][%p] Batch Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = BatchCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UdpRecvBatch,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UdpRecvDeferred
// [conn][%p] Recv %u deferred UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UdpRecvDeferred,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UdpRecv
// [conn][%p] Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecv,
            Connection,
            "Recv %u UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, UdpRecv,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatagramReceiveEnableUpdated
// [conn][%p] Updated datagram receive enabled to %hhu
// QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Settings.DatagramReceiveEnabled);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Settings.DatagramReceiveEnabled = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, DatagramReceiveEnableUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Disable1RttEncrytionUpdated
// [conn][%p] Updated disable 1-RTT encrytption to %hhu
// QuicTraceLogConnVerbose(
            Disable1RttEncrytionUpdated,
            Connection,
            "Updated disable 1-RTT encrytption to %hhu",
            Connection->State.Disable1RttEncrytion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->State.Disable1RttEncrytion = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, Disable1RttEncrytionUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ForceKeyUpdate
// [conn][%p] Forcing key update
// QuicTraceLogConnVerbose(
            ForceKeyUpdate,
            Connection,
            "Forcing key update");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ForceKeyUpdate,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ForceCidUpdate
// [conn][%p] Forcing destination CID update
// QuicTraceLogConnVerbose(
            ForceCidUpdate,
            Connection,
            "Forcing destination CID update");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ForceCidUpdate,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestTPSet
// [conn][%p] Setting Test Transport Parameter (type %hu, %hu bytes)
// QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %hu, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->TestTransportParameter.Type = arg3
// arg4 = arg4 = Connection->TestTransportParameter.Length = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, TestTPSet,
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
// Decoder Ring for AbandonInternallyClosed
// [conn][%p] Abandoning internal, closed connection
// QuicTraceLogConnVerbose(
            AbandonInternallyClosed,
            Connection,
            "Abandoning internal, closed connection");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, AbandonInternallyClosed,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
// arg2 = arg2 = "connection" = arg2
// arg3 = arg3 = sizeof(QUIC_CONNECTION) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnCreated
// [conn][%p] Created, IsServer=%hhu, CorrelationId=%llu
// QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = IsServer = arg3
// arg4 = arg4 = Connection->Stats.CorrelationId = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnCreated,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnLocalAddrAdded,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnRemoteAddrAdded,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->DestCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnDestCidAdded,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
            Connection,
            SourceCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = SourceCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnSourceCidAdded,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnInitializeComplete
// [conn][%p] Initialize complete
// QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnInitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnUnregistered
// [conn][%p] Unregistered from %p
// QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Registration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnUnregistered,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDestroyed
// [conn][%p] Destroyed
// QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHandleClosed
// [conn][%p] Handle closed
// QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnHandleClosed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRegistered
// [conn][%p] Registered with %p
// QuicTraceEvent(
            ConnRegistered,
            "[conn][%p] Registered with %p",
            Connection,
            Registration);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Registration = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnRegistered,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRundown
// [conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu
// QuicTraceEvent(
        ConnRundown,
        "[conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu",
        Connection,
        QuicConnIsServer(Connection),
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = QuicConnIsServer(Connection) = arg3
// arg4 = arg4 = Connection->Stats.CorrelationId = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnRundown,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnAssignWorker
// [conn][%p] Assigned worker: %p
// QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Connection->Worker);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Worker = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnAssignWorker,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnVersionSet
// [conn][%p] QUIC Version: %u
// QuicTraceEvent(
            ConnVersionSet,
            "[conn][%p] QUIC Version: %u",
            Connection,
            Connection->Stats.QuicVersion);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnVersionSet,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnHandshakeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Too many CID collisions");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Too many CID collisions" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
        Connection,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = DestCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnDestCidRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnSetTimer
// [conn][%p] Setting %hhu, delay=%llu us
// QuicTraceEvent(
        ConnSetTimer,
        "[conn][%p] Setting %hhu, delay=%llu us",
        Connection,
        (uint8_t)Type,
        Delay);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Type = arg3
// arg4 = arg4 = Delay = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnSetTimer,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnCancelTimer
// [conn][%p] Canceling %hhu
// QuicTraceEvent(
                ConnCancelTimer,
                "[conn][%p] Canceling %hhu",
                Connection,
                (uint8_t)Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Type = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnCancelTimer,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnExpiredTimer
// [conn][%p] %hhu expired
// QuicTraceEvent(
            ConnExpiredTimer,
            "[conn][%p] %hhu expired",
            Connection,
            (uint8_t)Temp[j].Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Temp[j].Type = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnExpiredTimer,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_ACK_DELAY);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = QUIC_CONN_TIMER_ACK_DELAY = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnExecTimerOper,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnShutdownComplete
// [conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.
// QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->State.ShutdownCompleteTimedOut = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnShutdownComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnAppShutdown
// [conn][%p] App Shutdown: %llu (Remote=%hhu)
// QuicTraceEvent(
                ConnAppShutdown,
                "[conn][%p] App Shutdown: %llu (Remote=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = ErrorCode = arg3
// arg4 = arg4 = ClosedRemotely = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnAppShutdown,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnTransportShutdown
// [conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)
// QuicTraceEvent(
                ConnTransportShutdown,
                "[conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely,
                !!(Flags & QUIC_CLOSE_QUIC_STATUS));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = ErrorCode = arg3
// arg4 = arg4 = ClosedRemotely = arg4
// arg5 = arg5 = !!(Flags & QUIC_CLOSE_QUIC_STATUS) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnTransportShutdown,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection, Status,
                    "Set current compartment Id");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Set current compartment Id" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnServerResumeTicket
// [conn][%p] Server app accepted resumption ticket
// QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnServerResumeTicket,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeStart
// [conn][%p] Handshake start
// QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnHandshakeStart,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketDecrypt
// [pack][%llu] Decrypting
// QuicTraceEvent(
        PacketDecrypt,
        "[pack][%llu] Decrypting",
        Packet->PacketId);
// arg2 = arg2 = Packet->PacketId = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, PacketDecrypt,
    TP_ARGS(
        unsigned long long, arg2), 
    TP_FIELDS(
        ctf_integer(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPacketRecv
// [conn][%p][RX][%llu] %c (%hu bytes)
// QuicTraceEvent(
        ConnPacketRecv,
        "[conn][%p][RX][%llu] %c (%hu bytes)",
        Connection,
        Packet->PacketNumber,
        Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1),
        Packet->HeaderLength + Packet->PayloadLength);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1) = arg4
// arg5 = arg5 = Packet->HeaderLength + Packet->PayloadLength = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnPacketRecv,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrRemoved
// [conn][%p] Removed Local IP: %!ADDR!
// QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_C, ConnLocalAddrRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)
