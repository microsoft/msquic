// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::QUIC_CONNECTION_EVENT;
use std::ffi::c_void;

/// Connection callback events.
/// TODO: derive Debug once all enums are safe.
pub enum ConnectionEvent<'a> {
    Connected {
        session_resumed: bool,
        negotiated_alpn: &'a [u8],
    },
    // The transport started the shutdown process.
    ShutdownInitiatedByTransport {
        status: crate::Status,
        error_code: crate::u62,
    },
    // The peer application started the shutdown process.
    ShutdownInitiatedByPeer {
        error_code: crate::u62,
    },
    // Ready for the handle to be closed.
    ShutdownComplete {
        handshake_completed: bool,
        peer_acknowledged_shutdown: bool,
        app_close_in_progress: bool,
    },
    LocalAddressChanged {
        address: &'a crate::Addr,
    },
    PeerAddressChanged {
        address: &'a crate::Addr,
    },
    PeerStreamStarted {
        stream: crate::StreamRef,
        // TODO: provide safe wrapper.
        flags: crate::ffi::QUIC_STREAM_OPEN_FLAGS,
    },
    StreamsAvailable {
        bidirectional_count: u16,
        unidirectional_count: u16,
    },
    PeerNeedsStreams {
        bidirectional: bool,
    },
    IdealProcessorChanged {
        ideal_processor: u16,
        partition_index: u16,
    },
    DatagramStateChanged {
        send_enabled: bool,
        max_send_length: u16,
    },
    // TODO: buffer needs to be safely converted.
    DatagramReceived {
        buffer: &'a crate::ffi::QUIC_BUFFER,
        // TODO: provide safe wrapper.
        flags: crate::ffi::QUIC_RECEIVE_FLAGS,
    },
    DatagramSendStateChanged {
        client_context: *const c_void,
        // TODO: provide safe wrapper.
        state: crate::ffi::QUIC_DATAGRAM_SEND_STATE,
    },
    // Server-only; provides resumption data, if any.
    Resumed {
        resumption_state: &'a [u8],
    },
    // Client-only; provides ticket to persist, if any.
    ResumptionTicketReceived {
        resumption_ticket: &'a [u8],
    },
    // Only with QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED set
    PeerCertificateReceived {
        certificate: *mut crate::ffi::QUIC_CERTIFICATE,
        deferred_error_flags: u32,
        deferred_status: crate::Status,
        chain: *mut crate::ffi::QUIC_CERTIFICATE_CHAIN,
    },
    // TODO: preview features
    // ReliableResetNegotiated, // Only indicated if QUIC_SETTINGS.ReliableResetEnabled is TRUE.
    // OneWayDelayNegotiated,   // Only indicated if QUIC_SETTINGS.OneWayDelayEnabled is TRUE.
    // NetworkStatistics,       // Only indicated if QUIC_SETTINGS.EnableNetStatsEvent is TRUE.
}

impl<'a> From<&'a QUIC_CONNECTION_EVENT> for ConnectionEvent<'a> {
    fn from(value: &QUIC_CONNECTION_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_CONNECTED => {
                let ev = unsafe { value.__bindgen_anon_1.CONNECTED };
                let alpn = if ev.NegotiatedAlpnLength > 0{
                  unsafe { std::slice::from_raw_parts(ev.NegotiatedAlpn, ev.NegotiatedAlpnLength as usize)}
                }else{
                  &[]
                };
                Self::Connected { session_resumed: ev.SessionResumed != 0, negotiated_alpn: alpn }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_INITIATED_BY_TRANSPORT };
              Self::ShutdownInitiatedByTransport { status: crate::Status(ev.Status), error_code: ev.ErrorCode }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_INITIATED_BY_PEER };
              Self::ShutdownInitiatedByPeer { error_code: ev.ErrorCode }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE => {
              let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_COMPLETE };
               Self::ShutdownComplete { handshake_completed: ev.HandshakeCompleted() != 0,
                  peer_acknowledged_shutdown: ev.PeerAcknowledgedShutdown() != 0,
                  app_close_in_progress: ev.AppCloseInProgress() != 0 }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.LOCAL_ADDRESS_CHANGED };
              let addr = ev.Address as *const crate::Addr;
              Self::LocalAddressChanged { address: unsafe { addr.as_ref().unwrap() } }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_ADDRESS_CHANGED };
              let addr = ev.Address as *const crate::Addr;
              Self::PeerAddressChanged { address: unsafe { addr.as_ref().unwrap() } }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_STREAM_STARTED };
              Self::PeerStreamStarted { stream: unsafe { crate::StreamRef::from_raw(ev.Stream) }, flags: ev.Flags }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE => {
              let ev = unsafe { value.__bindgen_anon_1.STREAMS_AVAILABLE };
              Self::StreamsAvailable { bidirectional_count: ev.BidirectionalCount, unidirectional_count: ev.UnidirectionalCount }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_NEEDS_STREAMS };
              Self::PeerNeedsStreams { bidirectional: ev.Bidirectional != 0 }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.IDEAL_PROCESSOR_CHANGED };
              Self::IdealProcessorChanged { ideal_processor: ev.IdealProcessor, partition_index: ev.PartitionIndex }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_STATE_CHANGED };
              Self::DatagramStateChanged { send_enabled: ev.SendEnabled != 0, max_send_length: ev.MaxSendLength }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_RECEIVED };
              Self::DatagramReceived { buffer: unsafe { ev.Buffer.as_ref().unwrap() }, flags: ev.Flags }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_SEND_STATE_CHANGED };
              Self::DatagramSendStateChanged { client_context: ev.ClientContext, state: ev.State }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMED };
              // TODO: may need to check 0 len.
              Self::Resumed {
                resumption_state:  unsafe { std::slice::from_raw_parts(ev.ResumptionState, ev.ResumptionStateLength as usize) }
              }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMPTION_TICKET_RECEIVED };
              // TODO: may need to check 0 len.
              Self::ResumptionTicketReceived {
                resumption_ticket:  unsafe { std::slice::from_raw_parts(ev.ResumptionTicket, ev.ResumptionTicketLength as usize) }
              }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED => {
              let ev = unsafe { value.__bindgen_anon_1.PEER_CERTIFICATE_RECEIVED };
              Self::PeerCertificateReceived {
                certificate: ev.Certificate,
                deferred_error_flags: ev.DeferredErrorFlags,
                deferred_status: crate::Status(ev.DeferredStatus),
                chain: ev.Chain
              }
            }
            _ => {
                todo!("unknown event. maybe preview feature.")
            }
        }
    }
}

/// Stream callback events
pub enum StreamEvent<'a> {
    StartComplete {
        status: crate::Status,
        id: crate::u62,
        peer_accepted: bool,
    },
    Receive {
        absolute_offset: u64,
        total_buffer_length: &'a mut u64,       // out parameter
        buffers: &'a [crate::ffi::QUIC_BUFFER], // TODO: impl buffer wrapper types
        flags: crate::ffi::QUIC_RECEIVE_FLAGS,
    },
    SendComplete {
        cancelled: bool,
        client_context: *const std::ffi::c_void,
    },
    PeerSendShutdown,
    PeerSendAborted {
        error_code: crate::u62,
    },
    PeerReceiveAborted {
        error_code: crate::u62,
    },
    SendShutdownComplete {
        graceful: bool,
    },
    ShutdownComplete {
        connection_shutdown: bool,
        app_close_in_progress: bool,
        connection_shutdown_by_app: bool,
        connection_closed_remotely: bool,
        connection_error_code: crate::u62,
        connection_close_status: crate::Status,
    },
    IdealSendBufferSize {
        byte_count: u64,
    },
    PeerAccepted,
    CancelOnLoss {
        error_code: &'a mut crate::u62, // out param
    },
}

impl<'b> From<&'b mut crate::ffi::QUIC_STREAM_EVENT> for StreamEvent<'b> {
    fn from(value: &'b mut crate::ffi::QUIC_STREAM_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_START_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.START_COMPLETE };
                Self::StartComplete {
                    status: crate::Status(ev.Status),
                    id: ev.ID,
                    peer_accepted: ev.PeerAccepted() != 0,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_RECEIVE => {
                let ev = unsafe { &mut value.__bindgen_anon_1.RECEIVE };
                Self::Receive {
                    absolute_offset: ev.AbsoluteOffset,
                    total_buffer_length: &mut ev.TotalBufferLength,
                    buffers: unsafe {
                        std::slice::from_raw_parts(ev.Buffers, ev.BufferCount as usize)
                    },
                    flags: ev.Flags,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SEND_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SEND_COMPLETE };
                Self::SendComplete {
                    cancelled: ev.Canceled != 0,
                    client_context: ev.ClientContext,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN => {
                Self::PeerSendShutdown
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_SEND_ABORTED => {
                let ev = unsafe { value.__bindgen_anon_1.PEER_SEND_ABORTED };
                Self::PeerSendAborted {
                    error_code: ev.ErrorCode,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED => {
                let ev = unsafe { value.__bindgen_anon_1.PEER_RECEIVE_ABORTED };
                Self::PeerReceiveAborted {
                    error_code: ev.ErrorCode,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SEND_SHUTDOWN_COMPLETE };
                Self::SendShutdownComplete {
                    graceful: ev.Graceful != 0,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE => {
                let ev = unsafe { value.__bindgen_anon_1.SHUTDOWN_COMPLETE };
                Self::ShutdownComplete {
                    connection_shutdown: ev.ConnectionShutdown != 0,
                    app_close_in_progress: ev.AppCloseInProgress() != 0,
                    connection_shutdown_by_app: ev.ConnectionShutdownByApp() != 0,
                    connection_closed_remotely: ev.ConnectionClosedRemotely() != 0,
                    connection_error_code: ev.ConnectionErrorCode,
                    connection_close_status: crate::Status(ev.ConnectionCloseStatus),
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE => {
                let ev = unsafe { value.__bindgen_anon_1.IDEAL_SEND_BUFFER_SIZE };
                Self::IdealSendBufferSize {
                    byte_count: ev.ByteCount,
                }
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_PEER_ACCEPTED => {
                Self::PeerAccepted
            }
            crate::ffi::QUIC_STREAM_EVENT_TYPE_QUIC_STREAM_EVENT_CANCEL_ON_LOSS => {
                let ev = unsafe { &mut value.__bindgen_anon_1.CANCEL_ON_LOSS };
                Self::CancelOnLoss {
                    error_code: &mut ev.ErrorCode,
                }
            }
            _ => {
                panic!("unknown stream event: {}", value.Type)
            }
        }
    }
}
