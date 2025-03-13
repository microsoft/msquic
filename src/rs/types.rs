// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::{QUIC_BUFFER, QUIC_CONNECTION_EVENT};
use std::ffi::c_void;

/// Listener event converted from ffi type.
#[derive(Debug)]
pub enum ListenerEvent<'a> {
    NewConnection {
        info: NewConnectionInfo<'a>,
        /// User app needs to take ownership of this new connection.
        /// User app needs to set configuration for this connection
        /// before returning from the callback.
        /// TODO: Make this Connection type.
        connection: crate::ConnectionRef,
    },
    StopComplete {
        app_close_in_progress: bool,
    },
}

#[derive(Debug)]
pub struct NewConnectionInfo<'a> {
    pub quic_version: u32,
    pub local_address: &'a crate::Addr,
    pub remote_address: &'a crate::Addr,
    pub crypto_buffer: &'a [u8],
    pub client_alpn_list: &'a [u8],
    pub server_name: &'a [u8],
    pub negotiated_alpn: &'a [u8],
}

impl<'a> From<&'a crate::ffi::QUIC_NEW_CONNECTION_INFO> for NewConnectionInfo<'a> {
    fn from(value: &crate::ffi::QUIC_NEW_CONNECTION_INFO) -> Self {
        Self {
            quic_version: value.QuicVersion,
            local_address: unsafe { (value.LocalAddress as *const crate::Addr).as_ref().unwrap() },
            remote_address: unsafe {
                (value.RemoteAddress as *const crate::Addr)
                    .as_ref()
                    .unwrap()
            },
            crypto_buffer: unsafe {
                slice_conv(value.CryptoBuffer, value.CryptoBufferLength as usize)
            },
            client_alpn_list: unsafe {
                slice_conv(value.ClientAlpnList, value.ClientAlpnListLength as usize)
            },
            server_name: unsafe {
                slice_conv(
                    value.ServerName as *const u8,
                    value.ServerNameLength as usize,
                )
            },
            negotiated_alpn: unsafe {
                slice_conv(value.NegotiatedAlpn, value.NegotiatedAlpnLength as usize)
            },
        }
    }
}

impl<'a> From<&'a crate::ffi::QUIC_LISTENER_EVENT> for ListenerEvent<'a> {
    fn from(value: &'a crate::ffi::QUIC_LISTENER_EVENT) -> Self {
        match value.Type {
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_NEW_CONNECTION => {
                let ev = unsafe { &value.__bindgen_anon_1.NEW_CONNECTION };
                Self::NewConnection {
                    info: NewConnectionInfo::from(unsafe { ev.Info.as_ref().unwrap() }),
                    connection: unsafe { crate::ConnectionRef::from_raw(ev.Connection) },
                }
            }
            crate::ffi::QUIC_LISTENER_EVENT_TYPE_QUIC_LISTENER_EVENT_STOP_COMPLETE => {
                let ev = unsafe { &value.__bindgen_anon_1.STOP_COMPLETE };
                Self::StopComplete {
                    app_close_in_progress: ev.AppCloseInProgress() != 0,
                }
            }
            _ => panic!("unknown listener event {}", value.Type),
        }
    }
}

/// Connection callback events.
/// TODO: derive Debug once all enums are safe.
#[derive(Debug)]
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
    /// Stream ownership and cleanup is on user app.
    /// App needs to set the stream callback handler before
    /// returning from connection callback.
    // TODO: may need to change StreamRef to Stream for better safety.
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
    DatagramReceived {
        buffer: &'a BufferRef,
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
                let alpn = unsafe { slice_conv(ev.NegotiatedAlpn, ev.NegotiatedAlpnLength as usize) };
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
              Self::DatagramReceived { buffer: unsafe { BufferRef::from_ffi_ref(ev.Buffer.as_ref().unwrap()) }, flags: ev.Flags }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED => {
              let ev = unsafe { value.__bindgen_anon_1.DATAGRAM_SEND_STATE_CHANGED };
              Self::DatagramSendStateChanged { client_context: ev.ClientContext, state: ev.State }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMED };
              Self::Resumed {
                resumption_state:  unsafe { slice_conv(ev.ResumptionState, ev.ResumptionStateLength as usize) }
              }
            }
            crate::ffi::QUIC_CONNECTION_EVENT_TYPE_QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED =>{
              let ev = unsafe { value.__bindgen_anon_1.RESUMPTION_TICKET_RECEIVED };
              Self::ResumptionTicketReceived {
                resumption_ticket:  unsafe {slice_conv(ev.ResumptionTicket, ev.ResumptionTicketLength as usize) }
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
#[derive(Debug)]
pub enum StreamEvent<'a> {
    StartComplete {
        status: crate::Status,
        id: crate::u62,
        peer_accepted: bool,
    },
    Receive {
        absolute_offset: u64,
        total_buffer_length: &'a mut u64, // inout parameter
        buffers: &'a [BufferRef],
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
                        BufferRef::slice_from_ffi_ref(slice_conv(
                            ev.Buffers,
                            ev.BufferCount as usize,
                        ))
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

/// Buffer with same abi as ffi type.
/// # Safety
/// It has no ownership of the memory chunk,
/// and user needs to ensure that this ref has
/// the same lifetime as the original buffer
/// location.
#[repr(transparent)]
#[derive(Debug)]
pub struct BufferRef(pub QUIC_BUFFER);

impl BufferRef {
    /// Get the bytes of the buffer.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice_conv(self.0.Buffer, self.0.Length as usize) }
    }

    /// Cast from the ffi type.
    /// This achieves zero copy.
    pub fn from_ffi_ref(raw: &QUIC_BUFFER) -> &Self {
        unsafe { (raw as *const QUIC_BUFFER as *const Self).as_ref().unwrap() }
    }

    /// Cast from ffi slice type.
    /// This achieves zero copy.
    pub fn slice_from_ffi_ref(raw: &[QUIC_BUFFER]) -> &[Self] {
        unsafe {
            (raw as *const [QUIC_BUFFER] as *const [Self])
                .as_ref()
                .unwrap()
        }
    }
}

// Convert from various common buffer types
impl From<&str> for BufferRef {
    fn from(value: &str) -> Self {
        Self(QUIC_BUFFER {
            Length: value.len() as u32,
            Buffer: value.as_ptr() as *mut u8,
        })
    }
}

impl From<&[u8]> for BufferRef {
    fn from(value: &[u8]) -> Self {
        Self(QUIC_BUFFER {
            Length: value.len() as u32,
            Buffer: value.as_ptr() as *mut u8,
        })
    }
}

/// Convert array pointer to slice.
/// Allows empty buffer. slice::from_raw_parts does not allow empty buffer.
#[inline]
unsafe fn slice_conv<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

#[cfg(test)]
mod buff_tests {
    use crate::{ffi::QUIC_BUFFER, types::slice_conv, BufferRef};
    #[test]
    fn slice_conv_test() {
        {
            let ptr = std::ptr::null::<u8>();
            let len = 0;
            let buff = unsafe { slice_conv(ptr, len) };
            assert_eq!(buff.len(), 0)
        }
        {
            let original = b"hello";
            let buff = unsafe { slice_conv(original.as_ptr(), original.len()) };
            assert_eq!(buff, original.as_slice())
        }
    }

    #[test]
    fn buffer_ref_raw_test() {
        let first = Box::new(b"first");
        let second = b"second";
        let buffers = Box::new([
            QUIC_BUFFER {
                Buffer: first.as_ptr() as *mut u8,
                Length: first.len() as u32,
            },
            QUIC_BUFFER {
                Buffer: second.as_ptr() as *mut u8,
                Length: second.len() as u32,
            },
        ]);
        let buffer_refs = BufferRef::slice_from_ffi_ref(buffers.as_ref());
        let buffs = buffer_refs;
        // In callback events, buffers has memory from C,
        // and it has the right lifetime.
        // In this test, `buffers` variable emulates the memory from C.

        let first1 = &buffs[0];
        // If we drop buffers here on this line, compiler can catch the first1's lifetime is violated.
        // This shows that the BufferSlice wrapper captures the right lifetime of the buffers.
        // However there is no way to carry the lifetime of the var `first` into var `buffers` because the C style
        // api raw pointer boundary has been crossed.
        // TODO: msquic has feature to hold on to buffers even after callback have returned. This is
        // is not supported safely in rust. (event if we support this, buffs reference's lifetime is still only valid
        // at the end of the callback function. However, the lifetime of content of the buffer, i.e. &[u8], can be extended.)
        let second1 = &buffs[1];
        assert_eq!(first.as_slice(), first1.as_bytes());
        assert_eq!(second, second1.as_bytes());
    }

    /// This test shows how to construct simple
    /// buffers to call msquic.
    #[test]
    fn buffer_ref_conv_test() {
        let b1 = b"11";
        let b2 = b"22".to_vec();
        let b3 = "33";

        let buffer_refs = [
            BufferRef::from(b1.as_slice()),
            BufferRef::from(b2.as_slice()),
            BufferRef::from(b3),
        ];
        // One can call msquic api here using the slice.

        assert_eq!(buffer_refs[0].as_bytes(), b1);
        assert_eq!(buffer_refs[1].as_bytes(), b2);
        assert_eq!(buffer_refs[2].as_bytes(), b3.as_bytes());
    }

    #[test]
    fn buffer_ref_detach_test() {
        let data = b"data".to_vec().into_boxed_slice();
        let buff_refs = [BufferRef::from(data.as_ref())];

        // Detach the data as raw ptr.
        // raw ptr can be pass to msquic as client context.
        let raw = Box::into_raw(data);

        // MsQuic takes ownership of the buff and can inspect it.
        assert_eq!(buff_refs[0].as_bytes(), b"data");

        // Attach back the ownership
        // Usually used when msquic gives back the client context
        // in the callback event.
        let _ = unsafe { Box::from_raw(raw) };
    }

    #[test]
    fn multi_buffer_ref_detach_test() {
        let data = b"data".to_vec();
        let data2 = Box::new("data2");
        let buff_refs = [
            BufferRef::from(data.as_slice()),
            BufferRef::from(data2.as_bytes()),
        ];

        let ctx = Box::new((data, data2));

        // Detach the data as raw ptr.
        // raw ptr can be pass to msquic as client context.
        let raw = Box::into_raw(ctx);

        // MsQuic takes ownership of the buff and can inspect it.
        assert_eq!(buff_refs[0].as_bytes(), b"data");
        assert_eq!(buff_refs[1].as_bytes(), b"data2");

        // Attach back the ownership
        // Usually used when msquic gives back the client context
        // in the callback event.
        let _ = unsafe { Box::from_raw(raw) };
    }
}
