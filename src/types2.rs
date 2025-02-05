pub enum StreamEvent2<'a> {
    StartComplete {
        status: crate::Status,
        id: crate::u62,
        peer_accepted: bool,
    },
    Receive {
        absolute_offset: u64,
        total_buffer_length: &'a mut u64,       // TODO: needs modify
        buffers: &'a [crate::ffi::QUIC_BUFFER], // TODO: better buffer types
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

impl<'b> From<&'b mut crate::ffi::QUIC_STREAM_EVENT> for StreamEvent2<'b> {
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
