// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[allow(unused_imports)]
use c_types::AF_INET;
#[allow(unused_imports)]
use c_types::AF_INET6;
#[allow(unused_imports)]
use c_types::AF_UNSPEC;
use c_types::{sa_family_t, sockaddr_in, sockaddr_in6, socklen_t};
use ffi::{HQUIC, QUIC_API_TABLE, QUIC_BUFFER, QUIC_CREDENTIAL_CONFIG, QUIC_SETTINGS, QUIC_STATUS};
use libc::c_void;
use serde::{Deserialize, Serialize};
use socket2::SockAddr;
use std::fmt::Debug;
use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::option::Option;
use std::ptr;
use std::result::Result;
use std::sync::Once;
mod error;
pub mod ffi;
pub use error::{Status, StatusCode};
mod types;
pub use types::{BufferRef, ConnectionEvent, ListenerEvent, NewConnectionInfo, StreamEvent};
mod settings;
pub use settings::{ServerResumptionLevel, Settings};
mod config;
pub use config::{CredentialConfig, ExecutionProfile, RegistrationConfig};

//
// The following starts the C interop layer of MsQuic API.
//

/// Unsigned 62-bit integer.
#[allow(non_camel_case_types)]
pub type u62 = u64;

/// C-style bool.
pub type BOOLEAN = ::std::os::raw::c_uchar;

/// Family of an IP address.
pub type AddressFamily = u16;
#[allow(clippy::unnecessary_cast)]
pub const ADDRESS_FAMILY_UNSPEC: AddressFamily = c_types::AF_UNSPEC as u16;
#[allow(clippy::unnecessary_cast)]
pub const ADDRESS_FAMILY_INET: AddressFamily = c_types::AF_INET as u16;
#[allow(clippy::unnecessary_cast)]
pub const ADDRESS_FAMILY_INET6: AddressFamily = c_types::AF_INET6 as u16;

/// Generic representation of IPv4 or IPv6 addresses.
#[repr(C)]
#[derive(Copy, Clone)]
pub union Addr {
    pub ipv4: sockaddr_in,
    pub ipv6: sockaddr_in6,
}

impl Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: implement Addr content debug string
        write!(f, "Addr{{..}}")
    }
}

impl Addr {
    /// Converts the `Addr` to a `SocketAddr`.
    pub fn as_socket(&self) -> Option<SocketAddr> {
        unsafe {
            SockAddr::try_init(|addr, len| {
                if self.ipv4.sin_family == AF_INET as sa_family_t {
                    let addr = addr.cast::<sockaddr_in>();
                    *addr = self.ipv4;
                    *len = mem::size_of::<sockaddr_in>() as socklen_t;
                    Ok(())
                } else if self.ipv4.sin_family == AF_INET6 as sa_family_t {
                    let addr = addr.cast::<sockaddr_in6>();
                    *addr = self.ipv6;
                    *len = mem::size_of::<sockaddr_in6>() as socklen_t;
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::Other))
                }
            })
        }
        .map(|((), addr)| addr.as_socket().unwrap())
        .ok()
    }

    /// Get port number from the `Addr`.
    pub fn port(&self) -> u16 {
        unsafe { u16::from_be(self.ipv4.sin_port) }
    }
}

impl From<SocketAddr> for Addr {
    fn from(addr: SocketAddr) -> Addr {
        match addr {
            SocketAddr::V4(addr) => addr.into(),
            SocketAddr::V6(addr) => addr.into(),
        }
    }
}

impl From<SocketAddrV4> for Addr {
    fn from(addr: SocketAddrV4) -> Addr {
        // SAFETY: a `Addr` of all zeros is valid.
        let mut storage = unsafe { mem::zeroed::<Addr>() };
        let addr: SockAddr = addr.into();
        let addr = addr.as_ptr().cast::<sockaddr_in>();
        storage.ipv4 = unsafe { *addr };
        storage
    }
}

impl From<SocketAddrV6> for Addr {
    fn from(addr: SocketAddrV6) -> Addr {
        // SAFETY: a `Addr` of all zeros is valid.
        let mut storage = unsafe { mem::zeroed::<Addr>() };
        let addr: SockAddr = addr.into();
        let addr = addr.as_ptr().cast::<sockaddr_in6>();
        storage.ipv6 = unsafe { *addr };
        storage
    }
}

/// The different possible TLS providers used by MsQuic.
pub type TlsProvider = u32;
pub const TLS_PROVIDER_SCHANNEL: TlsProvider = 0;
pub const TLS_PROVIDER_OPENSSL: TlsProvider = 1;

/// Represents how load balancing is performed.
pub type LoadBalancingMode = u32;
pub const LOAD_BALANCING_DISABLED: LoadBalancingMode = 0;
pub const LOAD_BALANCING_SERVER_ID_IP: LoadBalancingMode = 1;

/// Represents different TLS alert codes.
pub type TlsAlertCode = u32;
pub const TLS_ALERT_CODE_SUCCESS: TlsAlertCode = 0xffff;
pub const TLS_ALERT_CODE_UNEXPECTED_MESSAGE: TlsAlertCode = 10;
pub const TLS_ALERT_CODE_BAD_CERTIFICATE: TlsAlertCode = 42;
pub const TLS_ALERT_CODE_UNSUPPORTED_CERTIFICATE: TlsAlertCode = 43;
pub const TLS_ALERT_CODE_CERTIFICATE_REVOKED: TlsAlertCode = 44;
pub const TLS_ALERT_CODE_CERTIFICATE_EXPIRED: TlsAlertCode = 45;
pub const TLS_ALERT_CODE_CERTIFICATE_UNKNOWN: TlsAlertCode = 46;
pub const TLS_ALERT_CODE_ILLEGAL_PARAMETER: TlsAlertCode = 47;
pub const TLS_ALERT_CODE_UNKNOWN_CA: TlsAlertCode = 48;
pub const TLS_ALERT_CODE_ACCESS_DENIED: TlsAlertCode = 49;
pub const TLS_ALERT_CODE_INSUFFICIENT_SECURITY: TlsAlertCode = 71;
pub const TLS_ALERT_CODE_INTERNAL_ERROR: TlsAlertCode = 80;
pub const TLS_ALERT_CODE_USER_CANCELED: TlsAlertCode = 90;
pub const TLS_ALERT_CODE_CERTIFICATE_REQUIRED: TlsAlertCode = 116;

/// Modifies the default certificate hash store configuration.
pub type CertificateHashStoreFlags = u32;
pub const CERTIFICATE_HASH_STORE_FLAG_NONE: CertificateHashStoreFlags = 0;
pub const CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE: CertificateHashStoreFlags = 1;

/// Controls connection shutdown behavior.
pub type ConnectionShutdownFlags = u32;
pub const CONNECTION_SHUTDOWN_FLAG_NONE: ConnectionShutdownFlags = 0;
pub const CONNECTION_SHUTDOWN_FLAG_SILENT: ConnectionShutdownFlags = 1;

/// Modifies the behavior when sending resumption data.
pub type SendResumptionFlags = u32;
pub const SEND_RESUMPTION_FLAG_NONE: SendResumptionFlags = 0;
pub const SEND_RESUMPTION_FLAG_FINAL: SendResumptionFlags = 1;

/// Controls the connection's scheduling behavior for streams.
pub type StreamSchedulingScheme = u32;
pub const STREAM_SCHEDULING_SCHEME_FIFO: StreamSchedulingScheme = 0;
pub const STREAM_SCHEDULING_SCHEME_ROUND_ROBIN: StreamSchedulingScheme = 1;
pub const STREAM_SCHEDULING_SCHEME_COUNT: StreamSchedulingScheme = 2;

pub type StreamOpenFlags = u32;
pub const STREAM_OPEN_FLAG_NONE: StreamOpenFlags = 0;
pub const STREAM_OPEN_FLAG_UNIDIRECTIONAL: StreamOpenFlags = 1;
pub const STREAM_OPEN_FLAG_0_RTT: StreamOpenFlags = 2;

pub type StreamStartFlags = u32;
pub const STREAM_START_FLAG_NONE: StreamStartFlags = 0;
pub const STREAM_START_FLAG_IMMEDIATE: StreamStartFlags = 1;
pub const STREAM_START_FLAG_FAIL_BLOCKED: StreamStartFlags = 2;
pub const STREAM_START_FLAG_SHUTDOWN_ON_FAIL: StreamStartFlags = 4;
pub const STREAM_START_FLAG_INDICATE_PEER_ACCEPT: StreamStartFlags = 8;

/// Controls stream shutdown behavior.
pub type StreamShutdownFlags = u32;
pub const STREAM_SHUTDOWN_FLAG_NONE: StreamShutdownFlags = 0;
pub const STREAM_SHUTDOWN_FLAG_GRACEFUL: StreamShutdownFlags = 1;
pub const STREAM_SHUTDOWN_FLAG_ABORT_SEND: StreamShutdownFlags = 2;
pub const STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE: StreamShutdownFlags = 4;
pub const STREAM_SHUTDOWN_FLAG_ABORT: StreamShutdownFlags = 6;
pub const STREAM_SHUTDOWN_FLAG_IMMEDIATE: StreamShutdownFlags = 8;

pub type ReceiveFlags = u32;
pub const RECEIVE_FLAG_NONE: ReceiveFlags = 0;
pub const RECEIVE_FLAG_0_RTT: ReceiveFlags = 1;
pub const RECEIVE_FLAG_FIN: ReceiveFlags = 2;

/// Controls stream and datagram send behavior.
pub type SendFlags = u32;
pub const SEND_FLAG_NONE: SendFlags = 0;
pub const SEND_FLAG_ALLOW_0_RTT: SendFlags = 1;
pub const SEND_FLAG_START: SendFlags = 2;
pub const SEND_FLAG_FIN: SendFlags = 4;
pub const SEND_FLAG_DGRAM_PRIORITY: SendFlags = 8;
pub const SEND_FLAG_DELAY_SEND: SendFlags = 16;

pub type DatagramSendState = u32;
pub const DATAGRAM_SEND_SENT: DatagramSendState = 0;
pub const DATAGRAM_SEND_LOST_SUSPECT: DatagramSendState = 1;
pub const DATAGRAM_SEND_LOST_DISCARDED: DatagramSendState = 2;
pub const DATAGRAM_SEND_ACKNOWLEDGED: DatagramSendState = 3;
pub const DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS: DatagramSendState = 4;
pub const DATAGRAM_SEND_CANCELED: DatagramSendState = 5;

/// Key information for TLS session ticket encryption.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TicketKeyConfig {
    pub id: [u8; 16usize],
    pub material: [u8; 64usize],
    pub material_length: u8,
}

pub type TlsProtocolVersion = u32;
pub const TLS_PROTOCOL_UNKNOWN: TlsProtocolVersion = 0;
pub const TLS_PROTOCOL_1_3: TlsProtocolVersion = 12288;

pub type CipherAlgorithm = u32;
pub const CIPHER_ALGORITHM_NONE: CipherAlgorithm = 0;
pub const CIPHER_ALGORITHM_AES_128: CipherAlgorithm = 26126;
pub const CIPHER_ALGORITHM_AES_256: CipherAlgorithm = 26128;
pub const CIPHER_ALGORITHM_CHACHA20: CipherAlgorithm = 26130;

pub type HashAlgorithm = u32;
pub const HASH_ALGORITHM_NONE: HashAlgorithm = 0;
pub const HASH_ALGORITHM_SHA_256: HashAlgorithm = 32780;
pub const HASH_ALGORITHM_SHA_384: HashAlgorithm = 32781;

pub type KeyExchangeAlgorithm = u32;
pub const KEY_EXCHANGE_ALGORITHM_NONE: KeyExchangeAlgorithm = 0;

pub type CipherSuite = u32;
pub const CIPHER_SUITE_TLS_AES_128_GCM_SHA256: CipherSuite = 4865;
pub const CIPHER_SUITE_TLS_AES_256_GCM_SHA384: CipherSuite = 4866;
pub const CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256: CipherSuite = 4867;

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct HandshakeInfo {
    pub tls_protocol_version: TlsProtocolVersion,
    pub cipher_algorithm: CipherAlgorithm,
    pub cipher_strength: i32,
    pub hash: HashAlgorithm,
    pub hash_strength: i32,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
    pub key_exchange_strength: i32,
    pub cipher_suite: CipherSuite,
}

/// A helper struct for accessing listener statistics.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QuicListenerStatistics {
    pub total_accepted_connections: u64,
    pub total_rejected_connections: u64,
    pub binding: u64,
}

type QuicPerformanceCountersParam =
    [i64; crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_MAX as usize];

/// A helper struct for accessing performance counters.
#[derive(Debug)]
pub struct QuicPerformanceCounters {
    pub conn_created: i64,
    pub conn_handshake_fail: i64,
    pub conn_app_reject: i64,
    pub conn_resumed: i64,
    pub conn_active: i64,
    pub conn_connected: i64,
    pub conn_protocol_errors: i64,
    pub conn_no_alpn: i64,
    pub strm_active: i64,
    pub pkts_suspected_lost: i64,
    pub pkts_dropped: i64,
    pub pkts_decryption_fail: i64,
    pub udp_recv: i64,
    pub udp_send: i64,
    pub udp_recv_bytes: i64,
    pub udp_send_bytes: i64,
    pub udp_recv_events: i64,
    pub udp_send_calls: i64,
    pub app_send_bytes: i64,
    pub app_recv_bytes: i64,
    pub conn_queue_depth: i64,
    pub conn_oper_queue_depth: i64,
    pub conn_oper_queued: i64,
    pub conn_oper_completed: i64,
    pub work_oper_queue_depth: i64,
    pub work_oper_queued: i64,
    pub work_oper_completed: i64,
    pub path_validated: i64,
    pub path_failure: i64,
    pub send_stateless_reset: i64,
    pub send_stateless_retry: i64,
    pub conn_load_reject: i64,
}

pub const QUIC_TLS_SECRETS_MAX_SECRET_LEN: usize = 64;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QuicTlsSecrets {
    pub secret_length: u8,
    pub flags: u8,
    pub client_random: [u8; 32],
    pub client_early_traffic_secret: [u8; QUIC_TLS_SECRETS_MAX_SECRET_LEN],
    pub client_handshake_traffic_secret: [u8; QUIC_TLS_SECRETS_MAX_SECRET_LEN],
    pub server_handshake_traffic_secret: [u8; QUIC_TLS_SECRETS_MAX_SECRET_LEN],
    pub client_traffic_secret0: [u8; QUIC_TLS_SECRETS_MAX_SECRET_LEN],
    pub server_traffic_secret0: [u8; QUIC_TLS_SECRETS_MAX_SECRET_LEN],
}

pub const PARAM_GLOBAL_RETRY_MEMORY_PERCENT: u32 = 0x01000000;
pub const PARAM_GLOBAL_SUPPORTED_VERSIONS: u32 = 0x01000001;
pub const PARAM_GLOBAL_LOAD_BALACING_MODE: u32 = 0x01000002;
pub const PARAM_GLOBAL_PERF_COUNTERS: u32 = 0x01000003;
pub const PARAM_GLOBAL_VERSION: u32 = 0x01000004;
pub const PARAM_GLOBAL_SETTINGS: u32 = 0x01000005;
pub const PARAM_GLOBAL_GLOBAL_SETTINGS: u32 = 0x01000006;
pub const PARAM_GLOBAL_VERSION_SETTINGS: u32 = 0x01000007;
pub const PARAM_GLOBAL_LIBRARY_GIT_HASH: u32 = 0x01000008;
pub const PARAM_GLOBAL_DATAPATH_PROCESSORS: u32 = 0x01000009;
pub const PARAM_GLOBAL_TLS_PROVIDER: u32 = 0x0100000A;

pub const PARAM_CONFIGURATION_SETTINGS: u32 = 0x03000000;
pub const PARAM_CONFIGURATION_TICKET_KEYS: u32 = 0x03000001;
pub const PARAM_CONFIGURATION_VERSION_SETTINGS: u32 = 0x03000002;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SchannelCredentialAttributeW {
    pub attribute: u32,
    pub buffer_length: u32,
    pub buffer: *mut c_void,
}
pub const PARAM_CONFIGURATION_SCHANNEL_CREDENTIAL_ATTRIBUTE_W: u32 = 0x03000003;

pub const PARAM_LISTENER_LOCAL_ADDRESS: u32 = 0x04000000;
pub const PARAM_LISTENER_STATS: u32 = 0x04000001;
pub const PARAM_LISTENER_CIBIR_ID: u32 = 0x04000002;

pub const PARAM_CONN_QUIC_VERSION: u32 = 0x05000000;
pub const PARAM_CONN_LOCAL_ADDRESS: u32 = 0x05000001;
pub const PARAM_CONN_REMOTE_ADDRESS: u32 = 0x05000002;
pub const PARAM_CONN_IDEAL_PROCESSOR: u32 = 0x05000003;
pub const PARAM_CONN_SETTINGS: u32 = 0x05000004;
pub const PARAM_CONN_STATISTICS: u32 = 0x05000005;
pub const PARAM_CONN_STATISTICS_PLAT: u32 = 0x05000006;
pub const PARAM_CONN_SHARE_UDP_BINDING: u32 = 0x05000007;
pub const PARAM_CONN_LOCAL_BIDI_STREAM_COUNT: u32 = 0x05000008;
pub const PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT: u32 = 0x05000009;
pub const PARAM_CONN_MAX_STREAM_IDS: u32 = 0x0500000A;
pub const PARAM_CONN_CLOSE_REASON_PHRASE: u32 = 0x0500000B;
pub const PARAM_CONN_STREAM_SCHEDULING_SCHEME: u32 = 0x0500000C;
pub const PARAM_CONN_DATAGRAM_RECEIVE_ENABLED: u32 = 0x0500000D;
pub const PARAM_CONN_DATAGRAM_SEND_ENABLED: u32 = 0x0500000E;
pub const CONN_DISABLE_1RTT_ENCRYPTION: u32 = 0x0500000F;
pub const PARAM_CONN_RESUMPTION_TICKET: u32 = 0x05000010;
pub const PARAM_CONN_PEER_CERTIFICATE_VALID: u32 = 0x05000011;
pub const PARAM_CONN_LOCAL_INTERFACE: u32 = 0x05000012;
pub const PARAM_CONN_TLS_SECRETS: u32 = 0x05000013;
pub const PARAM_CONN_VERSION_SETTINGS: u32 = 0x05000014;
pub const PARAM_CONN_INITIAL_DCID_PREFIX: u32 = 0x05000015;
pub const PARAM_CONN_STATISTICS_V2: u32 = 0x05000016;
pub const PARAM_CONN_STATISTICS_V2_PLAT: u32 = 0x05000017;

pub const PARAM_TLS_HANDSHAKE_INFO: u32 = 0x06000000;
pub const PARAM_TLS_NEGOTIATED_ALPN: u32 = 0x06000001;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SchannelContextAttributeW {
    pub attribute: u32,
    pub buffer: *mut c_void,
}
pub const PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W: u32 = 0x07000000;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SchannelContextAttributeExW {
    pub attribute: u32,
    pub buffer_length: u32,
    pub buffer: *mut c_void,
}
pub const PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W: u32 = 0x07000001;
pub const PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN: u32 = 0x07000002;

pub const PARAM_STREAM_ID: u32 = 0x08000000;
pub const PARAM_STREAM_0RTT_LENGTH: u32 = 0x08000001;
pub const PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE: u32 = 0x08000002;
pub const PARAM_STREAM_PRIORITY: u32 = 0x08000003;

#[link(name = "msquic")]
unsafe extern "C" {
    unsafe fn MsQuicOpenVersion(version: u32, api: *mut *const QUIC_API_TABLE) -> u32;
    unsafe fn MsQuicClose(api: *const QUIC_API_TABLE);
}

//
// The following starts the "nice" Rust API wrapper on the C interop layer.
//

//
// APITABLE will be initialized via MsQuicOpenVersion() when we first initialize Api or Registration.
//
static mut APITABLE: *const QUIC_API_TABLE = ptr::null();
static START_MSQUIC: Once = Once::new();

/// Entry point for some global MsQuic APIs.
pub struct Api {}

impl Api {
    /// Get the ffi api table internally.
    /// Assumes global has been initialized.
    /// i.e. get_ffi() has been called at least once before.
    #[inline]
    fn ffi_ref() -> &'static crate::ffi::QUIC_API_TABLE {
        unsafe { APITABLE.as_ref().unwrap() }
    }

    /// Returns the global ffi api table.
    /// Initialize it if called the first time.
    /// Allows user to use the unsafe api table for functions not yet
    /// supported in the wrappers.
    pub fn get_ffi() -> &'static crate::ffi::QUIC_API_TABLE {
        Api::once_init_api();
        Api::ffi_ref()
    }

    /// Initializes the global static api table.
    /// This is used in registration creation, or in user getting raw ffi.
    fn once_init_api() {
        // initialization is done exactly once.
        unsafe {
            START_MSQUIC.call_once(|| {
                let mut table: *const QUIC_API_TABLE = ptr::null();
                let status = MsQuicOpenVersion(2, std::ptr::addr_of_mut!(table));
                if let Err(err) = Status::ok_from_raw(status as QUIC_STATUS) {
                    panic!("Failed to open MsQuic: {}", err);
                }
                APITABLE = table;
            });
        }
    }
}

/// The execution context for processing connections on the application's behalf.
pub struct Registration {
    handle: HQUIC,
}
unsafe impl Sync for Registration {}
unsafe impl Send for Registration {}

/// Specifies how to configure a connection.
pub struct Configuration {
    handle: HQUIC,
}
unsafe impl Sync for Configuration {}
unsafe impl Send for Configuration {}

/// A single QUIC connection.
#[derive(Debug)]
pub struct Connection {
    handle: HQUIC,
}
unsafe impl Sync for Connection {}
unsafe impl Send for Connection {}

/// A single server listener
#[derive(Debug)]
pub struct Listener {
    handle: HQUIC,
}
unsafe impl Sync for Listener {}
unsafe impl Send for Listener {}

/// A single QUIC stream on a parent connection.
#[derive(Debug)]
pub struct Stream {
    handle: HQUIC,
}
unsafe impl Sync for Stream {}
unsafe impl Send for Stream {}

impl From<QuicPerformanceCountersParam> for QuicPerformanceCounters {
    fn from(value: QuicPerformanceCountersParam) -> Self {
        Self {
            conn_created: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_CREATED as usize],
            conn_handshake_fail: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL
                    as usize],
            conn_app_reject: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_APP_REJECT as usize],
            conn_resumed: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_RESUMED as usize],
            conn_active: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_ACTIVE as usize],
            conn_connected: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_CONNECTED as usize],
            conn_protocol_errors: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS
                    as usize],
            conn_no_alpn: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_NO_ALPN as usize],
            strm_active: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_STRM_ACTIVE as usize],
            pkts_suspected_lost: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST
                    as usize],
            pkts_dropped: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_PKTS_DROPPED as usize],
            pkts_decryption_fail: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL
                    as usize],
            udp_recv: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_RECV as usize],
            udp_send: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_SEND as usize],
            udp_recv_bytes: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_RECV_BYTES as usize],
            udp_send_bytes: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_SEND_BYTES as usize],
            udp_recv_events: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_RECV_EVENTS as usize],
            udp_send_calls: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_UDP_SEND_CALLS as usize],
            app_send_bytes: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_APP_SEND_BYTES as usize],
            app_recv_bytes: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_APP_RECV_BYTES as usize],
            conn_queue_depth: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH as usize],
            conn_oper_queue_depth: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH
                    as usize],
            conn_oper_queued: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_OPER_QUEUED as usize],
            conn_oper_completed: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_OPER_COMPLETED
                    as usize],
            work_oper_queue_depth: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH
                    as usize],
            work_oper_queued: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_WORK_OPER_QUEUED as usize],
            work_oper_completed: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_WORK_OPER_COMPLETED
                    as usize],
            path_validated: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_PATH_VALIDATED as usize],
            path_failure: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_PATH_FAILURE as usize],
            send_stateless_reset: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_SEND_STATELESS_RESET
                    as usize],
            send_stateless_retry: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_SEND_STATELESS_RETRY
                    as usize],
            conn_load_reject: value
                [crate::ffi::QUIC_PERFORMANCE_COUNTERS_QUIC_PERF_COUNTER_CONN_LOAD_REJECT as usize],
        }
    }
}

impl Api {
    /// # Safety
    /// Buffer needs to be valid
    pub unsafe fn get_param(
        handle: HQUIC,
        param: u32,
        buffer_length: *const u32,
        buffer: *mut c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().GetParam.unwrap()(handle, param, buffer_length as *mut u32, buffer)
        };
        Status::ok_from_raw(status)
    }

    /// Auto create param type T
    /// # Safety
    /// T needs to be ffi type compatible.
    pub unsafe fn get_param_auto<T>(handle: HQUIC, param: u32) -> Result<T, Status> {
        let buffer = std::mem::zeroed::<T>();
        let len = std::mem::size_of::<T>() as u32;
        Self::get_param(handle, param, &len, &buffer as *const T as *mut c_void)?;
        Ok(buffer)
    }

    /// # Safety
    /// buffer needs to be valid.
    pub unsafe fn set_param(
        handle: HQUIC,
        param: u32,
        buffer_length: u32,
        buffer: *const c_void,
    ) -> Result<(), Status> {
        let status =
            unsafe { Api::ffi_ref().SetParam.unwrap()(handle, param, buffer_length, buffer) };
        Status::ok_from_raw(status)
    }

    pub fn get_perf() -> Result<QuicPerformanceCounters, Status> {
        unsafe {
            Api::get_param_auto::<QuicPerformanceCountersParam>(
                std::ptr::null_mut(),
                crate::ffi::QUIC_PARAM_GLOBAL_PERF_COUNTERS,
            )
        }
        .map(QuicPerformanceCounters::from)
    }

    pub fn get_retry_memory_percent() -> Result<u16, Status> {
        unsafe {
            Api::get_param_auto(
                std::ptr::null_mut(),
                crate::ffi::QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
            )
        }
    }

    pub fn get_tls_provider() -> Result<crate::ffi::QUIC_TLS_PROVIDER, Status> {
        unsafe {
            Api::get_param_auto(
                std::ptr::null_mut(),
                crate::ffi::QUIC_PARAM_GLOBAL_TLS_PROVIDER,
            )
        }
    }

    /// # Safety
    /// handler and context must be valid.
    pub unsafe fn set_callback_handler(
        handle: HQUIC,
        handler: *const c_void,
        context: *const c_void,
    ) {
        unsafe {
            Api::ffi_ref().SetCallbackHandler.unwrap()(
                handle,
                handler as *mut c_void,
                context as *mut c_void,
            )
        };
    }
}

#[ctor::dtor]
fn close_msquic() {
    unsafe {
        if !APITABLE.is_null() {
            MsQuicClose(APITABLE);
            APITABLE = ptr::null();
        }
    }
}

/// macro to define common functionalities for quic handle,
/// including conversion from raw HQUIC and Drop trait.
macro_rules! define_quic_handle_impl {
    ($handle_name:ident) => {
        /// Raw quic handle apis.
        impl $handle_name {
            /// Takes ownership of raw handle.
            /// # Safety
            /// handle must be valid
            pub unsafe fn from_raw(h: HQUIC) -> Self {
                Self { handle: h }
            }

            /// Returns the raw handle.
            /// # Safety
            /// caller should not close handle.
            pub unsafe fn as_raw(&self) -> HQUIC {
                self.handle
            }

            /// Returns the raw handle.
            /// # Safety
            /// caller is responsible for cleanups
            pub unsafe fn into_raw(mut self) -> HQUIC {
                let h = self.handle;
                self.handle = std::ptr::null_mut();
                h
            }

            /// Closes the handle and consumes it.
            pub fn close(self) {
                self.close_inner();
            }
        }

        /// drop the handle. Requires close_inner() to be implemented.
        impl Drop for $handle_name {
            fn drop(&mut self) {
                self.close_inner();
            }
        }
    };
}

/// defines the common code for the handle to manage handle context
macro_rules! define_quic_handle_ctx_fn {
    ($handle_name:ident, $callback_type:ident) => {
        impl $handle_name {
            pub fn get_context(&self) -> *mut c_void {
                unsafe { Api::ffi_ref().GetContext.unwrap()(self.handle) }
            }

            /// # Safety
            /// Previous context needs to be cleaned up before set a new one.
            pub unsafe fn set_context(&self, ctx: *mut c_void) {
                unsafe { Api::ffi_ref().SetContext.unwrap()(self.handle, ctx) }
            }

            /// Consume ctx by dropping it.
            /// Set msquic ctx to null.
            fn consume_callback_ctx(&self) {
                let res = unsafe { self.get_callback_ctx() };
                if res.is_some() {
                    unsafe { self.set_context(std::ptr::null_mut()) };
                }
            }

            /// # Safety
            /// Caller is responsible for clearing the context if needed.
            /// This does not clear the ctx.
            unsafe fn get_callback_ctx(&self) -> Option<Box<Box<$callback_type>>> {
                let ctx = self.get_context();
                if !ctx.is_null() {
                    Some(unsafe { Box::from_raw(ctx as *mut Box<$callback_type>) })
                } else {
                    None
                }
            }
        }
    };
}

/// Defines the Ref type for the handle that does not cleanup
/// the handle on drop.
macro_rules! define_quic_handle_ref {
    ($handle_name:ident, $handle_ref_name:ident) => {
        /// Same as the owned type but does not own the handle.
        /// Only used in callback wrapping where handle
        /// should not be closed by default.
        #[derive(Debug)]
        pub struct $handle_ref_name($handle_name);

        impl $handle_ref_name {
            /// For internal use only.
            pub(crate) unsafe fn from_raw(handle: HQUIC) -> Self {
                Self($handle_name { handle })
            }
        }

        impl Drop for $handle_ref_name {
            fn drop(&mut self) {
                // clear the handle to prevent auto close.
                self.0.handle = std::ptr::null_mut()
            }
        }

        /// Make inner handle accessible
        impl std::ops::Deref for $handle_ref_name {
            type Target = $handle_name;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

impl Registration {
    pub fn new(config: &RegistrationConfig) -> Result<Registration, Status> {
        // Initialize the global api table.
        // Registration is the first created in all msquic apps.
        let api = Api::get_ffi();
        let mut h = std::ptr::null_mut();
        let status = unsafe {
            api.RegistrationOpen.unwrap()(
                &config.as_ffi() as *const crate::ffi::QUIC_REGISTRATION_CONFIG,
                std::ptr::addr_of_mut!(h),
            )
        };

        Status::ok_from_raw(status)?;
        Ok(Registration { handle: h })
    }

    pub fn shutdown(&self) {
        unsafe { Api::ffi_ref().RegistrationShutdown.unwrap()(self.handle, 0, 0) }
    }

    fn close_inner(&self) {
        if !self.handle.is_null() {
            unsafe { Api::ffi_ref().RegistrationClose.unwrap()(self.handle) }
        }
    }
}

define_quic_handle_impl!(Registration);

impl Configuration {
    pub fn new(
        registration: &Registration,
        alpn: &[BufferRef],
        settings: Option<&Settings>,
    ) -> Result<Configuration, Status> {
        let context: *mut c_void = ptr::null_mut();
        let mut new_configuration: HQUIC = ptr::null_mut();
        let (settings_ptr, settings_size) = match settings {
            Some(s) => (
                s.as_ffi_ref() as *const QUIC_SETTINGS,
                ::std::mem::size_of::<QUIC_SETTINGS>() as u32,
            ),
            None => (std::ptr::null(), 0),
        };

        let status = unsafe {
            Api::ffi_ref().ConfigurationOpen.unwrap()(
                registration.as_raw(),
                alpn.as_ptr() as *const QUIC_BUFFER,
                alpn.len() as u32,
                settings_ptr,
                settings_size,
                context,
                std::ptr::addr_of_mut!(new_configuration),
            )
        };
        Status::ok_from_raw(status)?;
        Ok(Configuration {
            handle: new_configuration,
        })
    }

    pub fn load_credential(&self, cred_config: &CredentialConfig) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ConfigurationLoadCredential.unwrap()(
                self.handle,
                &cred_config.as_ffi() as *const QUIC_CREDENTIAL_CONFIG,
            )
        };
        Status::ok_from_raw(status)
    }

    fn close_inner(&self) {
        if !self.handle.is_null() {
            unsafe { Api::ffi_ref().ConfigurationClose.unwrap()(self.handle) };
        }
    }
}

define_quic_handle_impl!(Configuration);

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

// Remarks on Rust callback in general:
// Callback function or closure is set to msquic handle context of type `*mut Box<TCallback>>`.
// We cannot use type `*mut TCallback` because dyn trait cannot be converted to a pointer directly.
// In the ffi function passed to msquic, the TCallback is extracted from msquic callback context
// and invoked.
// The context is cleaned up when connection is dropped or when new callback is set.
// TCallback type is either Fn or FnMut type, so user can capture variables in them without worrying
// about lifetime and how to set or cleanup msquic callback context.

/// Connection callback type.
/// msquic never invokes the connection callback in parallel, so use FnMut to allow mutation.
type ConnectionCallback = dyn FnMut(ConnectionRef, ConnectionEvent) -> Result<(), Status> + 'static;

extern "C" fn raw_conn_callback(
    connection: HQUIC,
    context: *mut c_void,
    event: *mut ffi::QUIC_CONNECTION_EVENT,
) -> QUIC_STATUS {
    let conn = unsafe { ConnectionRef::from_raw(connection) };
    let f = unsafe {
        (context as *mut Box<ConnectionCallback>)
            .as_mut() // allow mutation
            .expect("cannot get ConnectionCallback from ctx")
    };
    let event = ConnectionEvent::from(unsafe { event.as_ref().unwrap() });
    match f(conn, event) {
        Ok(_) => StatusCode::QUIC_STATUS_SUCCESS.into(),
        Err(e) => e.0,
    }
}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            handle: ptr::null_mut(),
        }
    }

    pub fn open<F>(&mut self, registration: &Registration, handler: F) -> Result<(), Status>
    where
        F: FnMut(ConnectionRef, ConnectionEvent) -> Result<(), Status> + 'static,
    {
        // double boxing to allow Box dyn fat pointer
        let b: Box<Box<ConnectionCallback>> = Box::new(Box::new(handler));
        let ctx = Box::into_raw(b);
        self.consume_callback_ctx();
        let status = unsafe {
            Api::ffi_ref().ConnectionOpen.unwrap()(
                registration.handle,
                Some(raw_conn_callback),
                ctx as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status).inspect_err(|_| {
            // attach memory back on failure
            let _ = unsafe { Box::from_raw(ctx) };
        })
    }

    pub fn start(
        &self,
        configuration: &Configuration,
        server_name: &str,
        server_port: u16,
    ) -> Result<(), Status> {
        let server_name_safe = std::ffi::CString::new(server_name).unwrap();
        let status = unsafe {
            Api::ffi_ref().ConnectionStart.unwrap()(
                self.handle,
                configuration.handle,
                0,
                server_name_safe.as_ptr(),
                server_port,
            )
        };
        Status::ok_from_raw(status)
    }

    fn close_inner(&self) {
        if !self.handle.is_null() {
            // get the context and drop it after handle close.
            let ctx = unsafe { self.get_callback_ctx() };
            unsafe {
                Api::ffi_ref().ConnectionClose.unwrap()(self.handle);
                self.set_context(std::ptr::null_mut());
            }
            // Drop call here is required to prevent compiler drop it early.
            // During handle close the ctx might still be used.
            std::mem::drop(ctx);
        }
    }

    pub fn shutdown(&self, flags: ConnectionShutdownFlags, error_code: u62) {
        unsafe {
            Api::ffi_ref().ConnectionShutdown.unwrap()(
                self.handle,
                flags as crate::ffi::QuicFlag,
                error_code,
            );
        }
    }

    /// TODO: provide safe wrapper for ffi
    pub fn get_stats(&self) -> Result<crate::ffi::QUIC_STATISTICS, Status> {
        unsafe { Api::get_param_auto(self.handle, crate::ffi::QUIC_PARAM_CONN_STATISTICS) }
    }

    /// TODO: provide safe wrapper for ffi
    pub fn get_stats_v2(&self) -> Result<crate::ffi::QUIC_STATISTICS_V2, Status> {
        unsafe { Api::get_param_auto(self.handle, PARAM_CONN_STATISTICS_V2) }
    }

    pub fn set_configuration(&self, configuration: &Configuration) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ConnectionSetConfiguration.unwrap()(self.handle, configuration.handle)
        };
        Status::ok_from_raw(status)
    }

    pub fn set_callback_handler<F>(&self, handler: F)
    where
        F: FnMut(ConnectionRef, ConnectionEvent) -> Result<(), Status> + 'static,
    {
        let b: Box<Box<ConnectionCallback>> = Box::new(Box::new(handler));
        let ctx = Box::into_raw(b);
        // clear previous ctx before setting it.
        self.consume_callback_ctx();
        unsafe {
            Api::set_callback_handler(
                self.handle,
                raw_conn_callback as *const c_void,
                ctx as *mut c_void,
            )
        }
    }

    /// # Safety
    /// buffers memory needs to be valid until callback
    /// [ConnectionEvent::DatagramSendStateChanged]
    /// is delivered.
    /// One can optionally pass client_send_context along
    /// and get it back in the callback.
    pub unsafe fn datagram_send(
        &self,
        buffers: &[BufferRef],
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().DatagramSend.unwrap()(
                self.handle,
                buffers.as_ptr() as *const QUIC_BUFFER,
                buffers.len() as u32,
                flags as crate::ffi::QuicFlag,
                client_send_context as *mut c_void,
            )
        };
        Status::ok_from_raw(status)
    }

    pub fn resumption_ticket_validation_complete(&self, result: BOOLEAN) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref()
                .ConnectionResumptionTicketValidationComplete
                .unwrap()(self.handle, result)
        };
        Status::ok_from_raw(status)
    }

    pub fn certificate_validation_complete(
        &self,
        result: BOOLEAN,
        tls_alert: TlsAlertCode,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref()
                .ConnectionCertificateValidationComplete
                .unwrap()(self.handle, result, tls_alert as crate::ffi::QuicFlag)
        };
        Status::ok_from_raw(status)
    }

    pub fn get_local_addr(&self) -> Result<Addr, Status> {
        unsafe { Api::get_param_auto(self.handle, crate::ffi::QUIC_PARAM_CONN_LOCAL_ADDRESS) }
    }

    pub fn get_remote_addr(&self) -> Result<Addr, Status> {
        unsafe { Api::get_param_auto(self.handle, crate::ffi::QUIC_PARAM_CONN_REMOTE_ADDRESS) }
    }
}

define_quic_handle_impl!(Connection);
define_quic_handle_ref!(Connection, ConnectionRef);
define_quic_handle_ctx_fn!(Connection, ConnectionCallback);

impl Default for Listener {
    fn default() -> Self {
        Self::new()
    }
}

/// Listener callback.
/// msquic may execute listener callback in parallel,
/// so Fn is used for immutability.
pub type ListenerCallback = dyn Fn(ListenerRef, ListenerEvent) -> Result<(), Status> + 'static;

extern "C" fn raw_listener_callback(
    listener: HQUIC,
    context: *mut c_void,
    event: *mut ffi::QUIC_LISTENER_EVENT,
) -> QUIC_STATUS {
    let listner_ref = unsafe { ListenerRef::from_raw(listener) };
    let event = ListenerEvent::from(unsafe { event.as_ref().expect("fail to get listener event") });
    let f = unsafe {
        (context as *mut Box<ListenerCallback>)
            .as_ref() // allow mutation
            .expect("cannot get ListenerCallback from ctx")
    };
    match f(listner_ref, event) {
        Ok(_) => StatusCode::QUIC_STATUS_SUCCESS.into(),
        Err(e) => e.0,
    }
}

impl Listener {
    pub fn new() -> Listener {
        Listener {
            handle: ptr::null_mut(),
        }
    }

    pub fn open<F>(&mut self, registration: &Registration, handler: F) -> Result<(), Status>
    where
        F: Fn(ListenerRef, ListenerEvent) -> Result<(), Status> + 'static,
    {
        // double boxing to allow Box dyn fat pointer
        let b: Box<Box<ListenerCallback>> = Box::new(Box::new(handler));
        let ctx = Box::into_raw(b);
        self.consume_callback_ctx();
        let status = unsafe {
            Api::ffi_ref().ListenerOpen.unwrap()(
                registration.handle,
                Some(raw_listener_callback),
                ctx as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status).inspect_err(|_| {
            let _ = unsafe { Box::from_raw(ctx) };
        })
    }

    pub fn start(&self, alpn: &[BufferRef], local_address: Option<&Addr>) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ListenerStart.unwrap()(
                self.handle,
                alpn.as_ptr() as *const QUIC_BUFFER,
                alpn.len() as u32,
                local_address
                    .map(|addr| addr as *const Addr as *const _)
                    .unwrap_or(ptr::null()),
            )
        };
        Status::ok_from_raw(status)
    }

    pub fn stop(&self) {
        unsafe {
            Api::ffi_ref().ListenerStop.unwrap()(self.handle);
        }
    }

    pub fn get_local_addr(&self) -> Result<Addr, Status> {
        unsafe { Api::get_param_auto(self.handle, crate::ffi::QUIC_PARAM_LISTENER_LOCAL_ADDRESS) }
    }

    fn close_inner(&self) {
        if !self.handle.is_null() {
            // consume the context and drop it after handle close.
            let ctx = unsafe { self.get_callback_ctx() };
            unsafe {
                Api::ffi_ref().ListenerClose.unwrap()(self.handle);
                self.set_context(std::ptr::null_mut());
            }
            std::mem::drop(ctx);
        }
    }
}

define_quic_handle_impl!(Listener);
define_quic_handle_ref!(Listener, ListenerRef);
define_quic_handle_ctx_fn!(Listener, ListenerCallback);

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// Stream callback.
/// msquic never executes stream callback on the same stream in parallel.
pub type StreamCallback = dyn FnMut(StreamRef, StreamEvent) -> Result<(), Status> + 'static;

extern "C" fn raw_stream_callback(
    stream: HQUIC,
    context: *mut c_void,
    event: *mut ffi::QUIC_STREAM_EVENT,
) -> QUIC_STATUS {
    let f = unsafe {
        (context as *mut Box<StreamCallback>)
            .as_mut() // allow mutation
            .expect("cannot get ConnectionCallback from ctx")
    };
    let stream_ref = unsafe { StreamRef::from_raw(stream) };
    let event = StreamEvent::from(unsafe { event.as_mut().expect("cannot get event ref") });
    match f(stream_ref, event) {
        Ok(_) => StatusCode::QUIC_STATUS_SUCCESS.into(),
        Err(e) => e.0,
    }
}

impl Stream {
    pub fn new() -> Stream {
        Stream {
            handle: ptr::null_mut(),
        }
    }

    pub fn open<F>(
        &mut self,
        connection: &Connection,
        flags: StreamOpenFlags,
        handler: F,
    ) -> Result<(), Status>
    where
        F: FnMut(StreamRef, StreamEvent) -> Result<(), Status> + 'static,
    {
        let b: Box<Box<StreamCallback>> = Box::new(Box::new(handler));
        let ctx = Box::into_raw(b);
        self.consume_callback_ctx();
        let status = unsafe {
            Api::ffi_ref().StreamOpen.unwrap()(
                connection.handle,
                flags as crate::ffi::QuicFlag,
                Some(raw_stream_callback),
                ctx as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status).inspect_err(|_| {
            let _ = unsafe { Box::from_raw(ctx) };
        })
    }

    pub fn start(&self, flags: StreamStartFlags) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().StreamStart.unwrap()(self.handle, flags as crate::ffi::QuicFlag)
        };
        Status::ok_from_raw(status)
    }

    pub fn shutdown(&self, flags: StreamShutdownFlags, error_code: u62) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().StreamShutdown.unwrap()(
                self.handle,
                flags as crate::ffi::QuicFlag,
                error_code,
            )
        };
        Status::ok_from_raw(status)
    }

    pub fn close_inner(&self) {
        if !self.handle.is_null() {
            // consume the context and drop it after handle close.
            let ctx = unsafe { self.get_callback_ctx() };
            unsafe {
                Api::ffi_ref().StreamClose.unwrap()(self.handle);
                self.set_context(std::ptr::null_mut());
            }
            std::mem::drop(ctx);
        }
    }

    /// # Safety
    /// buffers memory needs to be valid until callback
    /// [StreamEvent::SendComplete]
    /// is delivered.
    /// One can optionally pass client_send_context along
    /// and get it back in the callback.
    pub unsafe fn send(
        &self,
        buffers: &[BufferRef],
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().StreamSend.unwrap()(
                self.handle,
                buffers.as_ptr() as *const QUIC_BUFFER,
                buffers.len() as u32,
                flags as crate::ffi::QuicFlag,
                client_send_context as *mut c_void,
            )
        };
        Status::ok_from_raw(status)
    }

    pub fn set_callback_handler<F>(&self, handler: F)
    where
        F: FnMut(StreamRef, StreamEvent) -> Result<(), Status> + 'static,
    {
        let b: Box<Box<StreamCallback>> = Box::new(Box::new(handler));
        let ctx = Box::into_raw(b);
        // clear previous ctx before setting it.
        self.consume_callback_ctx();
        unsafe {
            Api::set_callback_handler(
                self.handle,
                raw_stream_callback as *const c_void,
                ctx as *mut c_void,
            )
        };
    }

    pub fn receive_complete(&self, buffer_length: u64) {
        unsafe { Api::ffi_ref().StreamReceiveComplete.unwrap()(self.handle, buffer_length) }
    }
}

define_quic_handle_impl!(Stream);
define_quic_handle_ref!(Stream, StreamRef);
define_quic_handle_ctx_fn!(Stream, StreamCallback);

#[cfg(test)]
mod tests {

    //
    // The following defines some simple test code.
    //

    use crate::{
        BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, CredentialConfig,
        Registration, RegistrationConfig, Settings, Status, Stream, StreamEvent, StreamRef,
    };

    fn test_conn_callback(connection: ConnectionRef, event: ConnectionEvent) -> Result<(), Status> {
        match event {
            ConnectionEvent::Connected {
                session_resumed,
                negotiated_alpn,
            } => {
                let local_addr = connection.get_local_addr().unwrap().as_socket().unwrap();
                let remote_addr = connection.get_remote_addr().unwrap().as_socket().unwrap();
                let alpn = String::from_utf8_lossy(negotiated_alpn);
                println!("Connected({local_addr}, {remote_addr}), session_resumed:{session_resumed}, negotiated_alpn:{alpn}");
            }
            ConnectionEvent::ShutdownInitiatedByTransport { status, error_code } => {
                println!("Transport shutdown {status}, {error_code}")
            }
            ConnectionEvent::ShutdownInitiatedByPeer { error_code } => {
                println!("App shutdown {error_code}")
            }
            ConnectionEvent::ShutdownComplete {
                handshake_completed,
                peer_acknowledged_shutdown,
                app_close_in_progress,
            } => {
                println!("Shutdown complete: {handshake_completed}, {peer_acknowledged_shutdown}, {app_close_in_progress}")
            }
            ConnectionEvent::LocalAddressChanged { address } => {
                println!("Local address changed: {:?}", address.as_socket().unwrap())
            }
            ConnectionEvent::PeerAddressChanged { address } => {
                println!("Peer address changed: {:?}", address.as_socket().unwrap())
            }
            ConnectionEvent::PeerStreamStarted { stream, flags } => {
                println!("Peer stream started: flags: {flags}");
                stream.set_callback_handler(test_stream_callback)
            }
            ConnectionEvent::StreamsAvailable {
                bidirectional_count,
                unidirectional_count,
            } => {
                println!(
                    "Streams available: bi: {bidirectional_count}, uni: {unidirectional_count}"
                )
            }
            ConnectionEvent::PeerNeedsStreams { bidirectional } => {
                println!("Peer needs streams: bi: {bidirectional}");
            }
            _ => println!("Connection other callback ?",),
        }
        Ok(())
    }

    fn test_stream_callback(stream: StreamRef, event: StreamEvent) -> Result<(), Status> {
        match event {
            StreamEvent::StartComplete {
                status,
                id,
                peer_accepted,
            } => {
                println!("Stream start complete: {status}, {id}, {peer_accepted}");
            }
            StreamEvent::Receive {
                absolute_offset,
                total_buffer_length,
                buffers: _,
                flags: _,
            } => {
                println!("Stream receive: {absolute_offset}, {total_buffer_length}");
            }
            StreamEvent::SendComplete {
                cancelled,
                client_context: _,
            } => {
                println!("Stream send complete: {cancelled}");
            }
            StreamEvent::PeerSendShutdown => {
                println!("Stream peer send shutdown");
            }
            StreamEvent::PeerSendAborted { error_code } => {
                println!("Stream peer send abort: {error_code}");
            }
            StreamEvent::PeerReceiveAborted { error_code } => {
                println!("Stream peer receive aborted: {error_code}");
            }
            StreamEvent::SendShutdownComplete { graceful } => {
                println!("Stream send shutdown complete: {graceful}");
            }
            StreamEvent::ShutdownComplete {
                connection_shutdown,
                app_close_in_progress,
                connection_shutdown_by_app,
                connection_closed_remotely,
                connection_error_code,
                connection_close_status,
            } => {
                println!("Stream shutdown complete: {connection_shutdown} {app_close_in_progress} {connection_shutdown_by_app} {connection_closed_remotely} {connection_error_code} {connection_close_status}");
                // Attach to stream for auto close handle.
                unsafe { Stream::from_raw(stream.as_raw()) };
            }
            StreamEvent::IdealSendBufferSize { byte_count } => {
                println!("Stream ideal send buffer size: {byte_count}");
            }
            StreamEvent::PeerAccepted => {
                println!("Stream peer accepted.");
            }
            StreamEvent::CancelOnLoss { error_code } => {
                println!("Stream cancel on loss: {error_code}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_module() {
        let res = Registration::new(&RegistrationConfig::default());
        assert!(
            res.is_ok(),
            "Failed to open registration: {}",
            res.err().unwrap()
        );
        let registration = res.unwrap();

        // check global settings
        {
            let retry_memory_percent =
                crate::Api::get_retry_memory_percent().expect("fail to get retry memory percent");
            assert!(retry_memory_percent > 0);
            let _tls_provider = crate::Api::get_tls_provider().expect("fail to get tls provider");
        }

        let alpn = [BufferRef::from("h3")];
        let settings = Settings::new()
            .set_PeerBidiStreamCount(100)
            .set_PeerUnidiStreamCount(3);
        #[cfg(feature = "preview-api")]
        let settings = settings.set_StreamMultiReceiveEnabled();
        let res = Configuration::new(&registration, &alpn, Some(&settings));
        assert!(
            res.is_ok(),
            "Failed to open configuration: {}",
            res.err().unwrap()
        );
        let configuration = res.unwrap();

        let cred_config = CredentialConfig::new_client();
        let res = configuration.load_credential(&cred_config);
        assert!(
            res.is_ok(),
            "Failed to load credential: {}",
            res.err().unwrap()
        );

        let mut connection = Connection::new();
        let res = connection.open(&registration, test_conn_callback);
        assert!(
            res.is_ok(),
            "Failed to open connection: {}",
            res.err().unwrap()
        );

        let res = connection.start(&configuration, "www.cloudflare.com", 443);
        assert!(
            res.is_ok(),
            "Failed to start connection: {}",
            res.err().unwrap()
        );

        // check getting addr params are ok.
        {
            let local_addr = connection
                .get_local_addr()
                .expect("cannot get local addr")
                .as_socket()
                .unwrap();
            let remove_addr = connection
                .get_remote_addr()
                .expect("cannot get local addr")
                .as_socket()
                .unwrap();
            println!("Connection local addr {local_addr}, remote addr {remove_addr}");
        }

        let duration = std::time::Duration::from_millis(1000);
        std::thread::sleep(duration);

        // check get stats ok
        {
            let stats = connection.get_stats().expect("fail to get stats");
            assert!(stats.Recv.TotalBytes > 0);

            let stats2 = connection.get_stats_v2().expect("fail to get stats v2");
            assert!(stats2.RecvTotalBytes > 0);
        }
        // check perf counters.
        {
            let perf = crate::Api::get_perf().unwrap();
            assert!(perf.conn_created > 0);
            assert!(perf.strm_active > 0);
        }
    }
}

// test certs are only installed on windows
#[cfg(target_os = "windows")]
#[cfg(test)]
mod server_client_test;
