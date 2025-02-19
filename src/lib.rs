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
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::option::Option;
use std::ptr;
use std::result::Result;
use std::sync::Once;
#[macro_use]
extern crate bitfield;
mod error;
pub mod ffi;
pub use error::{Status, StatusCode};
mod types;
pub use types::ConnectionEvent;

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

/// Configures how to process a registration's workload.
pub type ExecutionProfile = u32;
pub const EXECUTION_PROFILE_LOW_LATENCY: ExecutionProfile = 0;
pub const EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT: ExecutionProfile = 1;
pub const EXECUTION_PROFILE_TYPE_SCAVENGER: ExecutionProfile = 2;
pub const EXECUTION_PROFILE_TYPE_REAL_TIME: ExecutionProfile = 3;

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

/// Type of credentials used for a connection.
pub type CredentialType = u32;
pub const CREDENTIAL_TYPE_NONE: CredentialType = 0;
pub const CREDENTIAL_TYPE_CERTIFICATE_HASH: CredentialType = 1;
pub const CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE: CredentialType = 2;
pub const CREDENTIAL_TYPE_CERTIFICATE_CONTEXT: CredentialType = 3;
pub const CREDENTIAL_TYPE_CERTIFICATE_FILE: CredentialType = 4;
pub const CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED: CredentialType = 5;
pub const CREDENTIAL_TYPE_CERTIFICATE_PKCS12: CredentialType = 6;

/// Modifies the default credential configuration.
pub type CredentialFlags = u32;
pub const CREDENTIAL_FLAG_NONE: CredentialFlags = 0;
pub const CREDENTIAL_FLAG_CLIENT: CredentialFlags = 1;
pub const CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS: CredentialFlags = 2;
pub const CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION: CredentialFlags = 4;
pub const CREDENTIAL_FLAG_ENABLE_OCSP: CredentialFlags = 8;
pub const CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED: CredentialFlags = 16;
pub const CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION: CredentialFlags = 32;
pub const CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION: CredentialFlags = 64;
pub const CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION: CredentialFlags = 128;
pub const CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT: CredentialFlags = 256;
pub const CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN: CredentialFlags = 512;
pub const CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: CredentialFlags = 1024;
pub const CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK: CredentialFlags = 2048;
pub const CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE: CredentialFlags = 4096;
pub const CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES: CredentialFlags = 8192;
pub const CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES: CredentialFlags = 16384;
pub const CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS: CredentialFlags = 32768;
pub const CREDENTIAL_FLAG_USE_SYSTEM_MAPPER: CredentialFlags = 65536;
pub const CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL: CredentialFlags = 131072;
pub const CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY: CredentialFlags = 262144;

/// Set of allowed TLS cipher suites.
pub type AllowedCipherSuiteFlags = u32;
pub const ALLOWED_CIPHER_SUITE_NONE: AllowedCipherSuiteFlags = 0;
pub const ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256: AllowedCipherSuiteFlags = 1;
pub const ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384: AllowedCipherSuiteFlags = 2;
pub const ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256: AllowedCipherSuiteFlags = 4;

/// Modifies the default certificate hash store configuration.
pub type CertificateHashStoreFlags = u32;
pub const CERTIFICATE_HASH_STORE_FLAG_NONE: CertificateHashStoreFlags = 0;
pub const CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE: CertificateHashStoreFlags = 1;

/// Controls connection shutdown behavior.
pub type ConnectionShutdownFlags = u32;
pub const CONNECTION_SHUTDOWN_FLAG_NONE: ConnectionShutdownFlags = 0;
pub const CONNECTION_SHUTDOWN_FLAG_SILENT: ConnectionShutdownFlags = 1;

/// Type of resumption behavior on the server side.
pub type ServerResumptionLevel = u32;
pub const SERVER_NO_RESUME: ServerResumptionLevel = 0;
pub const SERVER_RESUME_ONLY: ServerResumptionLevel = 1;
pub const SERVER_RESUME_AND_ZERORTT: ServerResumptionLevel = 2;

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

/// Specifies the configuration for a new registration.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RegistrationConfig {
    pub app_name: *const i8,
    pub execution_profile: ExecutionProfile,
}

/// Completion callback for a async creation of a new credential.
pub type CredentialLoadComplete =
    extern "C" fn(configuration: HQUIC, context: *const c_void, status: u64);

/// The 20-byte hash/thumbprint of a certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateHash {
    pub sha_hash: [u8; 20usize],
}

/// The 20-byte hash/thumbprint and store name of a certificate.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CertificateHashStore {
    pub flags: CertificateHashStoreFlags,
    pub sha_hash: [u8; 20usize],
    pub store_name: [i8; 128usize],
}

/// The file paths of a certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateFile {
    pub private_key_file: *const i8,
    pub certificate_file: *const i8,
}

/// The file paths of a protected certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateFileProtected {
    pub private_key_file: *const i8,
    pub certificate_file: *const i8,
    pub private_key_password: *const i8,
}

/// The binary blobs of a PKCS#12 certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificatePkcs12 {
    pub ans1_blob: *const u8,
    pub ans1_blob_length: u32,
    pub private_key_password: *const i8,
}

/// Generic interface for a certificate.
pub type Certificate = c_void;

/// Generic interface for a certificate chain.
pub type CertificateChain = c_void;

/// Wrapper for all certificate types.
#[repr(C)]
#[derive(Copy, Clone)]
pub union CertificateUnion {
    pub hash: *const CertificateHash,
    pub hash_store: *const CertificateHashStore,
    pub context: *const Certificate,
    pub file: *const CertificateFile,
    pub file_protected: *const CertificateFileProtected,
    pub pkcs12: *const CertificatePkcs12,
}

/// Specifies the configuration for a new credential.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CredentialConfig {
    pub cred_type: CredentialType,
    pub cred_flags: CredentialFlags,
    pub certificate: CertificateUnion,
    pub principle: *const i8,
    pub reserved: *const c_void,
    pub async_handler: Option<CredentialLoadComplete>,
    pub allowed_cipher_suites: AllowedCipherSuiteFlags,
}

/// Key information for TLS session ticket encryption.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TicketKeyConfig {
    pub id: [u8; 16usize],
    pub material: [u8; 64usize],
    pub material_length: u8,
}

/// A generic wrapper for contiguous buffer.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Buffer {
    pub length: u32,
    pub buffer: *mut u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NewConnectionInfo {
    pub quic_version: u32,
    pub local_address: *const Addr,
    pub remote_address: *const Addr,
    pub crypto_buffer_length: u32,
    pub client_alpn_list_length: u16,
    pub server_name_length: u16,
    pub negotiated_alpn_length: u8,
    pub crypto_buffer: *const u8,
    pub client_alpn_list: *const u8,
    pub negotiated_alpn: *const u8,
    pub server_name: *const i8,
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

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsTiming {
    pub start: u64,
    /// Processed all peer's Initial packets
    pub start_flight_end: u64,
    /// Processed all peer's Handshake packets
    pub handshake_fligh_end: u64,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsHandshake {
    /// Sum of TLS payloads
    pub client_flight_1_bytes: u32,
    /// Sum of TLS payloads
    pub server_flight_1_bytes: u32,
    /// Sum of TLS payloads
    pub client_flight_2_bytes: u32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsSend {
    /// Current path MTU.
    pub path_mtu: u16,
    /// QUIC packets; could be coalesced into fewer UDP datagrams.
    pub total_packets: u64,
    pub retransmittable_packets: u64,
    pub suspected_lost_packets: u64,
    /// Actual lost is (suspected_lost_packets - spurious_lost_packets)
    pub spurious_lost_packets: u64,
    /// Sum of UDP payloads
    pub total_bytes: u64,
    /// Sum of stream payloads
    pub total_stream_bytes: u64,
    /// Number of congestion events
    pub congestion_count: u32,
    /// Number of persistent congestion events
    pub persistent_congestion_count: u32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsRecv {
    /// QUIC packets; could be coalesced into fewer UDP datagrams.
    pub total_packets: u64,
    /// Packets where packet number is less than highest seen.
    pub reordered_packets: u64,
    /// Includes DuplicatePackets.
    pub dropped_packets: u64,
    pub duplicate_packets: u64,
    /// Sum of UDP payloads
    pub total_bytes: u64,
    /// Sum of stream payloads
    pub total_stream_bytes: u64,
    /// Count of packet decryption failures.
    pub decryption_failures: u64,
    /// Count of receive ACK frames.
    pub valid_ack_frames: u64,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsMisc {
    pub key_update_count: u32,
}

bitfield! {
    #[repr(C)]
    #[derive(Serialize, Deserialize, Clone, Copy)]
    pub struct QuicStatisticsBitfields(u32);
    // The fields default to u32
    version_negotiation, _: 1, 0;
    stateless_retry, _: 1, 1;
    resumption_attempted, _: 1, 2;
    resumption_succeeded, _: 1, 3;
    grease_bit_negotiated, _: 1, 4;
}

/// Implementation of Debug for formatting the QuicStatisticsBitfields struct.
/// This is implemented manually because the derived implementation by the bitfield macro
/// has been observed to cause panic.
impl fmt::Debug for QuicStatisticsBitfields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:#06x}", &self.0))
    }
}

/// A helper struct for accessing connection statistics
#[repr(C)]
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct QuicStatistics {
    correlation_id: u64,
    pub flags: QuicStatisticsBitfields,
    /// In microseconds
    pub rtt: u32,
    /// In microseconds
    pub min_rtt: u32,
    /// In microseconds
    pub max_rtt: u32,
    pub timing: QuicStatisticsTiming,
    pub handshake: QuicStatisticsHandshake,
    pub send: QuicStatisticsSend,
    pub recv: QuicStatisticsRecv,
    pub misc: QuicStatisticsMisc,
}

/// A helper struct for accessing connection statistics
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct QuicStatisticsV2 {
    correlation_id: u64,
    pub flags: QuicStatisticsBitfields,
    /// In microseconds
    pub rtt: u32,
    /// In microseconds
    pub min_rtt: u32,
    /// In microseconds
    pub max_rtt: u32,

    pub timing_start: u64,
    /// Processed all peer's Initial packets
    pub timing_start_flight_end: u64,
    /// Processed all peer's Handshake packets
    pub timing_handshake_fligh_end: u64,

    /// Sum of TLS payloads
    pub handshake_client_flight_1_bytes: u32,
    /// Sum of TLS payloads
    pub handshake_server_flight_1_bytes: u32,
    /// Sum of TLS payloads
    pub handshake_client_flight_2_bytes: u32,

    /// Current path MTU.
    pub send_path_mtu: u16,
    /// QUIC packets; could be coalesced into fewer UDP datagrams.
    pub send_total_packets: u64,
    pub send_retransmittable_packets: u64,
    pub send_suspected_lost_packets: u64,
    /// Actual lost is (suspected_lost_packets - spurious_lost_packets)
    pub send_spurious_lost_packets: u64,
    /// Sum of UDP payloads
    pub send_total_bytes: u64,
    /// Sum of stream payloads
    pub send_total_stream_bytes: u64,
    /// Number of congestion events
    pub send_congestion_count: u32,
    /// Number of persistent congestion events
    pub send_persistent_congestion_count: u32,

    /// QUIC packets; could be coalesced into fewer UDP datagrams.
    pub recv_total_packets: u64,
    /// Packets where packet number is less than highest seen.
    pub recv_reordered_packets: u64,
    /// Includes DuplicatePackets.
    pub recv_dropped_packets: u64,
    pub recv_duplicate_packets: u64,
    /// Sum of UDP payloads
    pub recv_total_bytes: u64,
    /// Sum of stream payloads
    pub recv_total_stream_bytes: u64,
    /// Count of packet decryption failures.
    pub recv_decryption_failures: u64,
    /// Count of receive ACK frames.
    pub recv_valid_ack_frames: u64,

    pub key_update_count: u32,

    pub send_congestion_window: u32,
    // Number of times the destination CID changed.
    pub dest_cid_update_count: u32,
}

/// A helper struct for accessing listener statistics.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QuicListenerStatistics {
    pub total_accepted_connections: u64,
    pub total_rejected_connections: u64,
    pub binding: u64,
}

/// A helper struct for accessing performance counters.
pub struct QuicPerformance {
    pub counters: [i64; PERF_COUNTER_MAX as usize],
}

pub type PerformanceCounter = u32;
pub const PERF_COUNTER_CONN_CREATED: PerformanceCounter = 0;
pub const PERF_COUNTER_CONN_HANDSHAKE_FAIL: PerformanceCounter = 1;
pub const PERF_COUNTER_CONN_APP_REJECT: PerformanceCounter = 2;
pub const PERF_COUNTER_CONN_RESUMED: PerformanceCounter = 3;
pub const PERF_COUNTER_CONN_ACTIVE: PerformanceCounter = 4;
pub const PERF_COUNTER_CONN_CONNECTED: PerformanceCounter = 5;
pub const PERF_COUNTER_CONN_PROTOCOL_ERRORS: PerformanceCounter = 6;
pub const PERF_COUNTER_CONN_NO_ALPN: PerformanceCounter = 7;
pub const PERF_COUNTER_STRM_ACTIVE: PerformanceCounter = 8;
pub const PERF_COUNTER_PKTS_SUSPECTED_LOST: PerformanceCounter = 9;
pub const PERF_COUNTER_PKTS_DROPPED: PerformanceCounter = 10;
pub const PERF_COUNTER_PKTS_DECRYPTION_FAIL: PerformanceCounter = 11;
pub const PERF_COUNTER_UDP_RECV: PerformanceCounter = 12;
pub const PERF_COUNTER_UDP_SEND: PerformanceCounter = 13;
pub const PERF_COUNTER_UDP_RECV_BYTES: PerformanceCounter = 14;
pub const PERF_COUNTER_UDP_SEND_BYTES: PerformanceCounter = 15;
pub const PERF_COUNTER_UDP_RECV_EVENTS: PerformanceCounter = 16;
pub const PERF_COUNTER_UDP_SEND_CALLS: PerformanceCounter = 17;
pub const PERF_COUNTER_APP_SEND_BYTES: PerformanceCounter = 18;
pub const PERF_COUNTER_APP_RECV_BYTES: PerformanceCounter = 19;
pub const PERF_COUNTER_CONN_QUEUE_DEPTH: PerformanceCounter = 20;
pub const PERF_COUNTER_CONN_OPER_QUEUE_DEPTH: PerformanceCounter = 21;
pub const PERF_COUNTER_CONN_OPER_QUEUED: PerformanceCounter = 22;
pub const PERF_COUNTER_CONN_OPER_COMPLETED: PerformanceCounter = 23;
pub const PERF_COUNTER_WORK_OPER_QUEUE_DEPTH: PerformanceCounter = 24;
pub const PERF_COUNTER_WORK_OPER_QUEUED: PerformanceCounter = 25;
pub const PERF_COUNTER_WORK_OPER_COMPLETED: PerformanceCounter = 26;
pub const PERF_COUNTER_MAX: PerformanceCounter = 27;

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

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Settings {
    pub is_set_flags: u64,
    pub max_bytes_per_key: u64,
    pub handshake_idle_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub mtu_discovery_search_complete_timeout_us: u64,
    pub tls_client_max_send_buffer: u32,
    pub tls_server_max_send_buffer: u32,
    pub stream_recv_window_default: u32,
    pub stream_recv_buffer_default: u32,
    pub conn_flow_control_window: u32,
    pub max_worker_queue_delay_us: u32,
    pub max_stateless_operations: u32,
    pub initial_window_packets: u32,
    pub send_idle_timeout_ms: u32,
    pub initiall_rtt_ms: u32,
    pub max_ack_delay_ms: u32,
    pub disconnect_timeout_ms: u32,
    pub keep_alive_interval_ms: u32,
    pub congestion_control_algorithm: u16,
    pub peer_bidi_stream_count: u16,
    pub peer_unidi_stream_count: u16,
    pub max_binding_stateless_operations: u16,
    pub stateless_operation_expiration_ms: u16,
    pub minimum_mtu: u16,
    pub maximum_mtu: u16,
    pub other_flags: u8,
    pub mtu_operations_per_drain: u8,
    pub mtu_discovery_missing_probe_count: u8,
    pub dest_cid_update_idle_timeout_ms: u32,
    pub other2_flags: u64,
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

pub type ListenerEventType = u32;
pub const LISTENER_EVENT_NEW_CONNECTION: ListenerEventType = 0;
pub const LISTENER_EVENT_STOP_COMPLETE: ListenerEventType = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListenerEventNewConnection {
    pub info: *const NewConnectionInfo,
    pub connection: HQUIC,
}

bitfield! {
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ListenerEventStopCompleteBitfields(u8);
    // The fields default to u8
    pub app_close_in_progress, _: 0, 0;
    _reserved, _: 7, 1;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListenerEventStopComplete {
    pub bit_flags: ListenerEventStopCompleteBitfields,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ListenerEventPayload {
    pub new_connection: ListenerEventNewConnection,
    pub stop_complete: ListenerEventStopComplete,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListenerEvent {
    pub event_type: ListenerEventType,
    pub payload: ListenerEventPayload,
}

pub type StreamEventType = u32;
pub const STREAM_EVENT_START_COMPLETE: StreamEventType = 0;
pub const STREAM_EVENT_RECEIVE: StreamEventType = 1;
pub const STREAM_EVENT_SEND_COMPLETE: StreamEventType = 2;
pub const STREAM_EVENT_PEER_SEND_SHUTDOWN: StreamEventType = 3;
pub const STREAM_EVENT_PEER_SEND_ABORTED: StreamEventType = 4;
pub const STREAM_EVENT_PEER_RECEIVE_ABORTED: StreamEventType = 5;
pub const STREAM_EVENT_SEND_SHUTDOWN_COMPLETE: StreamEventType = 6;
pub const STREAM_EVENT_SHUTDOWN_COMPLETE: StreamEventType = 7;
pub const STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE: StreamEventType = 8;
pub const STREAM_EVENT_PEER_ACCEPTED: StreamEventType = 9;
pub const STREAM_EVENT_CANCEL_ON_LOSS: StreamEventType = 10;

bitfield! {
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct StreamEventStartCompleteBitfields(u8);
    // The fields default to u8
    pub peer_accepted, _: 0, 0;
    _reserved, _: 7, 1;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventStartComplete {
    pub status: u32,
    pub id: u62,
    pub bit_flags: StreamEventStartCompleteBitfields,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventReceive {
    pub absolute_offset: u64,
    pub total_buffer_length: u64,
    pub buffer: *const Buffer,
    pub buffer_count: u32,
    pub flags: ReceiveFlags,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventSendComplete {
    pub canceled: bool,
    pub client_context: *const c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventPeerSendAborted {
    pub error_code: u62,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventPeerReceiveAborted {
    pub error_code: u62,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventSendShutdownComplete {
    pub graceful: bool,
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct StreamEventShutdownCompleteBitfields(u8);
    // The fields default to u8
    pub app_close_in_progress, _: 0, 0;
    pub conn_shutdown_by_app, _: 1, 1;
    pub conn_closed_remotely, _: 2, 2;
    _reserved, _: 7, 3;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct StreamEventShutdownComplete {
    pub connection_shutdown: bool,
    pub bit_flags: StreamEventShutdownCompleteBitfields,
    pub connection_error_code: u62,
    pub connection_close_status: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventIdealSendBufferSize {
    pub byte_count: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventCancelOnLoss {
    pub error_code: u62,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union StreamEventPayload {
    pub start_complete: StreamEventStartComplete,
    pub receive: StreamEventReceive,
    pub send_complete: StreamEventSendComplete,
    pub peer_send_aborted: StreamEventPeerSendAborted,
    pub peer_receive_aborted: StreamEventPeerReceiveAborted,
    pub send_shutdown_complete: StreamEventSendShutdownComplete,
    pub shutdown_complete: StreamEventShutdownComplete,
    pub ideal_send_buffer_size: StreamEventIdealSendBufferSize,
    pub cancel_on_loss: StreamEventCancelOnLoss,
}

#[repr(C)]
pub struct StreamEvent {
    pub event_type: StreamEventType,
    pub payload: StreamEventPayload,
}

pub type StreamEventHandler =
    extern "C" fn(stream: HQUIC, context: *mut c_void, event: &StreamEvent) -> u32;

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
pub struct Connection {
    handle: HQUIC,
}
unsafe impl Sync for Connection {}
unsafe impl Send for Connection {}

/// A single server listener
pub struct Listener {
    handle: HQUIC,
}
unsafe impl Sync for Listener {}
unsafe impl Send for Listener {}

/// A single QUIC stream on a parent connection.
pub struct Stream {
    handle: HQUIC,
}
unsafe impl Sync for Stream {}
unsafe impl Send for Stream {}

/// Same as Stream but does not own the handle.
/// Only used in callback wrapping where handle
/// should not be closed by default.
pub struct StreamRef(Stream);

impl From<&str> for Buffer {
    fn from(data: &str) -> Buffer {
        Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        }
    }
}

impl From<&Vec<u8>> for Buffer {
    fn from(data: &Vec<u8>) -> Buffer {
        Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        }
    }
}

impl From<&[u8]> for Buffer {
    fn from(data: &[u8]) -> Buffer {
        Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(data: Buffer) -> Vec<u8> {
        let mut vec = vec![0; data.length.try_into().unwrap()];
        for index in 0..data.length - 1 {
            vec[index as usize] = unsafe { *data.buffer.offset(index as isize) };
        }
        vec
    }
}

impl QuicPerformance {
    pub fn counter(&self, counter: PerformanceCounter) -> i64 {
        self.counters[counter as usize]
    }
}

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_peer_bidi_stream_count(&mut self, value: u16) -> &mut Settings {
        self.is_set_flags |= 0x40000;
        self.peer_bidi_stream_count = value;
        self
    }
    pub fn set_peer_unidi_stream_count(&mut self, value: u16) -> &mut Settings {
        self.is_set_flags |= 0x80000;
        self.peer_unidi_stream_count = value;
        self
    }
    pub fn set_idle_timeout_ms(&mut self, value: u64) -> &mut Settings {
        self.is_set_flags |= 0x4;
        self.idle_timeout_ms = value;
        self
    }
    pub fn set_datagram_receive_enabled(&mut self, value: bool) -> &mut Settings {
        self.is_set_flags |= 1 << 27;
        self.other_flags |= (value as u8) << 3;
        self
    }
    #[cfg(feature = "preview-api")]
    pub fn set_stream_multi_receive_enabled(&mut self, value: bool) -> &mut Settings {
        self.is_set_flags |= 1 << 42;
        self.other2_flags |= (value as u64) << 5;
        self
    }
}

impl CredentialConfig {
    pub fn new_client() -> CredentialConfig {
        CredentialConfig {
            cred_type: CREDENTIAL_FLAG_NONE,
            cred_flags: CREDENTIAL_FLAG_CLIENT,
            certificate: CertificateUnion {
                context: ptr::null(),
            },
            principle: ptr::null(),
            reserved: ptr::null(),
            async_handler: None,
            allowed_cipher_suites: 0,
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

    pub fn get_perf(&self) -> Result<QuicPerformance, Status> {
        let mut perf = QuicPerformance {
            counters: [0; PERF_COUNTER_MAX as usize],
        };
        let perf_length = std::mem::size_of::<[i64; PERF_COUNTER_MAX as usize]>() as u32;
        unsafe {
            Api::get_param(
                std::ptr::null_mut(),
                PARAM_GLOBAL_PERF_COUNTERS,
                std::ptr::addr_of!(perf_length),
                perf.counters.as_mut_ptr() as *mut c_void,
            )?
        };
        Ok(perf)
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

impl Registration {
    pub fn new(config: *const RegistrationConfig) -> Result<Registration, Status> {
        // Initialize the global api table.
        // Registration is the first created in all msquic apps.
        let api = Api::get_ffi();
        let mut h = std::ptr::null_mut();
        let status = unsafe {
            api.RegistrationOpen.unwrap()(
                config as *const crate::ffi::QUIC_REGISTRATION_CONFIG,
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
        alpn: &[Buffer],
        settings: *const Settings,
    ) -> Result<Configuration, Status> {
        let context: *mut c_void = ptr::null_mut();
        let mut new_configuration: HQUIC = ptr::null_mut();
        let mut settings_size: u32 = 0;
        if !settings.is_null() {
            settings_size = ::std::mem::size_of::<Settings>() as u32;
        }

        let status = unsafe {
            Api::ffi_ref().ConfigurationOpen.unwrap()(
                registration.as_raw(),
                alpn.as_ptr() as *const QUIC_BUFFER,
                alpn.len() as u32,
                settings as *const QUIC_SETTINGS,
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
                cred_config as *const CredentialConfig as *const QUIC_CREDENTIAL_CONFIG,
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

impl Connection {
    pub fn new() -> Connection {
        Connection {
            handle: ptr::null_mut(),
        }
    }

    /// TODO: The handler type should eventually be changed to Fn type.
    /// ffi type and the context ptr makes this function unsafe.
    pub fn open(
        &mut self,
        registration: &Registration,
        handler: ffi::QUIC_CONNECTION_CALLBACK_HANDLER,
        context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ConnectionOpen.unwrap()(
                registration.handle,
                handler,
                context as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status)
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
            unsafe {
                Api::ffi_ref().ConnectionClose.unwrap()(self.handle);
            }
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

    pub fn get_stats(&self) -> Result<QuicStatistics, Status> {
        let mut stat_buffer: [u8; std::mem::size_of::<QuicStatistics>()] =
            [0; std::mem::size_of::<QuicStatistics>()];
        let stat_size_mut = std::mem::size_of::<QuicStatistics>();
        unsafe {
            Api::get_param(
                self.handle,
                PARAM_CONN_STATISTICS,
                (&stat_size_mut) as *const usize as *const u32 as *mut u32,
                stat_buffer.as_mut_ptr() as *mut c_void,
            )
        }?;
        Ok(unsafe { *(stat_buffer.as_ptr() as *const c_void as *const QuicStatistics) })
    }

    pub fn get_stats_v2(&self) -> Result<QuicStatisticsV2, Status> {
        let mut stat_buffer: [u8; std::mem::size_of::<QuicStatisticsV2>()] =
            [0; std::mem::size_of::<QuicStatisticsV2>()];
        let stat_size_mut = std::mem::size_of::<QuicStatisticsV2>();
        unsafe {
            Api::get_param(
                self.handle,
                PARAM_CONN_STATISTICS_V2,
                (&stat_size_mut) as *const usize as *const u32 as *mut u32,
                stat_buffer.as_mut_ptr() as *mut c_void,
            )
        }?;
        Ok(unsafe { *(stat_buffer.as_ptr() as *const c_void as *const QuicStatisticsV2) })
    }

    pub fn set_configuration(&self, configuration: &Configuration) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ConnectionSetConfiguration.unwrap()(self.handle, configuration.handle)
        };
        Status::ok_from_raw(status)
    }

    /// # Safety
    /// handler and context must be valid
    pub unsafe fn set_callback_handler(
        &self,
        handler: ffi::QUIC_CONNECTION_CALLBACK_HANDLER,
        context: *const c_void,
    ) {
        unsafe {
            Api::set_callback_handler(
                self.handle,
                std::mem::transmute::<ffi::QUIC_CONNECTION_CALLBACK_HANDLER, *const c_void>(
                    handler,
                ),
                context,
            )
        };
    }

    pub fn datagram_send(
        &self,
        buffer: &Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().DatagramSend.unwrap()(
                self.handle,
                buffer as *const Buffer as *const QUIC_BUFFER,
                buffer_count,
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
        let mut addr_buffer: [u8; mem::size_of::<Addr>()] = [0; mem::size_of::<Addr>()];
        let addr_size_mut = mem::size_of::<Addr>();
        unsafe {
            Api::get_param(
                self.handle,
                PARAM_CONN_LOCAL_ADDRESS,
                (&addr_size_mut) as *const usize as *const u32 as *mut u32,
                addr_buffer.as_mut_ptr() as *mut c_void,
            )?
        };
        Ok(unsafe { *(addr_buffer.as_ptr() as *const c_void as *const Addr) })
    }

    pub fn get_remote_addr(&self) -> Result<Addr, Status> {
        let mut addr_buffer: [u8; mem::size_of::<Addr>()] = [0; mem::size_of::<Addr>()];
        let addr_size_mut = mem::size_of::<Addr>();
        unsafe {
            Api::get_param(
                self.handle,
                PARAM_CONN_REMOTE_ADDRESS,
                (&addr_size_mut) as *const usize as *const u32 as *mut u32,
                addr_buffer.as_mut_ptr() as *mut c_void,
            )?
        };
        Ok(unsafe { *(addr_buffer.as_ptr() as *const c_void as *const Addr) })
    }
}

define_quic_handle_impl!(Connection);

impl Default for Listener {
    fn default() -> Self {
        Self::new()
    }
}

impl Listener {
    pub fn new() -> Listener {
        Listener {
            handle: ptr::null_mut(),
        }
    }

    /// TODO: handler should be changed to Fn type.
    pub fn open(
        &mut self,
        registration: &Registration,
        handler: ffi::QUIC_LISTENER_CALLBACK_HANDLER,
        context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().ListenerOpen.unwrap()(
                registration.handle,
                handler,
                context as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status)
    }

    pub fn start(&self, alpn: &[Buffer], local_address: Option<&Addr>) -> Result<(), Status> {
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
        let mut addr_buffer: [u8; mem::size_of::<Addr>()] = [0; mem::size_of::<Addr>()];
        let addr_size_mut = mem::size_of::<Addr>();
        unsafe {
            Api::get_param(
                self.handle,
                PARAM_LISTENER_LOCAL_ADDRESS,
                (&addr_size_mut) as *const usize as *const u32 as *mut u32,
                addr_buffer.as_mut_ptr() as *mut c_void,
            )?
        };
        Ok(unsafe { *(addr_buffer.as_ptr() as *const c_void as *const Addr) })
    }

    fn close_inner(&self) {
        if !self.handle.is_null() {
            unsafe {
                Api::ffi_ref().ListenerClose.unwrap()(self.handle);
            }
        }
    }
}

define_quic_handle_impl!(Listener);

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    pub fn new() -> Stream {
        Stream {
            handle: ptr::null_mut(),
        }
    }

    pub fn open(
        &mut self,
        connection: &Connection,
        flags: StreamOpenFlags,
        handler: StreamEventHandler,
        context: *const c_void,
    ) -> Result<(), Status> {
        // TODO: remove transmute.
        #[allow(clippy::missing_transmute_annotations)]
        let status = unsafe {
            Api::ffi_ref().StreamOpen.unwrap()(
                connection.handle,
                flags as crate::ffi::QuicFlag,
                Some(std::mem::transmute(handler)),
                context as *mut c_void,
                std::ptr::addr_of_mut!(self.handle),
            )
        };
        Status::ok_from_raw(status)
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
            unsafe {
                Api::ffi_ref().StreamClose.unwrap()(self.handle);
            }
        }
    }

    pub fn send(
        &self,
        buffer: &Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> Result<(), Status> {
        let status = unsafe {
            Api::ffi_ref().StreamSend.unwrap()(
                self.handle,
                buffer as *const Buffer as *const QUIC_BUFFER,
                buffer_count,
                flags as crate::ffi::QuicFlag,
                client_send_context as *mut c_void, //(self as *const Stream) as *const c_void,
            )
        };
        Status::ok_from_raw(status)
    }

    /// # Safety
    /// handler and context must be valid.
    pub unsafe fn set_callback_handler(&self, handler: StreamEventHandler, context: *const c_void) {
        unsafe { Api::set_callback_handler(self.handle, handler as *const c_void, context) };
    }

    pub fn receive_complete(&self, buffer_length: u64) {
        unsafe { Api::ffi_ref().StreamReceiveComplete.unwrap()(self.handle, buffer_length) }
    }
}

define_quic_handle_impl!(Stream);

impl StreamRef {
    /// For internal use only.
    pub(crate) unsafe fn from_raw(handle: HQUIC) -> Self {
        Self(Stream { handle })
    }
}

impl Drop for StreamRef {
    fn drop(&mut self) {
        // clear the handle to prevent auto close.
        self.0.handle = std::ptr::null_mut()
    }
}

/// Make inner stream accessile
impl std::ops::Deref for StreamRef {
    type Target = Stream;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    //
    // The following defines some simple test code.
    //

    use std::ffi::c_void;
    use std::ptr;

    use crate::ffi::{HQUIC, QUIC_STATUS};
    use crate::{
        ffi, Buffer, Configuration, Connection, ConnectionEvent, CredentialConfig, Registration,
        Settings, StatusCode, Stream, StreamEvent,
    };

    extern "C" fn test_conn_callback(
        _connection: HQUIC,
        context: *mut c_void,
        event: *mut ffi::QUIC_CONNECTION_EVENT,
    ) -> QUIC_STATUS {
        let connection = unsafe { &*(context as *const Connection) };
        let ev_ref = unsafe { event.as_ref().unwrap() };
        let event = ConnectionEvent::from(ev_ref);
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
                unsafe { stream.set_callback_handler(test_stream_callback, context) };
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
            _ => println!("Connection other callback {}", ev_ref.Type),
        }
        StatusCode::QUIC_STATUS_SUCCESS.into()
    }

    extern "C" fn test_stream_callback(
        stream: HQUIC,
        _context: *mut c_void,
        event: &StreamEvent,
    ) -> u32 {
        match event.event_type {
            crate::STREAM_EVENT_START_COMPLETE => {
                println!("Stream start complete 0x{:x}", unsafe {
                    event.payload.start_complete.status
                })
            }
            crate::STREAM_EVENT_RECEIVE => println!("Receive {} bytes", unsafe {
                event.payload.receive.total_buffer_length
            }),
            crate::STREAM_EVENT_SEND_COMPLETE => println!("Send complete"),
            crate::STREAM_EVENT_PEER_SEND_SHUTDOWN => println!("Peer send shutdown"),
            crate::STREAM_EVENT_PEER_SEND_ABORTED => println!("Peer send aborted"),
            crate::STREAM_EVENT_PEER_RECEIVE_ABORTED => println!("Peer receive aborted"),
            crate::STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => println!("Peer receive aborted"),
            crate::STREAM_EVENT_SHUTDOWN_COMPLETE => {
                println!("Stream shutdown complete");
                // Attach to stream for auto close handle.
                unsafe { Stream::from_raw(stream) };
            }
            crate::STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE => println!("Ideal send buffer size"),
            crate::STREAM_EVENT_PEER_ACCEPTED => println!("Peer accepted"),
            _ => println!("Other callback {}", event.event_type),
        }
        0
    }

    #[test]
    fn test_module() {
        let res = Registration::new(ptr::null());
        assert!(
            res.is_ok(),
            "Failed to open registration: {}",
            res.err().unwrap()
        );
        let registration = res.unwrap();

        let alpn = [Buffer::from("h3")];
        let res = Configuration::new(
            &registration,
            &alpn,
            #[cfg(feature = "preview-api")]
            Settings::new()
                .set_peer_bidi_stream_count(100)
                .set_peer_unidi_stream_count(3)
                .set_stream_multi_receive_enabled(true),
            #[cfg(not(feature = "preview-api"))]
            Settings::new()
                .set_peer_bidi_stream_count(100)
                .set_peer_unidi_stream_count(3),
        );
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
        let res = connection.open(
            &registration,
            Some(test_conn_callback),
            &connection as *const Connection as *const c_void,
        );
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

        let duration = std::time::Duration::from_millis(1000);
        std::thread::sleep(duration);
    }
}
