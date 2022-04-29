// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[allow(unused_imports)]
use c_types::AF_INET;
#[allow(unused_imports)]
use c_types::AF_INET6;
#[allow(unused_imports)]
use c_types::AF_UNSPEC;
use libc::c_void;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;
use std::option::Option;
use std::ptr;
#[macro_use]
extern crate bitfield;

//
// The following starts the C interop layer of MsQuic API.
//

/// Opaque handle to a MsQuic object.
pub type Handle = *const libc::c_void;

/// Unsigned 62-bit integer.
#[allow(non_camel_case_types)]
pub type u62 = u64;

/// C-style bool.
pub type BOOLEAN = ::std::os::raw::c_uchar;

/// Family of an IP address.
pub type AddressFamily = u16;
pub const ADDRESS_FAMILY_UNSPEC: AddressFamily = c_types::AF_UNSPEC as u16;
pub const ADDRESS_FAMILY_INET: AddressFamily = c_types::AF_INET as u16;
pub const ADDRESS_FAMILY_INET6: AddressFamily = c_types::AF_INET6 as u16;

/// IPv4 address payload.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub family: AddressFamily,
    pub port: u16,
    pub addr: u32,
    pub zero: [u8; 8usize],
}

/// IPv6 address payload.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in6 {
    pub family: AddressFamily,
    pub port: u16,
    pub flow_info: u32,
    pub addr: [u8; 16usize],
    pub scope_id: u32,
}

/// Generic representation of IPv4 or IPv6 addresses.
#[repr(C)]
#[derive(Copy, Clone)]
pub union Addr {
    pub ipv4: sockaddr_in,
    pub ipv6: sockaddr_in6,
}

impl Addr {
    /// Create a representation of IPv4 address and perform Network byte order conversion
    /// on the port number.
    pub fn ipv4(family: u16, port: u16, addr: u32) -> Addr {
        Addr {
            ipv4: sockaddr_in {
                family,
                port: port,
                addr,
                zero: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        }
    }

    /// Create a representation of IPv6 address and perform Network byte order conversion
    /// on the port number.
    pub fn ipv6(
        family: u16,
        port: u16,
        flow_info: u32,
        addr: [u8; 16usize],
        scope_id: u32,
    ) -> Addr {
        Addr {
            ipv6: sockaddr_in6 {
                family,
                port: port,
                flow_info,
                addr,
                scope_id,
            },
        }
    }
}

/// Helper for processing MsQuic return statuses.
pub struct Status {}

impl Status {
    /// Determines if a MsQuic status is considered a succes, which includes
    /// both "no error" and "pending" status codes.
    #[cfg(target_os = "windows")]
    pub fn succeeded(status: u32) -> bool {
        (status as i32) >= 0
    }
    #[cfg(not(target_os = "windows"))]
    pub fn succeeded(status: u32) -> bool {
        (status as i32) <= 0
    }

    /// Determines if a MsQuic status is considered a failure.
    #[cfg(target_os = "windows")]
    pub fn failed(status: u32) -> bool {
        (status as i32) < 0
    }
    #[cfg(not(target_os = "windows"))]
    pub fn failed(status: u32) -> bool {
        (status as i32) > 0
    }
}

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
    extern "C" fn(configuration: Handle, context: *const c_void, status: u64);

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
#[derive(Copy, Clone)]
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

pub const PARAM_CONFIGURATION_SETTINGS: u32 = 0x03000000;
pub const PARAM_CONFIGURATION_TICKET_KEYS: u32 = 0x03000001;
pub const PARAM_CONFIGURATION_VERSION_SETTINGS: u32 = 0x03000002;

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

pub const PARAM_STREAM_ID: u32 = 0x08000000;
pub const PARAM_STREAM_0RTT_LENGTH: u32 = 0x08000001;
pub const PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE: u32 = 0x08000002;
pub const PARAM_STREAM_PRIORITY: u32 = 0x08000003;

pub type ListenerEventType = u32;
pub const LISTENER_EVENT_NEW_CONNECTION: ListenerEventType = 0;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListenerEventNewConnection {
    pub info: *const NewConnectionInfo,
    pub connection: Handle,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ListenerEventPayload {
    pub new_connection: ListenerEventNewConnection,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListenerEvent {
    pub event_type: ListenerEventType,
    pub payload: ListenerEventPayload,
}

pub type ListenerEventHandler =
    extern "C" fn(listener: Handle, context: *mut c_void, event: &ListenerEvent) -> u32;

pub type ConnectionEventType = u32;
pub const CONNECTION_EVENT_CONNECTED: ConnectionEventType = 0;
pub const CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: ConnectionEventType = 1;
pub const CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: ConnectionEventType = 2;
pub const CONNECTION_EVENT_SHUTDOWN_COMPLETE: ConnectionEventType = 3;
pub const CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED: ConnectionEventType = 4;
pub const CONNECTION_EVENT_PEER_ADDRESS_CHANGED: ConnectionEventType = 5;
pub const CONNECTION_EVENT_PEER_STREAM_STARTED: ConnectionEventType = 6;
pub const CONNECTION_EVENT_STREAMS_AVAILABLE: ConnectionEventType = 7;
pub const CONNECTION_EVENT_PEER_NEEDS_STREAMS: ConnectionEventType = 8;
pub const CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED: ConnectionEventType = 9;
pub const CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: ConnectionEventType = 10;
pub const CONNECTION_EVENT_DATAGRAM_RECEIVED: ConnectionEventType = 11;
pub const CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: ConnectionEventType = 12;
pub const CONNECTION_EVENT_RESUMED: ConnectionEventType = 13;
pub const CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED: ConnectionEventType = 14;
pub const CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: ConnectionEventType = 15;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventConnected {
    pub session_resumed: BOOLEAN,
    pub negotiated_alpn_length: u8,
    pub negotiated_alpn: *const u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventConnectionShutdownByTransport {
    pub status: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventConnectionShutdownByPeer {
    pub error_code: u62,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventShutdownComplete {
    pub _bitfield: BOOLEAN,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventPeerStreamStarted {
    pub stream: Handle,
    pub flags: StreamOpenFlags,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ConnectionEventResumptionTicketReceived {
    pub resumption_ticket_length: u32,
    pub resumption_ticket: *const u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ConnectionEventPayload {
    pub connected: ConnectionEventConnected,
    pub shutdown_initiated_by_transport: ConnectionEventConnectionShutdownByTransport,
    pub shutdown_initiated_by_peer: ConnectionEventConnectionShutdownByPeer,
    pub shutdown_complete: ConnectionEventShutdownComplete,
    //pub local_address_changed: ConnectionEventLocalAddressChanged,
    //pub peer_address_changed: ConnectionEventPeerAddressChanged,
    pub peer_stream_started: ConnectionEventPeerStreamStarted,
    //pub streams_available: ConnectionEventStreamsAvailable,
    //pub ideal_processor_changed: ConnectionEventIdealProcessorChanged,
    //pub datagram_state_changed: ConnectionEventDatagramStateChanged,
    //pub datagram_received: ConnectionEventDatagramReceived,
    //pub datagram_send_state_changed: ConnectionEventDatagramSendStateChanged,
    //pub resumed: ConnectionEventResumed,
    pub resumption_ticket_received: ConnectionEventResumptionTicketReceived,
    //pub peer_certificated_received: ConnectionEventPeerCertificateReceived,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionEvent {
    pub event_type: ConnectionEventType,
    pub payload: ConnectionEventPayload,
}

pub type ConnectionEventHandler =
    extern "C" fn(connection: Handle, context: *mut c_void, event: &ConnectionEvent) -> u32;

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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventStartComplete {
    pub status: u64,
    pub id: u62,
    pub bit_flags: u8,
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
    pub error_code: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventPeerReceiveAborted {
    pub error_code: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventSendShutdownComplete {
    pub graceful: bool,
}


bitfield! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct StreamEventShutdownCompleteBitfields(u8);
    // The fields default to u8
    app_close_in_progress, _: 1, 0;
    _reserved, _: 7, 1;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct StreamEventShutdownComplete {
    connection_shutdown: bool,
    flags: StreamEventShutdownCompleteBitfields
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StreamEventIdealSendBufferSize {
    pub byte_count: u64,
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
}

#[repr(C)]
pub struct StreamEvent {
    pub event_type: StreamEventType,
    pub payload: StreamEventPayload,
}

pub type StreamEventHandler =
    extern "C" fn(stream: Handle, context: *mut c_void, event: &StreamEvent) -> u32;

#[repr(C)]
struct ApiTable {
    set_context: extern "C" fn(handle: Handle, context: *const c_void),
    get_context: extern "C" fn(handle: Handle) -> *mut c_void,
    set_callback_handler:
        extern "C" fn(handle: Handle, handler: *const c_void, context: *const c_void),
    set_param:
        extern "C" fn(handle: Handle, param: u32, buffer_length: u32, buffer: *const c_void) -> u32,
    get_param: extern "C" fn(
        handle: Handle,
        param: u32,
        buffer_length: *mut u32,
        buffer: *const c_void,
    ) -> u32,
    registration_open:
        extern "C" fn(config: *const RegistrationConfig, registration: &Handle) -> u32,
    registration_close: extern "C" fn(registration: Handle),
    registration_shutdown: extern "C" fn(registration: Handle),
    configuration_open: extern "C" fn(
        registration: Handle,
        alpn_buffers: *const Buffer,
        alpn_buffer_cout: u32,
        settings: *const Settings,
        settings_size: u32,
        context: *const c_void,
        configuration: &*const c_void,
    ) -> u32,
    configuration_close: extern "C" fn(configuration: Handle),
    configuration_load_credential:
        extern "C" fn(configuration: Handle, cred_config: *const CredentialConfig) -> u32,
    listener_open: extern "C" fn(
        registration: Handle,
        handler: ListenerEventHandler,
        context: *const c_void,
        listener: &Handle,
    ) -> u32,
    listener_close: extern "C" fn(listener: Handle),
    listener_start: extern "C" fn(
        listener: Handle,
        alpn_buffers: *const Buffer,
        alpn_buffer_cout: u32,
        local_address: *const Addr,
    ) -> u32,
    listener_stop: extern "C" fn(listener: Handle),
    connection_open: extern "C" fn(
        registration: Handle,
        handler: ConnectionEventHandler,
        context: *const c_void,
        connection: &Handle,
    ) -> u32,
    connection_close: extern "C" fn(connection: Handle),
    connection_shutdown:
        extern "C" fn(connection: Handle, flags: ConnectionShutdownFlags, error_code: u62),
    connection_start: extern "C" fn(
        connection: Handle,
        configuration: Handle,
        family: AddressFamily,
        server_name: *const i8,
        server_port: u16,
    ) -> u32,
    connection_set_configuration: extern "C" fn(connection: Handle, configuration: Handle) -> u32,
    connection_send_resumption_ticket: extern "C" fn(
        connection: Handle,
        flags: SendResumptionFlags,
        data_length: u16,
        resumption_data: *const u8,
    ) -> u32,
    stream_open: extern "C" fn(
        connection: Handle,
        flags: StreamOpenFlags,
        handler: StreamEventHandler,
        context: *const c_void,
        stream: &Handle,
    ) -> u32,
    stream_close: extern "C" fn(stream: Handle),
    stream_start: extern "C" fn(stream: Handle, flags: StreamStartFlags) -> u32,
    stream_shutdown:
        extern "C" fn(stream: Handle, flags: StreamShutdownFlags, error_code: u62) -> u32,
    stream_send: extern "C" fn(
        stream: Handle,
        buffers: *const Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> u32,
    stream_receive_complete: extern "C" fn(stream: Handle, buffer_length: u64) -> u32,
    stream_receive_set_enabled: extern "C" fn(stream: Handle, is_enabled: BOOLEAN) -> u32,
    datagram_send: extern "C" fn(
        connection: Handle,
        buffers: *const Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: *const c_void,
    ) -> u32,
}

#[link(name = "msquic")]
extern "C" {
    fn MsQuicOpenVersion(version: u32, api: &*const ApiTable) -> u32;
    fn MsQuicClose(api: *const ApiTable);
}

//
// The following starts the "nice" Rust API wrapper on the C interop layer.
//

/// Top level entry point for the MsQuic API.
///
/// Developper must ensure a struct containing MsQuic members such as `Connection`
///  or `Stream` declares `API` last so that the API is dropped last when the containing
/// sruct goes out of scope.
pub struct Api {
    table: *const ApiTable,
}

/// The execution context for processing connections on the application's behalf.
pub struct Registration {
    table: *const ApiTable,
    handle: Handle,
}

/// Specifies how to configure a connection.
pub struct Configuration {
    table: *const ApiTable,
    handle: Handle,
}

/// A single QUIC connection.
pub struct Connection {
    table: *const ApiTable,
    handle: Handle,
}

/// A single server listener
pub struct Listener {
    table: *const ApiTable,
    handle: Handle,
}

/// A single QUIC stream on a parent connection.
pub struct Stream {
    table: *const ApiTable,
    handle: Handle,
}

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
        let buffer = Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        };
        buffer
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
    pub fn new() -> Settings {
        Settings {
            is_set_flags: 0,
            max_bytes_per_key: 0,
            handshake_idle_timeout_ms: 0,
            idle_timeout_ms: 0,
            mtu_discovery_search_complete_timeout_us: 0,
            tls_client_max_send_buffer: 0,
            tls_server_max_send_buffer: 0,
            stream_recv_window_default: 0,
            stream_recv_buffer_default: 0,
            conn_flow_control_window: 0,
            max_worker_queue_delay_us: 0,
            max_stateless_operations: 0,
            initial_window_packets: 0,
            send_idle_timeout_ms: 0,
            initiall_rtt_ms: 0,
            max_ack_delay_ms: 0,
            disconnect_timeout_ms: 0,
            keep_alive_interval_ms: 0,
            congestion_control_algorithm: 0,
            peer_bidi_stream_count: 0,
            peer_unidi_stream_count: 0,
            max_binding_stateless_operations: 0,
            stateless_operation_expiration_ms: 0,
            minimum_mtu: 0,
            maximum_mtu: 0,
            other_flags: 0,
            mtu_operations_per_drain: 0,
            mtu_discovery_missing_probe_count: 0,
        }
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
    pub fn new() -> Api {
        let new_table: *const ApiTable = ptr::null();
        let status = unsafe { MsQuicOpenVersion(2, &new_table) };
        if Status::failed(status) {
            panic!("MsQuicOpenVersion failure 0x{:x}", status);
        }
        Api { table: new_table }
    }

    pub fn close_listener(&self, listener: Handle) {
        unsafe {
            ((*self.table).listener_close)(listener);
        }
    }
    pub fn close_connection(&self, connection: Handle) {
        unsafe {
            ((*self.table).connection_close)(connection);
        }
    }
    pub fn close_stream(&self, stream: Handle) {
        unsafe {
            ((*self.table).stream_close)(stream);
        }
    }

    pub fn get_perf(&self) -> QuicPerformance {
        let mut perf = QuicPerformance {
            counters: [0; PERF_COUNTER_MAX as usize],
        };
        let perf_length = std::mem::size_of::<[i64; PERF_COUNTER_MAX as usize]>() as u32;
        unsafe {
            ((*self.table).get_param)(
                std::ptr::null(),
                PARAM_GLOBAL_PERF_COUNTERS,
                (&perf_length) as *const u32 as *mut u32,
                perf.counters.as_mut_ptr() as *const c_void,
            )
        };
        perf
    }

    pub fn set_callback_handler(
        &self,
        handle: Handle,
        handler: *const c_void,
        context: *const c_void,
    ) {
        unsafe { ((*self.table).set_callback_handler)(handle, handler, context) }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe { MsQuicClose(self.table) };
    }
}

impl Registration {
    pub fn new(api: &Api, config: *const RegistrationConfig) -> Registration {
        let new_registration: Handle = ptr::null();
        let status = unsafe { ((*api.table).registration_open)(config, &new_registration) };
        if Status::failed(status) {
            panic!("RegistrationOpen failure 0x{:x}", status);
        }
        Registration {
            table: api.table,
            handle: new_registration,
        }
    }

    pub fn shutdown(&self) {
        unsafe { ((*self.table).registration_shutdown)(self.handle) }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        unsafe { ((*self.table).registration_close)(self.handle) };
    }
}

impl Configuration {
    pub fn new(
        registration: &Registration,
        alpn: &Buffer,
        settings: *const Settings,
    ) -> Configuration {
        let context: *const c_void = ptr::null();
        let new_configuration: Handle = ptr::null();
        let mut settings_size: u32 = 0;
        if settings != ptr::null() {
            settings_size = ::std::mem::size_of::<Settings>() as u32;
        }
        let status = unsafe {
            ((*registration.table).configuration_open)(
                registration.handle,
                *&alpn,
                1,
                settings,
                settings_size,
                context,
                &new_configuration,
            )
        };
        if Status::failed(status) {
            panic!("ConfigurationOpen failure 0x{:x}", status);
        }
        Configuration {
            table: registration.table,
            handle: new_configuration,
        }
    }

    pub fn load_credential(&self, cred_config: &CredentialConfig) {
        let status =
            unsafe { ((*self.table).configuration_load_credential)(self.handle, *&cred_config) };
        if Status::failed(status) {
            panic!("ConfigurationLoadCredential failure 0x{:x}", status);
        }
    }
}

impl Drop for Configuration {
    fn drop(&mut self) {
        unsafe { ((*self.table).configuration_close)(self.handle) };
    }
}

impl Connection {
    pub fn new(registration: &Registration) -> Connection {
        Connection {
            table: registration.table,
            handle: ptr::null(),
        }
    }

    pub fn from_parts(handle: Handle, api: &Api) -> Connection {
        Connection {
            table: api.table,
            handle,
        }
    }

    pub fn open(
        &self,
        registration: &Registration,
        handler: ConnectionEventHandler,
        context: *const c_void,
    ) {
        let status = unsafe {
            ((*self.table).connection_open)(registration.handle, handler, context, &self.handle)
        };
        if Status::failed(status) {
            panic!("ConnectionOpen failure 0x{:x}", status);
        }
    }

    pub fn start(&self, configuration: &Configuration, server_name: &str, server_port: u16) {
        let server_name_safe = std::ffi::CString::new(server_name).unwrap();
        let status = unsafe {
            ((*self.table).connection_start)(
                self.handle,
                configuration.handle,
                0,
                server_name_safe.as_ptr(),
                server_port,
            )
        };
        if Status::failed(status) {
            panic!("ConnectionStart failure 0x{:x}", status);
        }
    }

    pub fn close(&self) {
        unsafe {
            ((*self.table).connection_close)(self.handle);
        }
    }

    pub fn shutdown(&self, flags: ConnectionShutdownFlags, error_code: u62) {
        unsafe {
            ((*self.table).connection_shutdown)(self.handle, flags, error_code);
        }
    }

    pub fn set_param(&self, param: u32, buffer_length: u32, buffer: *const c_void) -> u32 {
        unsafe { ((*self.table).set_param)(self.handle, param, buffer_length, buffer) }
    }

    pub fn stream_close(&self, stream: Handle) {
        unsafe {
            ((*self.table).stream_close)(stream);
        }
    }

    pub fn get_stats(&self) -> QuicStatistics {
        let mut stat_buffer: [u8; std::mem::size_of::<QuicStatistics>()] =
            [0; std::mem::size_of::<QuicStatistics>()];
        let stat_size_mut = std::mem::size_of::<QuicStatistics>();
        unsafe {
            ((*self.table).get_param)(
                self.handle,
                PARAM_CONN_STATISTICS,
                (&stat_size_mut) as *const usize as *const u32 as *mut u32,
                stat_buffer.as_mut_ptr() as *const c_void,
            )
        };

        unsafe { *(stat_buffer.as_ptr() as *const c_void as *const QuicStatistics) }
    }

    pub fn get_stats_v2(&self) -> QuicStatisticsV2 {
        let mut stat_buffer: [u8; std::mem::size_of::<QuicStatisticsV2>()] =
            [0; std::mem::size_of::<QuicStatisticsV2>()];
        let stat_size_mut = std::mem::size_of::<QuicStatisticsV2>();
        unsafe {
            ((*self.table).get_param)(
                self.handle,
                PARAM_CONN_STATISTICS_V2,
                (&stat_size_mut) as *const usize as *const u32 as *mut u32,
                stat_buffer.as_mut_ptr() as *const c_void,
            )
        };

        unsafe { *(stat_buffer.as_ptr() as *const c_void as *const QuicStatisticsV2) }
    }

    pub fn set_configuration(&self, configuration: &Configuration) {
        let status = unsafe {
            ((*self.table).connection_set_configuration)(self.handle, configuration.handle)
        };
        if Status::failed(status) {
            panic!("ConnectionSetConfiguration failure 0x{:x}", status);
        }
    }

    pub fn set_callback_handler(&self, handler: ConnectionEventHandler, context: *const c_void) {
        unsafe {
            ((*self.table).set_callback_handler)(self.handle, handler as *const c_void, context)
        };
    }

    pub fn set_stream_callback_handler(
        &self,
        stream_handle: Handle,
        handler: StreamEventHandler,
        context: *const c_void,
    ) {
        unsafe {
            ((*self.table).set_callback_handler)(stream_handle, handler as *const c_void, context)
        };
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { ((*self.table).connection_close)(self.handle) };
    }
}

impl Listener {
    pub fn new(
        registration: &Registration,
        handler: ListenerEventHandler,
        context: *const c_void,
    ) -> Listener {
        let new_listener: Handle = ptr::null();
        let status = unsafe {
            ((*registration.table).listener_open)(
                registration.handle,
                handler,
                context,
                &new_listener,
            )
        };
        if Status::failed(status) {
            panic!("ListenerOpen failed, {:x}!\n", status);
        }

        Listener {
            table: registration.table,
            handle: new_listener,
        }
    }

    pub fn start(&self, alpn_buffers: &Buffer, alpn_buffer_count: u32, local_address: &Addr) {
        let status = unsafe {
            ((*self.table).listener_start)(
                self.handle,
                *&alpn_buffers,
                alpn_buffer_count,
                *&local_address,
            )
        };
        if Status::failed(status) {
            panic!("ListenerStart failed, {:x}!\n", status);
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        unsafe { ((*self.table).listener_close)(self.handle) };
    }
}

impl Stream {
    pub fn new(context: *const c_void) -> Stream {
        let api = unsafe { &*(context as *const Api) };
        Stream {
            table: api.table,
            handle: ptr::null(),
        }
    }

    pub fn from_parts(handle: Handle, api: &Api) -> Stream {
        Stream {
            table: api.table,
            handle,
        }
    }

    pub fn open(
        &self,
        connection: &Connection,
        flags: StreamOpenFlags,
        handler: StreamEventHandler,
        context: *const c_void,
    ) {
        let status = unsafe {
            ((*self.table).stream_open)(connection.handle, flags, handler, context, &self.handle)
        };
        if Status::failed(status) {
            panic!("StreamOpen failure 0x{:x}", status);
        }
    }

    pub fn start(&self, flags: StreamStartFlags) {
        let status = unsafe { ((*self.table).stream_start)(self.handle, flags) };
        if Status::failed(status) {
            panic!("StreamStart failure 0x{:x}", status);
        }
    }

    pub fn close(&self) {
        unsafe {
            ((*self.table).stream_close)(self.handle);
        }
    }

    pub fn send(
        &self,
        buffer: &Buffer,
        buffer_count: u32,
        flags: SendFlags,
        client_send_context: *const c_void,
    ) {
        let status = unsafe {
            ((*self.table).stream_send)(
                self.handle,
                *&buffer,
                buffer_count,
                flags,
                client_send_context, //(self as *const Stream) as *const c_void,
            )
        };
        if Status::failed(status) {
            panic!("StreamSend failure 0x{:x}", status);
        }
    }

    pub fn set_callback_handler(&self, handler: StreamEventHandler, context: *const c_void) {
        unsafe {
            ((*self.table).set_callback_handler)(self.handle, handler as *const c_void, context)
        };
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe { ((*self.table).stream_close)(self.handle) };
    }
}

//
// The following defines some simple test code.
//

#[allow(dead_code)] // Used in test code
extern "C" fn test_conn_callback(
    _connection: Handle,
    context: *mut c_void,
    event: &ConnectionEvent,
) -> u32 {
    let connection = unsafe { &*(context as *const Connection) };
    match event.event_type {
        CONNECTION_EVENT_CONNECTED => println!("Connected"),
        CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT => {
            println!("Transport shutdown 0x{:x}", unsafe {
                event.payload.shutdown_initiated_by_transport.status
            })
        }
        CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER => println!("App shutdown {}", unsafe {
            event.payload.shutdown_initiated_by_peer.error_code
        }),
        CONNECTION_EVENT_SHUTDOWN_COMPLETE => println!("Shutdown complete"),
        CONNECTION_EVENT_PEER_STREAM_STARTED => {
            println!("Peer stream started");
            connection.set_stream_callback_handler(
                unsafe { event.payload.peer_stream_started.stream },
                test_stream_callback,
                context,
            );
        }
        _ => println!("Other callback {}", event.event_type),
    }
    0
}

#[allow(dead_code)] // Used in test code
extern "C" fn test_stream_callback(
    stream: Handle,
    context: *mut c_void,
    event: &StreamEvent,
) -> u32 {
    let connection = unsafe { &*(context as *const Connection) };
    match event.event_type {
        STREAM_EVENT_START_COMPLETE => println!("Stream start complete 0x{:x}", unsafe {
            event.payload.start_complete.status
        }),
        STREAM_EVENT_RECEIVE => println!("Receive {} bytes", unsafe {
            event.payload.receive.total_buffer_length
        }),
        STREAM_EVENT_SEND_COMPLETE => println!("Send complete"),
        STREAM_EVENT_PEER_SEND_SHUTDOWN => println!("Peer send shutdown"),
        STREAM_EVENT_PEER_SEND_ABORTED => println!("Peer send aborted"),
        STREAM_EVENT_PEER_RECEIVE_ABORTED => println!("Peer receive aborted"),
        STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => println!("Peer receive aborted"),
        STREAM_EVENT_SHUTDOWN_COMPLETE => {
            println!("Stream shutdown complete");
            connection.stream_close(stream);
        }
        STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE => println!("Ideal send buffer size"),
        STREAM_EVENT_PEER_ACCEPTED => println!("Peer accepted"),
        _ => println!("Other callback {}", event.event_type),
    }
    0
}

#[test]
fn test_module() {
    let api = Api::new();
    let registration = Registration::new(&api, ptr::null());

    let alpn = Buffer::from("h3");
    let configuration = Configuration::new(
        &registration,
        &alpn,
        Settings::new()
            .set_peer_bidi_stream_count(100)
            .set_peer_unidi_stream_count(3),
    );
    let cred_config = CredentialConfig::new_client();
    configuration.load_credential(&cred_config);

    let connection = Connection::new(&registration);
    connection.open(
        &registration,
        test_conn_callback,
        &connection as *const Connection as *const c_void,
    );
    connection.start(&configuration, "www.cloudflare.com", 443);

    let duration = std::time::Duration::from_millis(1000);
    std::thread::sleep(duration);
}
