// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use libc::c_void;
use std::ptr;
use std::os::raw::c_char;
use std::option::Option;

/// Represents an opaque handle to a MsQuic object.
pub type Handle = *const libc::c_void;

/// Represents an unsigned 62-bit integer.
#[allow(non_camel_case_types)]
pub type u62 = u64;

/// Represents a C-style bool.
pub type BOOLEAN = ::std::os::raw::c_uchar;

pub type AddressFamily = u16;
pub const ADDRESS_FAMILY_UNSPEC: AddressFamily = 0;
pub const ADDRESS_FAMILY_INET: AddressFamily = 2;
pub const ADDRESS_FAMILY_INET6: AddressFamily = 23;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub family: AddressFamily,
    pub data: [u8; 14usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub family: AddressFamily,
    pub port: u16,
    pub addr: u32,
    pub zero: [u8; 8usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub family: AddressFamily,
    pub port: u16,
    pub flow_info: u32,
    pub addr: [u8; 16usize],
    pub scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Addr {
    pub ip: sockaddr,
    pub ipv4: sockaddr_in,
    pub ipv6: sockaddr_in6,
}

pub struct Status { }

impl Status {
    /// Determines if a MsQuic status is considered a succes, which includes
    /// both "no error" and "pending" status codes.
    #[cfg(target_os="windows")]
    pub fn succeeded(status: u64) -> bool {
        (status as i64) >= 0
    }
    #[cfg(not(target_os="windows"))]
    pub fn succeeded(status: u64) -> bool {
        (status as i64) <= 0
    }

    /// Determines if a MsQuic status is considered a failure.
    #[cfg(target_os="windows")]
    pub fn failed(status: u64) -> bool {
        (status as i64) < 0
    }
    #[cfg(not(target_os="windows"))]
    pub fn failed(status: u64) -> bool {
        (status as i64) > 0
    }
}

pub type ExecutionProfile = u32;
pub const EXECUTION_PROFILE_LOW_LATENCY: ExecutionProfile = 0;
pub const EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT: ExecutionProfile = 1;
pub const EXECUTION_PROFILE_TYPE_SCAVENGER: ExecutionProfile = 2;
pub const EXECUTION_PROFILE_TYPE_REAL_TIME: ExecutionProfile = 3;

pub type LoadBalancingMode = u32;
pub const LOAD_BALANCING_DISABLED: LoadBalancingMode = 0;
pub const LOAD_BALANCING_SERVER_ID_IP: LoadBalancingMode = 1;

pub type CredentialType = u32;
pub const CREDENTIAL_TYPE_NONE: CredentialType = 0;
pub const CREDENTIAL_TYPE_CERTIFICATE_HASH: CredentialType = 1;
pub const CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE: CredentialType = 2;
pub const CREDENTIAL_TYPE_CERTIFICATE_CONTEXT: CredentialType = 3;
pub const CREDENTIAL_TYPE_CERTIFICATE_FILE: CredentialType = 4;
pub const CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED: CredentialType = 5;
pub const CREDENTIAL_TYPE_CERTIFICATE_PKCS12: CredentialType = 6;

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

pub type AllowedCipherSuiteFlags = u32;
pub const ALLOWED_CIPHER_SUITE_NONE: AllowedCipherSuiteFlags = 0;
pub const ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256: AllowedCipherSuiteFlags = 1;
pub const ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384: AllowedCipherSuiteFlags = 2;
pub const ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256: AllowedCipherSuiteFlags = 4;

pub type CertificateHashStoreFlags = u32;
pub const CERTIFICATE_HASH_STORE_FLAG_NONE: CertificateHashStoreFlags = 0;
pub const CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE: CertificateHashStoreFlags = 1;

pub type ConnectionShutdownFlags = u32;
pub const CONNECTION_SHUTDOWN_FLAG_NONE: ConnectionShutdownFlags = 0;
pub const CONNECTION_SHUTDOWN_FLAG_SILENT: ConnectionShutdownFlags = 1;

pub type ServerResumptionLevel = u32;
pub const SERVER_NO_RESUME: ServerResumptionLevel = 0;
pub const SERVER_RESUME_ONLY: ServerResumptionLevel = 1;
pub const SERVER_RESUME_AND_ZERORTT: ServerResumptionLevel = 2;

pub type SendResumptionFlags = u32;
pub const SEND_RESUMPTION_FLAG_NONE: SendResumptionFlags = 0;
pub const SEND_RESUMPTION_FLAG_FINAL: SendResumptionFlags = 1;

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
pub const STREAM_START_FLAG_FAIL_BLOCKED: StreamStartFlags = 1;
pub const STREAM_START_FLAG_IMMEDIATE: StreamStartFlags = 2;
pub const STREAM_START_FLAG_ASYNC: StreamStartFlags = 4;
pub const STREAM_START_FLAG_SHUTDOWN_ON_FAIL: StreamStartFlags = 8;
pub const STREAM_START_FLAG_INDICATE_PEER_ACCEPT: StreamStartFlags = 16;

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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RegistrationConfig {
    pub app_name: *const c_char,
    pub execution_profile: ExecutionProfile
}

pub type CredentialLoadComplete = extern fn(configuration: Handle, context: *const c_void, status: u64);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateHash {
    pub sha_hash: [u8; 20usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CertificateHashStore {
    pub flags: CertificateHashStoreFlags,
    pub sha_hash: [u8; 20usize],
    pub store_name: [c_char; 128usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateFile {
    pub private_key_file: *const c_char,
    pub certificate_file: *const c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateFileProtected {
    pub private_key_file: *const c_char,
    pub certificate_file: *const c_char,
    pub private_key_password: *const c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificatePkcs12 {
    pub ans1_blob: *const u8,
    pub ans1_blob_length: u32,
    pub private_key_password: *const c_char,
}

pub type Certificate = c_void;
pub type CertificateChain = c_void;

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CredentialConfig {
    pub cred_type: CredentialType,
    pub cred_flags: CredentialFlags,
    pub certificate: CertificateUnion,
    pub principle: *const c_char,
    reserved: *const c_void,
    pub async_handler: Option<CredentialLoadComplete>,
    pub allowed_cipher_suites: AllowedCipherSuiteFlags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TicketKeyConfig {
    pub id: [u8; 16usize],
    pub material: [u8; 64usize],
    pub material_length: u8,
}

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
    pub server_name: *const c_char,
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
#[derive(Debug, Copy, Clone)]
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

/*#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS__bindgen_ty_1 {
    pub Start: u64,
    pub InitialFlightEnd: u64,
    pub HandshakeFlightEnd: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS__bindgen_ty_2 {
    pub ClientFlight1Bytes: u32,
    pub ServerFlight1Bytes: u32,
    pub ClientFlight2Bytes: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS__bindgen_ty_3 {
    pub PathMtu: u16,
    pub TotalPackets: u64,
    pub RetransmittablePackets: u64,
    pub SuspectedLostPackets: u64,
    pub SpuriousLostPackets: u64,
    pub TotalBytes: u64,
    pub TotalStreamBytes: u64,
    pub CongestionCount: u32,
    pub PersistentCongestionCount: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS__bindgen_ty_4 {
    pub TotalPackets: u64,
    pub ReorderedPackets: u64,
    pub DroppedPackets: u64,
    pub DuplicatePackets: u64,
    pub TotalBytes: u64,
    pub TotalStreamBytes: u64,
    pub DecryptionFailures: u64,
    pub ValidAckFrames: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS__bindgen_ty_5 {
    pub KeyUpdateCount: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_STATISTICS {
    pub CorrelationId: u64,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
    pub Rtt: u32,
    pub MinRtt: u32,
    pub MaxRtt: u32,
    pub Timing: QUIC_STATISTICS__bindgen_ty_1,
    pub Handshake: QUIC_STATISTICS__bindgen_ty_2,
    pub Send: QUIC_STATISTICS__bindgen_ty_3,
    pub Recv: QUIC_STATISTICS__bindgen_ty_4,
    pub Misc: QUIC_STATISTICS__bindgen_ty_5,
}*/

/*#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_LISTENER_STATISTICS__bindgen_ty_1__bindgen_ty_1 {
    pub DroppedPackets: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_LISTENER_STATISTICS__bindgen_ty_1 {
    pub Recv: QUIC_LISTENER_STATISTICS__bindgen_ty_1__bindgen_ty_1,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QUIC_LISTENER_STATISTICS {
    pub TotalAcceptedConnections: u64,
    pub TotalRejectedConnections: u64,
    pub Binding: QUIC_LISTENER_STATISTICS__bindgen_ty_1,
}*/

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Settings {
    pub is_set_flags: u64,
    pub max_bytes_per_key: u64,
    pub handshake_idle_timeout_ms: u64,
    pub idle_timeout_ms: u64,
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
    pub peer_bidi_stream_count: u16,
    pub peer_unidi_stream_count: u16,
    pub retry_memory_limit: u16,
    pub load_balancing_mode: u16,
    pub other_flags: u8,
    pub desired_version_list: *const u32,
    pub desired_version_list_length: u32,
    pub minimum_mtu: u16,
    pub maximum_mtu: u16,
    pub mtu_discovery_search_complete_timeout_us: u64,
    pub mtu_discovery_missing_probe_count: u8,
    pub max_binding_stateless_operations: u16,
    pub stateless_operation_expiration_ms: u16,
}

pub type ParameterLevel = u32;
pub const PARAM_LEVEL_GLOBAL: ParameterLevel = 0;
pub const PARAM_LEVEL_REGISTRATION: ParameterLevel = 1;
pub const PARAM_LEVEL_CONFIGURATION: ParameterLevel = 2;
pub const PARAM_LEVEL_LISTENER: ParameterLevel = 3;
pub const PARAM_LEVEL_CONNECTION: ParameterLevel = 4;
pub const PARAM_LEVEL_TLS: ParameterLevel = 5;
pub const PARAM_LEVEL_STREAM: ParameterLevel = 6;

pub const PARAM_GLOBAL_RETRY_MEMORY_PERCENT: u32 = 67108864;
pub const PARAM_GLOBAL_SUPPORTED_VERSIONS: u32 = 67108865;
pub const PARAM_GLOBAL_LOAD_BALACING_MODE: u32 = 67108866;
pub const PARAM_GLOBAL_PERF_COUNTERS: u32 = 67108867;
pub const PARAM_GLOBAL_SETTINGS: u32 = 67108868;
pub const PARAM_GLOBAL_VERSION: u32 = 67108869;

pub const PARAM_REGISTRATION_CID_PREFIX: u32 = 134217728;

pub const PARAM_CONFIGURATION_SETTINGS: u32 = 201326592;
pub const PARAM_CONFIGURATION_TICKET_KEYS: u32 = 201326593;

pub const PARAM_LISTENER_LOCAL_ADDRESS: u32 = 268435456;
pub const PARAM_LISTENER_STATS: u32 = 268435457;

pub const PARAM_CONN_QUIC_VERSION: u32 = 335544320;
pub const PARAM_CONN_LOCAL_ADDRESS: u32 = 335544321;
pub const PARAM_CONN_REMOTE_ADDRESS: u32 = 335544322;
pub const PARAM_CONN_IDEAL_PROCESSOR: u32 = 335544323;
pub const PARAM_CONN_SETTINGS: u32 = 335544324;
pub const PARAM_CONN_STATISTICS: u32 = 335544325;
pub const PARAM_CONN_STATISTICS_PLAT: u32 = 335544326;
pub const PARAM_CONN_SHARE_UDP_BINDING: u32 = 335544327;
pub const PARAM_CONN_LOCAL_BIDI_STREAM_COUNT: u32 = 335544328;
pub const PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT: u32 = 335544329;
pub const PARAM_CONN_MAX_STREAM_IDS: u32 = 335544330;
pub const PARAM_CONN_CLOSE_REASON_PHRASE: u32 = 335544331;
pub const PARAM_CONN_STREAM_SCHEDULING_SCHEME: u32 = 335544332;
pub const PARAM_CONN_DATAGRAM_RECEIVE_ENABLED: u32 = 335544333;
pub const PARAM_CONN_DATAGRAM_SEND_ENABLED: u32 = 335544334;
pub const PARAM_CONN_RESUMPTION_TICKET: u32 = 335544336;
pub const PARAM_CONN_PEER_CERTIFICATE_VALID: u32 = 335544337;

pub const PARAM_TLS_HANDSHAKE_INFO: u32 = 402653184;
pub const PARAM_TLS_NEGOTIATED_ALPN: u32 = 402653185;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SchannelContextAttributeW {
    pub attribute: u32,
    pub buffer: *mut c_void,
}
pub const PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W: u32 = 419430400;

pub const PARAM_STREAM_ID: u32 = 469762048;
pub const PARAM_STREAM_0RTT_LENGTH: u32 = 469762049;
pub const PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE: u32 = 469762050;
pub const PARAM_STREAM_PRIORITY: u32 = 469762051;

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

pub type ListenerEventHandler = extern fn(listener: Handle, context: *mut c_void, event: &ListenerEvent) -> u64;

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
    //pub resumption_ticket_received: ConnectionEventResumptionTicketReceived,
    //pub peer_certificated_received: ConnectionEventPeerCertificateReceived,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionEvent {
    pub event_type: ConnectionEventType,
    pub payload: ConnectionEventPayload,
}

pub type ConnectionEventHandler = extern fn(connection: Handle, context: *mut c_void, event: &ConnectionEvent) -> u64;

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
#[derive(Copy, Clone)]
pub union StreamEventPayload {
    pub start_complete: StreamEventStartComplete,
    pub receive: StreamEventReceive,
    //pub send_complete: StreamEventSendComplete,
    //pub peer_send_aborted: StreamEventPeerSendAborted,
    //pub peer_receive_aborted: StreamEventPeerReceiveAborted,
    //pub send_shutdown_complete: StreamEventSendShutdownComplete,
    //pub shutdown_complete: StreamEventShutdownComplete,
    //pub ideal_send_buffer_size: StreamEventIdealSendBufferSize,
}

#[repr(C)]
pub struct StreamEvent {
    pub event_type: StreamEventType,
    pub payload: StreamEventPayload,
}

pub type StreamEventHandler = extern fn(stream: Handle, context: *mut c_void, event: &StreamEvent) -> u64;

#[repr(C)]
struct ApiTable {
    set_context : extern fn(handle: Handle, context: *const c_void),
    get_context : extern fn(handle: Handle) -> *mut c_void,
    set_callback_handler : extern fn(handle: Handle, handler: *const c_void, context: *const c_void),
    set_param : extern fn(handle: Handle, level: ParameterLevel, param: u32, buffer_length: u32, buffer: *const c_void) -> u64,
    get_param : extern fn(handle: Handle, level: ParameterLevel, param: u32, buffer_length: *mut u32, buffer: *const c_void) -> u64,
    registration_open : extern fn(config: *const RegistrationConfig, registration: &Handle) -> u64,
    registration_close : extern fn(registration: Handle),
    registration_shutdown : extern fn(registration: Handle),
    configuration_open : extern fn(registration: Handle, alpn_buffers: *const Buffer, alpn_buffer_cout: u32, settings: *const Settings, settings_size: u32, context: *const c_void, configuration: &*const c_void) -> u64,
    configuration_close : extern fn(configuration: Handle),
    configuration_load_credential : extern fn(configuration: Handle, cred_config: *const CredentialConfig) -> u64,
    listener_open : extern fn(registration: Handle, handler: ListenerEventHandler, context: *const c_void, listener: &Handle) -> u64,
    listener_close : extern fn(listener: Handle),
    listener_start : extern fn(listener: Handle, alpn_buffers: *const Buffer, alpn_buffer_cout: u32, local_address: *const Addr) -> u64,
    listener_stop : extern fn(listener: Handle),
    connection_open : extern fn(registration: Handle, handler: ConnectionEventHandler, context: *const c_void, connection: &Handle) -> u64,
    connection_close : extern fn(connection: Handle),
    connection_shutdown : extern fn(connection: Handle, flags: ConnectionShutdownFlags, error_code: u62),
    connection_start : extern fn(connection: Handle, configuration: Handle, family: AddressFamily, server_name: *const u8, server_port: u16) -> u64,
    connection_set_configuration : extern fn(connection: Handle, configuration: Handle) -> u64,
    connection_send_resumption_ticket : extern fn(connection: Handle, flags: SendResumptionFlags, data_length: u16, resumption_data: *const u8) -> u64,
    stream_open : extern fn(connection: Handle, flags: StreamOpenFlags, handler: StreamEventHandler, context: *const c_void, stream: &Handle) -> u64,
    stream_close : extern fn(stream: Handle),
    stream_start : extern fn(stream: Handle, flags: StreamStartFlags) -> u64,
    stream_shutdown : extern fn(stream: Handle, flags: StreamShutdownFlags, error_code: u62) -> u64,
    stream_send : extern fn(stream: Handle, buffers: *const Buffer, buffer_count: u32, flags: SendFlags, client_send_context: *const c_void) -> u64,
    stream_receive_complete : extern fn(stream: Handle, buffer_length: u64) -> u64,
    stream_receive_set_enabled : extern fn(stream: Handle, is_enabled: BOOLEAN) -> u64,
    datagram_send : extern fn(connection: Handle, buffers: *const Buffer, buffer_count: u32, flags: SendFlags, client_send_context: *const c_void) -> u64,
}

#[link(name = "msquic")]
extern {
    fn MsQuicOpenVersion(version: u32, api: &*const ApiTable) -> u64;
    fn MsQuicClose(api: *const ApiTable);
}

pub struct Api {
    table: *const ApiTable,
}

pub struct Registration {
    table: *const ApiTable,
    handle: Handle,
}

pub struct Configuration {
    table: *const ApiTable,
    handle: Handle,
}

pub struct Connection {
    table: *const ApiTable,
    handle: Handle,
}

pub struct Stream {
    table: *const ApiTable,
    handle: Handle,
}

impl Buffer {
    pub fn from_str(data: &str) -> Buffer {
        Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        }
    }
    pub fn from_char(data: &String) -> Buffer {
        Buffer {
            length: data.len() as u32,
            buffer: data.as_ptr() as *mut u8,
        }
    }
}

impl Settings {
    pub fn new() -> Settings {
        Settings {
            is_set_flags: 0,
            max_bytes_per_key: 0,
            handshake_idle_timeout_ms: 0,
            idle_timeout_ms: 0,
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
            peer_bidi_stream_count: 0,
            peer_unidi_stream_count: 0,
            retry_memory_limit: 0,
            load_balancing_mode: 0,
            other_flags: 0,
            desired_version_list: ptr::null(),
            desired_version_list_length: 0,
            minimum_mtu: 0,
            maximum_mtu: 0,
            mtu_discovery_search_complete_timeout_us: 0,
            mtu_discovery_missing_probe_count: 0,
            max_binding_stateless_operations: 0,
            stateless_operation_expiration_ms: 0,
        }
    }
    pub fn set_peer_bidi_stream_count(&mut self, value: u16) -> &mut Settings {
        self.is_set_flags |= 0x10000;
        self.peer_bidi_stream_count = value;
        self
    }
    pub fn set_peer_unidi_stream_count(&mut self, value: u16) -> &mut Settings {
        self.is_set_flags |= 0x20000;
        self.peer_unidi_stream_count = value;
        self
    }
}

impl CredentialConfig {
    pub fn new_client() -> CredentialConfig {
        CredentialConfig {
            cred_type: CREDENTIAL_FLAG_NONE,
            cred_flags: CREDENTIAL_FLAG_CLIENT,
            certificate: CertificateUnion { context: ptr::null() },
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
        let status = unsafe { MsQuicOpenVersion(1, &new_table) };
        if Status::failed(status) {
            panic!("MsQuicOpenVersion failure 0x{:x}", status);
        }
        Api {
            table: new_table,
        }
    }

    pub fn set_callback_handler(&self, handle: Handle, handler: *const c_void, context: *const c_void) {
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
    pub fn new(registration: &Registration, alpn: &Buffer, settings: *const Settings) -> Configuration {
        let context: *const c_void = ptr::null();
        let new_configuration: Handle = ptr::null();
        let mut settings_size: u32 = 0;
        if settings != ptr::null() {
            settings_size = ::std::mem::size_of::<Settings>() as u32;
        }
        let status = unsafe { ((*registration.table).configuration_open)(registration.handle, *&alpn, 1, settings, settings_size, context, &new_configuration) };
        if Status::failed(status) {
            panic!("ConfigurationOpen failure 0x{:x}", status);
        }
        Configuration {
            table: registration.table,
            handle: new_configuration,
        }
    }

    pub fn load_credential(&self, cred_config: &CredentialConfig) {
        let status = unsafe { ((*self.table).configuration_load_credential)(self.handle, *&cred_config) };
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
    pub fn new(registration: &Registration, handler: ConnectionEventHandler, context: *const c_void) -> Connection {
        let new_connection: Handle = ptr::null();
        let status = unsafe { ((*registration.table).connection_open)(registration.handle, handler, context, &new_connection) };
        if Status::failed(status) {
            panic!("ConnectionOpen failure 0x{:x}", status);
        }
        Connection {
            table: registration.table,
            handle: new_connection,
        }
    }

    pub fn start(&self, configuration: &Configuration, server_name: &str, server_port: u16) {
        let status = unsafe { ((*self.table).connection_start)(self.handle, configuration.handle, 0, server_name.as_ptr(), server_port) };
        if Status::failed(status) {
            panic!("ConnectionStart failure 0x{:x}", status);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { ((*self.table).connection_close)(self.handle) };
    }
}

impl Stream {
    pub fn new(connection: &Connection, flags: StreamOpenFlags, handler: StreamEventHandler, context: *const c_void) -> Stream {
        let new_stream: Handle = ptr::null();
        let status = unsafe { ((*connection.table).stream_open)(connection.handle, flags, handler, context, &new_stream) };
        if Status::failed(status) {
            panic!("StreamOpen failure 0x{:x}", status);
        }
        Stream {
            table: connection.table,
            handle: new_stream,
        }
    }

    pub fn start(&self, flags: StreamStartFlags) {
        let status = unsafe { ((*self.table).stream_start)(self.handle, flags) };
        if Status::failed(status) {
            panic!("StreamStart failure 0x{:x}", status);
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe { ((*self.table).stream_close)(self.handle) };
    }
}

#[allow(dead_code)] // Used in test code
extern fn test_conn_callback(_connection: Handle, context: *mut c_void, event: &ConnectionEvent) -> u64 {
    let api = unsafe {&*(context as *const Api) };
    match event.event_type {
        CONNECTION_EVENT_CONNECTED => println!("Connected"),
        CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT => println!("Transport shutdown 0x{:x}", unsafe {event.payload.shutdown_initiated_by_transport.status}),
        CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER => println!("App shutdown {}", unsafe {event.payload.shutdown_initiated_by_peer.error_code}),
        CONNECTION_EVENT_SHUTDOWN_COMPLETE => println!("Shutdown complete"),
        CONNECTION_EVENT_PEER_STREAM_STARTED => {
            println!("Peer stream started");
            unsafe { api.set_callback_handler(event.payload.peer_stream_started.stream, test_stream_callback as *const c_void, context) }
        },
        _ => println!("Other callback {}", event.event_type),
    }
    0
}

#[allow(dead_code)] // Used in test code
extern fn test_stream_callback(stream: Handle, context: *mut c_void, event: &StreamEvent) -> u64 {
    let api = unsafe {&*(context as *const Api) };
    match event.event_type {
        STREAM_EVENT_START_COMPLETE => println!("Start complete 0x{:x}", unsafe {event.payload.start_complete.status}),
        STREAM_EVENT_RECEIVE => println!("Receive {} bytes", unsafe {event.payload.receive.total_buffer_length}),
        STREAM_EVENT_SEND_COMPLETE => println!("Send complete"),
        STREAM_EVENT_PEER_SEND_SHUTDOWN => println!("Peer send shutdown"),
        STREAM_EVENT_PEER_SEND_ABORTED => println!("Peer send aborted"),
        STREAM_EVENT_PEER_RECEIVE_ABORTED => println!("Peer receive aborted"),
        STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => println!("Peer receive aborted"),
        STREAM_EVENT_SHUTDOWN_COMPLETE => {
            println!("Shutdown complete");
            unsafe { ((*api.table).stream_close)(stream) };
        },
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

    let alpn = Buffer::from_str("h3");
    let configuration = Configuration::new(&registration, &alpn, Settings::new()
                                                                    .set_peer_bidi_stream_count(100)
                                                                    .set_peer_unidi_stream_count(3));
    let cred_config = CredentialConfig::new_client();
    configuration.load_credential(&cred_config);

    let _connection = Connection::new(&registration, test_conn_callback, (&api as *const Api) as *const c_void);
    /*_connection.start(&configuration, "google.com", 443);

    let duration = std::time::Duration::from_millis(1000);
    std::thread::sleep(duration);*/
}
