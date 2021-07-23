// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use libc::c_void;
use std::ptr;

/// Represents an opaque handle to a MsQuic object.
pub type Handle = *const libc::c_void;

/// Represents an unsigned 62-bit integer.
#[allow(non_camel_case_types)]
pub type u62 = u64;

/// Represents a C-style bool.
pub type BOOLEAN = ::std::os::raw::c_uchar;

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

#[repr(C)]
pub struct Buffer {
    pub length: u32,
    pub buffer: *mut u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RegistrationConfig {
    pub app_name: *const u8,
    pub execution_profile: ExecutionProfile
}

#[repr(C)]
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

#[repr(C)]
pub struct CredentialConfig {
    pub cred_type: CredentialType,
    pub cred_flags: CredentialFlags,
    pub certificate: *const c_void,
    pub principle: *const u8,
    reserved: *const c_void,
    pub async_handler: *const c_void,
    pub allowed_cipher_suites: AllowedCipherSuiteFlags,
}

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

#[repr(C)]
pub struct StreamEvent {
    pub event_type: u32,
}

pub type StreamEventHandler = extern fn(stream: Handle, context: *mut c_void, event: &StreamEvent) -> u64;

#[repr(C)]
struct ApiTable {
    set_context : extern fn(handle: Handle, context: *const c_void),
    get_context : extern fn(handle: Handle) -> *mut c_void,
    set_callback_handler : extern fn(handle: Handle, handler: *const c_void, context: *const c_void),
    set_param : *mut c_void,
    get_param : *mut c_void,
    registration_open : extern fn(config: *const RegistrationConfig, registration: &Handle) -> u64,
    registration_close : extern fn(registration: Handle),
    registration_shutdown : extern fn(registration: Handle),
    configuration_open : extern fn(registration: Handle, alpn_buffers: *const Buffer, alpn_buffer_cout: u32, settings: *const Settings, settings_size: u32, context: *const c_void, configuration: &*const c_void) -> u64,
    configuration_close : extern fn(configuration: Handle),
    configuration_load_credential : extern fn(configuration: Handle, cred_config: *const CredentialConfig) -> u64,
    listener_open : *mut c_void,
    listener_close : extern fn(listener: Handle),
    listener_start : *mut c_void,
    listener_stop : *mut c_void,
    connection_open : extern fn(registration: Handle, handler: ConnectionEventHandler, context: *const c_void, connection: &Handle) -> u64,
    connection_close : extern fn(connection: Handle),
    connection_shutdown : *mut c_void,
    connection_start : extern fn(connection: Handle, configuration: Handle, family: u16, server_name: *const u8, server_port: u16) -> u64,
    connection_set_configuration : *mut c_void,
    connection_send_resumption_ticket : *mut c_void,
    stream_open : *mut c_void,
    stream_close : extern fn(stream: Handle),
    stream_start : *mut c_void,
    stream_shutdown : *mut c_void,
    stream_send : *mut c_void,
    stream_receive_complete : *mut c_void,
    stream_receive_set_enabled : *mut c_void,
    datagram_send : *mut c_void,
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
            certificate: ptr::null(),
            principle: ptr::null(),
            reserved: ptr::null(),
            async_handler: ptr::null(),
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

#[allow(dead_code)] // Used in test code
extern fn test_conn_callback(_connection: Handle, context: *mut c_void, event: &ConnectionEvent) -> u64 {
    let api = unsafe {&*(context as *const Api) };
    match event.event_type {
        CONNECTION_EVENT_CONNECTED => println!("Connected!"),
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

extern fn test_stream_callback(_stream: Handle, _context: *mut c_void, _event: &StreamEvent) -> u64 {
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
