// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate libc;

pub mod msquic {

pub struct Status { }

impl Status {
    pub fn succeeded(status: u64) -> bool {
        (status as i64) >= 0
    }

    pub fn failed(status: u64) -> bool {
        (status as i64) < 0
    }
}

#[repr(C)]
pub struct Buffer {
    pub length: u32,
    pub buffer: *mut u8,
}

#[repr(C)]
pub struct RegistrationConfig {
    pub app_name: *const u8,
    pub execution_profile: u32
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
    pub desired_version_list: *const libc::c_void,
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
    pub cred_type: u32,
    pub cred_flags: u32,
    pub certificate: *const libc::c_void,
    pub principle: *const libc::c_void,
    reserved: *const libc::c_void,
    pub async_handler: *const libc::c_void,
    pub allowed_cipher_suites: *const libc::c_void,
}

#[repr(C)]
pub struct ConnectionEvent {
    pub event_type: u32,
}

#[repr(C)]
pub struct StreamEvent {
    pub event_type: u32,
}

#[repr(C)]
struct ApiTable {
    set_context : extern fn(handle: *const libc::c_void, context: *const libc::c_void),
    get_context : extern fn(handle: *const libc::c_void) -> *mut libc::c_void,
    set_callback_handler : extern fn(handle: *const libc::c_void, handler: *const libc::c_void, context: *const libc::c_void),
    set_param : *mut libc::c_void,
    get_param : *mut libc::c_void,
    registration_open : extern fn(config: *const RegistrationConfig, registration: &*const libc::c_void) -> u64,
    registration_close : extern fn(registration: *const libc::c_void),
    registration_shutdown : extern fn(registration: *const libc::c_void),
    configuration_open : extern fn(registration: *const libc::c_void, alpn_buffers: *const Buffer, alpn_buffer_cout: u32, settings: *const Settings, settings_size: u32, context: *const libc::c_void, configuration: &*const libc::c_void) -> u64,
    configuration_close : extern fn(configuration: *const libc::c_void),
    configuration_load_credential : extern fn(configuration: *const libc::c_void, cred_config: *const CredentialConfig) -> u64,
    listener_open : *mut libc::c_void,
    listener_close : extern fn(listener: *const libc::c_void),
    listener_start : *mut libc::c_void,
    listener_stop : *mut libc::c_void,
    connection_open : extern fn(registration: *const libc::c_void, handler: extern fn(connection: *mut libc::c_void, context: *mut libc::c_void, event: &ConnectionEvent), context: *const libc::c_void, connection: &*const libc::c_void) -> u64,
    connection_close : extern fn(connection: *const libc::c_void),
    connection_shutdown : *mut libc::c_void,
    connection_start : extern fn(connection: *const libc::c_void, configuration: *const libc::c_void, family: u16, server_name: *const u8, server_port: u16) -> u64,
    connection_set_configuration : *mut libc::c_void,
    connection_send_resumption_ticket : *mut libc::c_void,
    stream_open : *mut libc::c_void,
    stream_close : extern fn(stream: *const libc::c_void),
    stream_start : *mut libc::c_void,
    stream_shutdown : *mut libc::c_void,
    stream_send : *mut libc::c_void,
    stream_receive_complete : *mut libc::c_void,
    stream_receive_set_enabled : *mut libc::c_void,
    datagram_send : *mut libc::c_void,
}

#[cfg(target_os="windows")]
#[link(name = "msquic")] // TODO - support kind = "static"
extern {
    fn MsQuicOpenVersion(version: u32, api: &*const ApiTable) -> u64;
    fn MsQuicClose(api: *const ApiTable);
}

#[cfg(target_os="linux")]
#[link(name = "libmsquic")]
extern {
    fn MsQuicOpenVersion(version: u32, api: &*const ApiTable) -> u64;
    fn MsQuicClose(api: *const ApiTable);
}

pub struct Api {
    table: *const ApiTable,
}

pub struct Registration {
    table: *const ApiTable,
    handle: *const libc::c_void,
}

pub struct Configuration {
    table: *const ApiTable,
    handle: *const libc::c_void,
}

pub struct Connection {
    table: *const ApiTable,
    handle: *const libc::c_void,
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
            desired_version_list: std::ptr::null(),
            desired_version_list_length: 0,
            minimum_mtu: 0,
            maximum_mtu: 0,
            mtu_discovery_search_complete_timeout_us: 0,
            mtu_discovery_missing_probe_count: 0,
            max_binding_stateless_operations: 0,
            stateless_operation_expiration_ms: 0,
        }
    }
    pub fn set_peer_bidi_stream_count(&mut self, value: u16) {
        self.is_set_flags |= 0x10000;
        self.peer_bidi_stream_count = value;
    }
    pub fn set_peer_unidi_stream_count(&mut self, value: u16) {
        self.is_set_flags |= 0x20000;
        self.peer_unidi_stream_count = value;
    }
}

impl CredentialConfig {
    pub fn new_client() -> CredentialConfig {
        CredentialConfig {
            cred_type: 0,   // QUIC_CREDENTIAL_TYPE_NONE
            cred_flags: 1,  // QUIC_CREDENTIAL_FLAG_CLIENT
            certificate: std::ptr::null(),
            principle: std::ptr::null(),
            reserved: std::ptr::null(),
            async_handler: std::ptr::null(),
            allowed_cipher_suites: std::ptr::null(),
        }
    }
}

impl Api {
    pub fn new() -> Api {
        let new_table: *const ApiTable = std::ptr::null();
        let status = unsafe { MsQuicOpenVersion(1, &new_table) };
        if Status::failed(status) {
            panic!("MsQuicOpenVersion failure 0x{:x}", status);
        }
        Api {
            table: new_table,
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe { MsQuicClose(self.table) };
    }
}

impl Registration {
    pub fn new(api: &Api, config: *const RegistrationConfig) -> Registration {
        let new_registration: *const libc::c_void = std::ptr::null();
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
        unsafe { ((*self.table).registration_shutdown)(self.handle) };
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        unsafe { ((*self.table).registration_close)(self.handle) };
    }
}

impl Configuration {
    pub fn new(registration: &Registration, alpn: &Buffer, settings: *const Settings) -> Configuration {
        let context: *const libc::c_void = std::ptr::null();
        let new_configuration: *const libc::c_void = std::ptr::null();
        let mut settings_size: u32 = 0;
        if settings != std::ptr::null() {
            settings_size = 128
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
    pub fn new(registration: &Registration, handler: extern fn(connection: *mut libc::c_void, context: *mut libc::c_void, event: &ConnectionEvent), context: *const libc::c_void) -> Connection {
        let new_connection: *const libc::c_void = std::ptr::null();
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

#[test] // TODO - Figure out how to get the DLL load path working properly.
fn test_module() {
    let api = Api::new();
    let registration = Registration::new(&api, std::ptr::null());

    let alpn = Buffer::from_str("h3");
    let mut settings = Settings::new();
    settings.set_peer_bidi_stream_count(100);
    settings.set_peer_unidi_stream_count(3);
    let configuration = Configuration::new(&registration, &alpn, &settings);
    let cred_config = CredentialConfig::new_client();
    configuration.load_credential(&cred_config);
}

}
