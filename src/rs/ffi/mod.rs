#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]

pub type QUIC_ADDR = std::ffi::c_void;

#[cfg(target_os = "windows")]
pub type HANDLE = std::os::windows::raw::HANDLE;

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct OVERLAPPED {
    pub Internal: ::std::os::raw::c_ulonglong,
    pub InternalHigh: ::std::os::raw::c_ulonglong,
    pub __bindgen_anon_1: OVERLAPPED__bindgen_ty_1,
    pub hEvent: std::os::windows::raw::HANDLE,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union OVERLAPPED__bindgen_ty_1 {
    pub __bindgen_anon_1: OVERLAPPED__bindgen_ty_1__bindgen_ty_1,
    pub Pointer: *mut ::std::os::raw::c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OVERLAPPED__bindgen_ty_1__bindgen_ty_1 {
    pub Offset: ::std::os::raw::c_ulong,
    pub OffsetHigh: ::std::os::raw::c_ulong,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OVERLAPPED_ENTRY {
    pub lpCompletionKey: ::std::os::raw::c_ulonglong,
    pub lpOverlapped: *mut OVERLAPPED,
    pub Internal: ::std::os::raw::c_ulonglong,
    pub dwNumberOfBytesTransferred: ::std::os::raw::c_ulong,
}

#[cfg(target_os = "linux")]
pub type epoll_event = libc::epoll_event;

#[cfg(target_os = "macos")]
pub type epoll_event = u32; // HACK: TODO - Fix once we have macOS support

// TODO: macos currently is using the linux bindings.
#[cfg(not(target_os = "windows"))]
pub type sa_family_t = u16;
#[cfg(not(target_os = "windows"))]
include!("linux_bindings.rs");

#[cfg(target_os = "windows")]
pub type ADDRESS_FAMILY = u16;
#[cfg(target_os = "windows")]
include!("win_bindings.rs");

/// Temp type for casting manual ffi flags. To be removed eventually.
#[cfg(not(target_os = "windows"))]
pub type QuicFlag = u32;
#[cfg(target_os = "windows")]
pub type QuicFlag = i32;
