#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]

pub type QUIC_ADDR = std::ffi::c_void;

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
