#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]

pub type QUIC_ADDR = std::ffi::c_void;

#[cfg(target_os = "linux")]
pub type sa_family_t = u16;
#[cfg(target_os = "linux")]
include!("linux_bindings.rs");

#[cfg(target_os = "windows")]
pub type ADDRESS_FAMILY = u16;
#[cfg(target_os = "windows")]
include!("win_bindings.rs");
