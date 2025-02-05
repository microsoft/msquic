// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::QUIC_STATUS;

/// Defines quic error status enum and its conversion
/// to raw type using macro.
macro_rules! define_quic_status_code{
  ($( $code1:ident ),*) =>{
    /// Enum of quic status codes.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Clone, PartialEq)]
    #[repr(u32)]
    pub enum StatusCode {
      $(
        $code1 = crate::ffi::$code1 as u32,
      )*
    }

    /// Convert from ffi type to enum.
    /// Conversion failes when the status value is not a quic status.
    impl std::convert::TryFrom<crate::ffi::QUIC_STATUS> for StatusCode {
      type Error = &'static str;
      fn try_from(value: crate::ffi::QUIC_STATUS) -> Result<Self, Self::Error> {
          match value {
              $(
                crate::ffi::$code1 => Ok(Self::$code1),
              )*
              _ => Err("Unknown QUIC_STATUS")
          }
      }
    }
  }
}

// defines all quic error codes.
define_quic_status_code!(
    QUIC_STATUS_SUCCESS,
    QUIC_STATUS_PENDING,
    QUIC_STATUS_CONTINUE,
    QUIC_STATUS_OUT_OF_MEMORY,
    QUIC_STATUS_INVALID_PARAMETER,
    QUIC_STATUS_INVALID_STATE,
    QUIC_STATUS_NOT_SUPPORTED,
    QUIC_STATUS_NOT_FOUND,
    QUIC_STATUS_BUFFER_TOO_SMALL,
    QUIC_STATUS_HANDSHAKE_FAILURE,
    QUIC_STATUS_ABORTED,
    QUIC_STATUS_ADDRESS_IN_USE,
    QUIC_STATUS_INVALID_ADDRESS,
    QUIC_STATUS_CONNECTION_TIMEOUT,
    QUIC_STATUS_CONNECTION_IDLE,
    QUIC_STATUS_UNREACHABLE,
    QUIC_STATUS_INTERNAL_ERROR,
    QUIC_STATUS_CONNECTION_REFUSED,
    QUIC_STATUS_PROTOCOL_ERROR,
    QUIC_STATUS_VER_NEG_ERROR,
    QUIC_STATUS_TLS_ERROR,
    QUIC_STATUS_USER_CANCELED,
    QUIC_STATUS_ALPN_NEG_FAILURE,
    QUIC_STATUS_STREAM_LIMIT_REACHED,
    QUIC_STATUS_ALPN_IN_USE,
    QUIC_STATUS_CLOSE_NOTIFY,
    QUIC_STATUS_BAD_CERTIFICATE,
    QUIC_STATUS_UNSUPPORTED_CERTIFICATE,
    QUIC_STATUS_REVOKED_CERTIFICATE,
    QUIC_STATUS_EXPIRED_CERTIFICATE,
    QUIC_STATUS_UNKNOWN_CERTIFICATE,
    QUIC_STATUS_REQUIRED_CERTIFICATE,
    QUIC_STATUS_CERT_EXPIRED,
    QUIC_STATUS_CERT_UNTRUSTED_ROOT,
    QUIC_STATUS_CERT_NO_CERT
);

impl From<StatusCode> for QUIC_STATUS {
    fn from(value: StatusCode) -> Self {
        value as QUIC_STATUS
    }
}

/// The display string is the same as the debug string, i.e. the enum string.
impl core::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::write!(f, "{:?}", self)
    }
}

/// Quic status used in non-ffi code.
/// Internal representation matches the os platfrom type.
/// Used for all non-ffi error return and callback status code fields.
#[derive(Clone)]
pub struct Status(pub QUIC_STATUS);

impl Status {
    /// Create an status from enum.
    pub fn new(ec: StatusCode) -> Self {
        Self(ec as QUIC_STATUS)
    }
    /// Convert to status code if possible.
    pub fn try_as_status_code(&self) -> Result<StatusCode, &str> {
        use std::convert::TryFrom;
        StatusCode::try_from(self.0 as QUIC_STATUS)
    }

    /// Convert from raw ffi status type.
    pub fn ok_from_raw(ec: QUIC_STATUS) -> Result<(), Self> {
        let e = Self(ec);
        if e.is_ok() {
            Ok(())
        } else {
            Err(e)
        }
    }

    /// Return Err if the status is considered a failure.
    /// Ok includes both "no error" and "pending" status codes.
    pub fn is_ok(&self) -> bool {
        // on windows it is signed.
        #[cfg(target_os = "windows")]
        return self.0 >= 0;

        #[cfg(not(target_os = "windows"))]
        return self.0 as i32 <= 0;
    }
}

impl std::error::Error for Status {}

impl From<QUIC_STATUS> for Status {
    fn from(value: QUIC_STATUS) -> Self {
        Self(value)
    }
}

impl From<StatusCode> for Status {
    fn from(value: StatusCode) -> Self {
        Self::new(value)
    }
}

/// The debug message is in the same format as error in windows crate.
impl core::fmt::Debug for Status {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = fmt.debug_struct("Error");
        let str_code = match self.try_as_status_code() {
            Ok(c) => Some(c),
            Err(_) => None,
        };
        debug.field("code", &format_args!("0x{:x}", self.0));
        match str_code {
            Some(c) => debug.field("message", &c),
            None => debug.field("message", &"unknown quic error"),
        };
        debug.finish()
    }
}

/// The display message is in the same format as error in windows crate.
impl core::fmt::Display for Status {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let str_code = match self.try_as_status_code() {
            Ok(c) => Some(c),
            Err(_) => None,
        };
        match str_code {
            Some(c) => core::write!(fmt, "{} (0x{:x})", c, self.0),
            None => core::write!(fmt, "0x{:x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi::QUIC_STATUS;

    use super::{Status, StatusCode};

    #[test]
    fn error_fmt_test() {
        let err = Status::new(StatusCode::QUIC_STATUS_ABORTED);
        // message is platform dependent.
        #[cfg(target_os = "windows")]
        assert_eq!(format!("{err}"), "QUIC_STATUS_ABORTED (0x80004004)");
        #[cfg(target_os = "windows")]
        assert_eq!(
            format!("{err:?}"),
            "Error { code: 0x80004004, message: QUIC_STATUS_ABORTED }"
        );
        let ec = err.try_as_status_code().unwrap();
        assert_eq!(format!("{ec}"), "QUIC_STATUS_ABORTED");
    }

    #[test]
    fn error_ok_test() {
        assert!(!Status::new(StatusCode::QUIC_STATUS_ABORTED).is_ok());
        assert!(Status::new(StatusCode::QUIC_STATUS_SUCCESS).is_ok());
        assert!(Status::ok_from_raw(StatusCode::QUIC_STATUS_PENDING as QUIC_STATUS).is_ok());
    }
}
