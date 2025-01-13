// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::QUIC_ERROR;

/// Defines quic error code enum and its conversion
/// to raw type using macro.
macro_rules! define_quic_error_code{
  ($( $code1:ident ),*) =>{
    /// Enum of quic status codes.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Clone, PartialEq)]
    #[repr(u32)]
    pub enum ErrorCode {
      $(
        $code1 = crate::ffi::$code1 as u32,
      )*
    }

    /// Convert from ffi type to enum.
    /// Conversion failes when the status value is not a quic status.
    impl std::convert::TryFrom<crate::ffi::QUIC_ERROR> for ErrorCode {
      type Error = &'static str;
      fn try_from(value: crate::ffi::QUIC_ERROR) -> Result<Self, Self::Error> {
          match value {
              $(
                crate::ffi::$code1 => Ok(Self::$code1),
              )*
              _ => Err("Unknown QUIC_ERROR")
          }
      }
    }
  }
}

// defines all quic error codes.
define_quic_error_code!(
    QUIC_ERROR_SUCCESS,
    QUIC_ERROR_PENDING,
    QUIC_ERROR_CONTINUE,
    QUIC_ERROR_OUT_OF_MEMORY,
    QUIC_ERROR_INVALID_PARAMETER,
    QUIC_ERROR_INVALID_STATE,
    QUIC_ERROR_NOT_SUPPORTED,
    QUIC_ERROR_NOT_FOUND,
    QUIC_ERROR_BUFFER_TOO_SMALL,
    QUIC_ERROR_HANDSHAKE_FAILURE,
    QUIC_ERROR_ABORTED,
    QUIC_ERROR_ADDRESS_IN_USE,
    QUIC_ERROR_INVALID_ADDRESS,
    QUIC_ERROR_CONNECTION_TIMEOUT,
    QUIC_ERROR_CONNECTION_IDLE,
    QUIC_ERROR_UNREACHABLE,
    QUIC_ERROR_INTERNAL_ERROR,
    QUIC_ERROR_CONNECTION_REFUSED,
    QUIC_ERROR_PROTOCOL_ERROR,
    QUIC_ERROR_VER_NEG_ERROR,
    QUIC_ERROR_TLS_ERROR,
    QUIC_ERROR_USER_CANCELED,
    QUIC_ERROR_ALPN_NEG_FAILURE,
    QUIC_ERROR_STREAM_LIMIT_REACHED,
    QUIC_ERROR_ALPN_IN_USE,
    QUIC_ERROR_CLOSE_NOTIFY,
    QUIC_ERROR_BAD_CERTIFICATE,
    QUIC_ERROR_UNSUPPORTED_CERTIFICATE,
    QUIC_ERROR_REVOKED_CERTIFICATE,
    QUIC_ERROR_EXPIRED_CERTIFICATE,
    QUIC_ERROR_UNKNOWN_CERTIFICATE,
    QUIC_ERROR_REQUIRED_CERTIFICATE,
    QUIC_ERROR_CERT_EXPIRED,
    QUIC_ERROR_CERT_UNTRUSTED_ROOT,
    QUIC_ERROR_CERT_NO_CERT
);

impl From<ErrorCode> for QUIC_ERROR {
    fn from(value: ErrorCode) -> Self {
        value as QUIC_ERROR
    }
}

/// The display string is the same as the debug string, i.e. the enum string.
impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::write!(f, "{:?}", self)
    }
}

/// Quic error used in non-ffi code.
/// Internal representation matches the os platfrom type.
#[derive(Clone)]
pub struct Error(pub QUIC_ERROR);

impl Error {
    /// Create an error from enum.
    pub fn new(ec: ErrorCode) -> Self {
        Self(ec as QUIC_ERROR)
    }
    /// Convert to error code if possible.
    pub fn try_as_error_code(&self) -> Result<ErrorCode, &str> {
        use std::convert::TryFrom;
        ErrorCode::try_from(self.0 as QUIC_ERROR)
    }

    /// Convert from raw ffi error type.
    pub fn from_raw(ec: QUIC_ERROR) -> Self {
        Self(ec)
    }

    /// Temp api to use in manually written ffi code which is going to be
    /// removed and replaced by auto generated ffi code.
    /// This api will be replaced by from_raw.
    pub fn from_u32(ec: u32) -> Self {
        Self(ec as QUIC_ERROR)
    }

    /// Return Err if the error is considered a failure.
    /// Ok includes both "no error" and "pending" status codes.
    pub fn ok(self) -> Result<(), Self> {
        // on windows it is signed.
        #[cfg(target_os = "windows")]
        if self.0 < 0 {
            Err(self)
        } else {
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        if (self.0 as i32) > 0 {
            Err(self)
        } else {
            Ok(())
        }
    }
}

impl std::error::Error for Error {}

impl From<QUIC_ERROR> for Error {
    fn from(value: QUIC_ERROR) -> Self {
        Self(value)
    }
}

impl From<ErrorCode> for Error {
    fn from(value: ErrorCode) -> Self {
        Self::new(value)
    }
}

/// The debug message is in the same format as error in windows crate.
impl core::fmt::Debug for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = fmt.debug_struct("Error");
        let str_code = match self.try_as_error_code() {
            Ok(c) => Some(c),
            Err(_) => None,
        };
        debug.field("code", &self.0);
        match str_code {
            Some(c) => debug.field("message", &c),
            None => debug.field("message", &"unknown quic error"),
        };
        debug.finish()
    }
}

/// The display message is in the same format as error in windows crate.
impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let str_code = match self.try_as_error_code() {
            Ok(c) => Some(c),
            Err(_) => None,
        };
        match str_code {
            Some(c) => core::write!(fmt, "{} ({})", c, self.0),
            None => core::write!(fmt, "{}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ffi::QUIC_ERROR;

    use super::{Error, ErrorCode};

    #[test]
    fn error_fmt_test() {
        let err = Error::new(ErrorCode::QUIC_ERROR_ABORTED);
        // message is platform dependent.
        #[cfg(target_os = "windows")]
        assert_eq!(format!("{err}"), "QUIC_ERROR_ABORTED (-2147467260)");
        #[cfg(target_os = "windows")]
        assert_eq!(
            format!("{err:?}"),
            "Error { code: -2147467260, message: QUIC_ERROR_ABORTED }"
        );
        let ec = err.try_as_error_code().unwrap();
        assert_eq!(format!("{ec}"), "QUIC_ERROR_ABORTED");
    }

    #[test]
    fn error_ok_test() {
        assert!(Error::new(ErrorCode::QUIC_ERROR_ABORTED).ok().is_err());
        assert!(Error::new(ErrorCode::QUIC_ERROR_SUCCESS).ok().is_ok());
        assert!(Error::from_raw(ErrorCode::QUIC_ERROR_PENDING as QUIC_ERROR)
            .ok()
            .is_ok());
    }
}
