// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ffi::{QUIC_CREDENTIAL_CONFIG, QUIC_REGISTRATION_CONFIG};
use std::ffi::CString;

/// Specifies the configuration for a new registration.
#[derive(Debug, Default)]
pub struct RegistrationConfig {
    app_name: Option<CString>,
    execution_profile: ExecutionProfile,
}

impl RegistrationConfig {
    /// # Safety
    /// ffi type returned needs to have the lifetime of self.
    pub(crate) unsafe fn as_ffi(&self) -> QUIC_REGISTRATION_CONFIG {
        QUIC_REGISTRATION_CONFIG {
            AppName: self
                .app_name
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            ExecutionProfile: self.execution_profile.clone().into(),
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_app_name(mut self, value: String) -> Self {
        self.app_name = Some(CString::new(value).unwrap());
        self
    }

    pub fn set_execution_profile(mut self, value: ExecutionProfile) -> Self {
        self.execution_profile = value;
        self
    }
}

/// Configures how to process a registration's workload.
#[derive(Debug, PartialEq, Clone, Default)]
pub enum ExecutionProfile {
    #[default]
    LowLatency,
    MaxThroughput,
    Scavenger,
    RealTime,
}

impl From<ExecutionProfile> for crate::ffi::QUIC_EXECUTION_PROFILE {
    fn from(value: ExecutionProfile) -> Self {
        match value {
            ExecutionProfile::LowLatency => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_LOW_LATENCY
            }
            ExecutionProfile::MaxThroughput => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT
            }
            ExecutionProfile::Scavenger => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER
            }
            ExecutionProfile::RealTime => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CredentialConfig {
    credential_flags: CredentialFlags,
    credential: Credential,
    principal: Option<CString>, // TODO: support async handler.
    allowed_cipher_suites: AllowedCipherSuiteFlags,
    ca_certificate_file: Option<CString>,
}

impl CredentialConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// flags are additive when called multiple times.
    pub fn set_credential_flags(mut self, value: CredentialFlags) -> Self {
        self.credential_flags |= value;
        self
    }

    pub fn set_credential(mut self, value: Credential) -> Self {
        self.credential = value;
        self
    }

    pub fn set_principal(mut self, value: String) -> Self {
        self.principal = Some(CString::new(value).unwrap());
        self
    }

    pub fn set_allowed_cipher_suites(mut self, value: AllowedCipherSuiteFlags) -> Self {
        self.credential_flags |= CredentialFlags::SET_ALLOWED_CIPHER_SUITES;
        self.allowed_cipher_suites = value;
        self
    }

    pub fn set_ca_certificate_file(mut self, value: String) -> Self {
        self.credential_flags |= CredentialFlags::SET_CA_CERTIFICATE_FILE;
        self.ca_certificate_file = Some(CString::new(value).unwrap());
        self
    }

    /// # Safety
    /// ffi type returned needs to have the lifetime of self.
    pub(crate) unsafe fn as_ffi(&self) -> QUIC_CREDENTIAL_CONFIG {
        let mut ffi_cfg = unsafe { std::mem::zeroed::<QUIC_CREDENTIAL_CONFIG>() };
        ffi_cfg.Flags = self.credential_flags.bits();
        match &self.credential {
            Credential::None => {}
            Credential::CertificateHash(hash) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
                ffi_cfg.__bindgen_anon_1.CertificateHash = (&hash.0) as *const _ as *mut _;
            }
            Credential::CertificateHashStore(hash) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
                ffi_cfg.__bindgen_anon_1.CertificateHashStore = (&hash.0) as *const _ as *mut _;
            }
            Credential::CertificateContext(ctx) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
                ffi_cfg.__bindgen_anon_1.CertificateContext = *ctx as *mut _;
            }
            Credential::CertificateFile(file) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
                ffi_cfg.__bindgen_anon_1.CertificateFile = file.as_ffi_ref() as *const _ as *mut _;
            }
            Credential::CertificateFileProtected(file) => {
                ffi_cfg.Type = crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
                ffi_cfg.__bindgen_anon_1.CertificateFile = file.as_ffi_ref() as *const _ as *mut _;
            }
            Credential::CertificatePkcs12(cert) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
                ffi_cfg.__bindgen_anon_1.CertificatePkcs12 =
                    cert.as_ffi_ref() as *const _ as *mut _;
            }
        }
        ffi_cfg.Principal = self
            .principal
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        ffi_cfg.AllowedCipherSuites = self.allowed_cipher_suites.bits();
        ffi_cfg.CaCertificateFile = self
            .ca_certificate_file
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        ffi_cfg
    }

    pub fn new_client() -> Self {
        Self::default()
            .set_credential_flags(CredentialFlags::CLIENT)
            .set_credential(Credential::None)
    }
}

#[derive(Debug)]
pub struct CertificateHash(crate::ffi::QUIC_CERTIFICATE_HASH);
impl CertificateHash {
    pub fn new(hash: [u8; 20usize]) -> Self {
        Self(crate::ffi::QUIC_CERTIFICATE_HASH { ShaHash: hash })
    }

    /// Construct from string hash.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, crate::Status> {
        Ok(Self::new(Self::decode_hex(s)?))
    }

    /// To hex string
    pub fn to_hex_string(&self) -> String {
        use std::fmt::Write;
        // write every byte in hex.
        self.0.ShaHash.iter().fold(String::new(), |mut out, x| {
            write!(out, "{x:02X}").unwrap();
            out
        })
    }

    /// Helper function to convert hex string of hash into the hash bytes.
    fn decode_hex(s: &str) -> Result<[u8; 20usize], crate::Status> {
        let mut buff = [0_u8; 20usize];
        if s.len() != buff.len() * 2 {
            return Err(crate::StatusCode::QUIC_STATUS_INVALID_PARAMETER.into());
        }
        // Parse every 2 bytes and fill the buffer.
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .zip(buff.iter_mut())
            .try_for_each(|(b, df)| match b {
                Ok(data) => {
                    *df = data;
                    Ok(())
                }
                Err(_) => Err(crate::StatusCode::QUIC_STATUS_INVALID_PARAMETER),
            })?;
        Ok(buff)
    }
}

// QUIC_CERTIFICATE_HASH_STORE
#[derive(Debug)]
pub struct CertificateHashStore(crate::ffi::QUIC_CERTIFICATE_HASH_STORE);

impl CertificateHashStore {
    pub fn new(flags: CertificateHashStoreFlags, hash: [u8; 20], store_name: String) -> Self {
        // prepare slice with nul terminator
        let c_str = CString::new(store_name).unwrap();
        let c_slice = c_str.as_bytes_with_nul();
        let c_slice2 =
            unsafe { std::slice::from_raw_parts(c_slice.as_ptr() as *const i8, c_slice.len()) };
        // copy with nul terminator
        let mut name_buff = [0_i8; 128];
        let chunk = &mut name_buff[..c_slice2.len()];
        chunk.copy_from_slice(c_slice2);
        Self(crate::ffi::QUIC_CERTIFICATE_HASH_STORE {
            Flags: flags.bits(),
            ShaHash: hash,
            StoreName: name_buff,
        })
    }
}

bitflags::bitflags! {
    /// Modifies the default credential configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CertificateHashStoreFlags: crate::ffi::QUIC_CERTIFICATE_HASH_STORE_FLAGS {
        const NONE = crate::ffi::QUIC_CERTIFICATE_HASH_STORE_FLAGS_QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;
        const MACHINE_STORE = crate::ffi::QUIC_CERTIFICATE_HASH_STORE_FLAGS_QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE;
    }
}

#[derive(Debug)]
pub struct CertificateFile {
    raw: crate::ffi::QUIC_CERTIFICATE_FILE,
    _private_key_file: CString,
    _certificate_file: CString,
}

impl CertificateFile {
    pub fn new(private_key_file: String, certificate_file: String) -> Self {
        let key = CString::new(private_key_file).unwrap();
        let cert = CString::new(certificate_file).unwrap();
        Self {
            raw: crate::ffi::QUIC_CERTIFICATE_FILE {
                PrivateKeyFile: key.as_ptr(),
                CertificateFile: cert.as_ptr(),
            },
            _private_key_file: key,
            _certificate_file: cert,
        }
    }

    pub fn as_ffi_ref(&self) -> &crate::ffi::QUIC_CERTIFICATE_FILE {
        &self.raw
    }
}

#[derive(Debug)]
pub struct CertificateFileProtected {
    raw: crate::ffi::QUIC_CERTIFICATE_FILE_PROTECTED,
    _private_key_file: CString,
    _certificate_file: CString,
    _private_key_password: CString,
}

impl CertificateFileProtected {
    pub fn new(
        private_key_file: String,
        certificate_file: String,
        private_key_password: String,
    ) -> Self {
        let key = CString::new(private_key_file).unwrap();
        let cert = CString::new(certificate_file).unwrap();
        let pwd = CString::new(private_key_password).unwrap();
        Self {
            raw: crate::ffi::QUIC_CERTIFICATE_FILE_PROTECTED {
                PrivateKeyFile: key.as_ptr(),
                CertificateFile: cert.as_ptr(),
                PrivateKeyPassword: pwd.as_ptr(),
            },
            _private_key_file: key,
            _certificate_file: cert,
            _private_key_password: pwd,
        }
    }

    pub fn as_ffi_ref(&self) -> &crate::ffi::QUIC_CERTIFICATE_FILE_PROTECTED {
        &self.raw
    }
}

#[derive(Debug)]
pub struct CertificatePkcs12 {
    raw: crate::ffi::QUIC_CERTIFICATE_PKCS12,
    _asn1_blob: Vec<u8>,
    _private_key_password: Option<CString>,
}

impl CertificatePkcs12 {
    pub fn new(asn1_blob: Vec<u8>, private_key_password: Option<CString>) -> Self {
        Self {
            raw: crate::ffi::QUIC_CERTIFICATE_PKCS12 {
                Asn1Blob: asn1_blob.as_ptr(),
                Asn1BlobLength: asn1_blob.len() as u32,
                PrivateKeyPassword: private_key_password
                    .as_ref()
                    .map(|p| p.as_ptr())
                    .unwrap_or(std::ptr::null()),
            },
            _asn1_blob: asn1_blob,
            _private_key_password: private_key_password,
        }
    }

    pub fn as_ffi_ref(&self) -> &crate::ffi::QUIC_CERTIFICATE_PKCS12 {
        &self.raw
    }
}

/// Type of credentials used for a connection.
#[derive(Debug, Default)]
pub enum Credential {
    #[default]
    None,
    /// windows schannel only
    CertificateHash(CertificateHash),
    /// windows schannel only
    CertificateHashStore(CertificateHashStore),
    /// windows user mode only
    CertificateContext(*const crate::ffi::QUIC_CERTIFICATE),
    /// quictls only
    CertificateFile(CertificateFile),
    /// quictls only
    CertificateFileProtected(CertificateFileProtected),
    /// quictls only
    CertificatePkcs12(CertificatePkcs12),
}

bitflags::bitflags! {
/// Modifies the default credential configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialFlags: crate::ffi::QUIC_CREDENTIAL_FLAGS {
  const NONE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_NONE;
  const CLIENT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_CLIENT;
  const LOAD_ASYNCHRONOUS = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS;
  const NO_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  const ENABLE_OCSP = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_ENABLE_OCSP;
  const INDICATE_CERTIFICATE_RECEIVED = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
  const DEFER_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION;
  const REQUIRE_CLIENT_AUTHENTICATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
  const USE_TLS_BUILTIN_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
  const REVOCATION_CHECK_END_CERT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT;
  const REVOCATION_CHECK_CHAIN = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN;
  const REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
  const IGNORE_NO_REVOCATION_CHECK = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK;
  const IGNORE_REVOCATION_OFFLINE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE;
  const SET_ALLOWED_CIPHER_SUITES = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
  const USE_PORTABLE_CERTIFICATES = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;
  const USE_SUPPLIED_CREDENTIALS = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS;
  const USE_SYSTEM_MAPPER = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER;
  const CACHE_ONLY_URL_RETRIEVAL = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL;
  const REVOCATION_CHECK_CACHE_ONLY = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY;
  const INPROC_PEER_CERTIFICATE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE;
  const SET_CA_CERTIFICATE_FILE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
  const DISABLE_AIA = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_DISABLE_AIA;
  // reject undefined flags.
  const _ = !0;
  }
}

impl Default for CredentialFlags {
    fn default() -> Self {
        Self::NONE
    }
}

bitflags::bitflags! {
  /// Set of allowed TLS cipher suites.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct AllowedCipherSuiteFlags: crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS {
    const NONE = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_NONE;
    const AES_128_GCM_SHA256 = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256;
    const AES_256_GCM_SHA384 = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384;
    const CHACHA20_POLY1305_SHA256  = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;
    // reject undefined flags.
    const _ = !0;
  }
}

impl Default for AllowedCipherSuiteFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// Disable macos because the ffi bindings is using linux
// for macos and it has error code mismatch.
#[cfg(not(target_os = "macos"))]
#[cfg(test)]
mod tests {
    use crate::{
        config::{
            CertificateFile, CertificateHash, CertificateHashStore, CertificateHashStoreFlags,
            Credential,
        },
        BufferRef, Configuration, Registration, RegistrationConfig, Settings, StatusCode,
    };

    use super::CredentialConfig;

    #[test]
    fn config_load() {
        let registration = Registration::new(&RegistrationConfig::default()).unwrap();

        let alpn = [BufferRef::from("h3")];
        let configuration = Configuration::open(
            &registration,
            &alpn,
            Some(
                &Settings::new()
                    .set_PeerBidiStreamCount(100)
                    .set_PeerUnidiStreamCount(3),
            ),
        )
        .unwrap();

        {
            let cred_config =
                CredentialConfig::new().set_credential_flags(super::CredentialFlags::NONE);
            // server cred missing
            assert_eq!(
                configuration
                    .load_credential(&cred_config)
                    .unwrap_err()
                    .try_as_status_code()
                    .unwrap(),
                StatusCode::QUIC_STATUS_INVALID_PARAMETER
            );
            // zero hash
            let cred_config = cred_config
                .set_credential(Credential::CertificateHash(CertificateHash::new([0; 20])));
            let load_err = configuration
                .load_credential(&cred_config)
                .unwrap_err()
                .try_as_status_code()
                .unwrap();
            if cfg!(windows) {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_FOUND);
            } else {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_SUPPORTED);
            }
            // key and cert file not found
            let cred_config = cred_config.set_credential(Credential::CertificateFile(
                CertificateFile::new(String::from("./no_key"), String::from("./no_cert")),
            ));
            let load_err = configuration
                .load_credential(&cred_config)
                .unwrap_err()
                .try_as_status_code()
                .unwrap();
            if cfg!(windows) && !cfg!(feature = "openssl") && !cfg!(feature = "quictls") {
                // schannel does not support load from file.
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_SUPPORTED);
            } else {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_TLS_ERROR);
            }

            // cert with empty hash store.
            let cred_config = cred_config.set_credential(Credential::CertificateHashStore(
                CertificateHashStore::new(
                    CertificateHashStoreFlags::MACHINE_STORE,
                    [0; 20],
                    String::from("MY"),
                ),
            ));
            let load_err = configuration
                .load_credential(&cred_config)
                .unwrap_err()
                .try_as_status_code()
                .unwrap();
            if cfg!(windows) {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_FOUND);
            } else {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_SUPPORTED);
            }

            // empty context
            let cred_config =
                cred_config.set_credential(Credential::CertificateContext(std::ptr::null()));
            let load_err = configuration
                .load_credential(&cred_config)
                .unwrap_err()
                .try_as_status_code()
                .unwrap();
            if cfg!(windows) {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_INVALID_PARAMETER);
            } else {
                assert_eq!(load_err, StatusCode::QUIC_STATUS_NOT_SUPPORTED);
            }
        }
    }

    #[test]
    fn hash_test() {
        let hex_str = "0E31650DFB5283AB820E3735FD2B254A286F46B3";
        let hash = CertificateHash::from_str(hex_str).expect("fail to convert hash");
        let hex = hash.to_hex_string();
        assert_eq!(hex_str, hex);
    }
}
