// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::ffi::QUIC_SETTINGS;

/// Type of resumption behavior on the server side.
pub enum ServerResumptionLevel {
    NoResume,
    ResumeOnly,
    ResumeAndZerortt,
}

impl From<ServerResumptionLevel> for crate::ffi::QUIC_SERVER_RESUMPTION_LEVEL {
    fn from(value: ServerResumptionLevel) -> Self {
        match value {
            ServerResumptionLevel::NoResume => {
                crate::ffi::QUIC_SERVER_RESUMPTION_LEVEL_QUIC_SERVER_NO_RESUME
            }
            ServerResumptionLevel::ResumeOnly => {
                crate::ffi::QUIC_SERVER_RESUMPTION_LEVEL_QUIC_SERVER_RESUME_ONLY
            }
            ServerResumptionLevel::ResumeAndZerortt => {
                crate::ffi::QUIC_SERVER_RESUMPTION_LEVEL_QUIC_SERVER_RESUME_AND_ZERORTT
            }
        }
    }
}

/// Settings for MsQuic
/// Wrapping QUIC_SETTINGS ffi type.
pub struct Settings {
    inner: QUIC_SETTINGS,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            inner: unsafe { std::mem::zeroed::<QUIC_SETTINGS>() },
        }
    }
}

/// Macro to define function to set the setting entry in ffi type.
/// It sets the IsSet bitflag for the entry, and set the value.
/// Arguments are: function name, settings field name, settings field type.
macro_rules! define_settings_entry {
    ( $fn_name:ident, $field_name:ident, $tp:ty ) => {
        pub fn $fn_name(mut self, value: $tp) -> Self {
            unsafe { self.inner.__bindgen_anon_1.IsSet.$fn_name(1) };
            self.inner.$field_name = value;
            self
        }
    };
}

/// Macro to define function to set a bit flag in ffi type.
/// It sets the IsSet bitflag for the entry and set the bit flage value.
macro_rules! define_settings_entry_bitflag {
    ( $fn_name:ident) => {
        pub fn $fn_name(mut self) -> Self {
            unsafe { self.inner.__bindgen_anon_1.IsSet.$fn_name(1) };
            self.inner.$fn_name(1);
            self
        }
    };
}

/// Macro to define function to set a bit flag in a substruct.
/// It sets the IsSet bitflag for the entry and set the bit flage value.
macro_rules! define_settings_entry_bitflag2 {
    ( $fn_name:ident) => {
        pub fn $fn_name(mut self) -> Self {
            unsafe { self.inner.__bindgen_anon_1.IsSet.$fn_name(1) };
            unsafe { self.inner.__bindgen_anon_2.__bindgen_anon_1.$fn_name(1) };
            self
        }
    };
}

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_ffi_ref(&self) -> &QUIC_SETTINGS {
        &self.inner
    }
}

// Defines the setters for each setting.
// Keep the casing as the ffi function for easy of using macro.
#[allow(non_snake_case)]
impl Settings {
    define_settings_entry!(set_MaxBytesPerKey, MaxBytesPerKey, u64);
    define_settings_entry!(set_HandshakeIdleTimeoutMs, HandshakeIdleTimeoutMs, u64);
    define_settings_entry!(set_IdleTimeoutMs, IdleTimeoutMs, u64);
    define_settings_entry!(
        set_MtuDiscoverySearchCompleteTimeoutUs,
        MtuDiscoverySearchCompleteTimeoutUs,
        u64
    );
    define_settings_entry!(set_TlsClientMaxSendBuffer, TlsClientMaxSendBuffer, u32);
    define_settings_entry!(set_TlsServerMaxSendBuffer, TlsServerMaxSendBuffer, u32);
    define_settings_entry!(set_StreamRecvWindowDefault, StreamRecvWindowDefault, u32);
    define_settings_entry!(set_StreamRecvBufferDefault, StreamRecvBufferDefault, u32);
    define_settings_entry!(set_ConnFlowControlWindow, ConnFlowControlWindow, u32);
    define_settings_entry!(set_MaxWorkerQueueDelayUs, MaxWorkerQueueDelayUs, u32);
    define_settings_entry!(set_MaxStatelessOperations, MaxStatelessOperations, u32);
    define_settings_entry!(set_InitialWindowPackets, InitialWindowPackets, u32);
    define_settings_entry!(set_SendIdleTimeoutMs, SendIdleTimeoutMs, u32);
    define_settings_entry!(set_InitialRttMs, InitialRttMs, u32);
    define_settings_entry!(set_MaxAckDelayMs, MaxAckDelayMs, u32);
    define_settings_entry!(set_DisconnectTimeoutMs, DisconnectTimeoutMs, u32);
    define_settings_entry!(set_KeepAliveIntervalMs, KeepAliveIntervalMs, u32);
    define_settings_entry!(
        set_CongestionControlAlgorithm,
        CongestionControlAlgorithm,
        u16
    );
    define_settings_entry!(set_PeerBidiStreamCount, PeerBidiStreamCount, u16);
    define_settings_entry!(set_PeerUnidiStreamCount, PeerUnidiStreamCount, u16);
    define_settings_entry!(
        set_MaxBindingStatelessOperations,
        MaxBindingStatelessOperations,
        u16
    );
    define_settings_entry!(
        set_StatelessOperationExpirationMs,
        StatelessOperationExpirationMs,
        u16
    );
    define_settings_entry!(set_MinimumMtu, MinimumMtu, u16);
    define_settings_entry!(set_MaximumMtu, MaximumMtu, u16);
    define_settings_entry_bitflag!(set_SendBufferingEnabled);
    define_settings_entry_bitflag!(set_PacingEnabled);
    define_settings_entry_bitflag!(set_MigrationEnabled);
    define_settings_entry_bitflag!(set_DatagramReceiveEnabled);

    pub fn set_ServerResumptionLevel(mut self, value: ServerResumptionLevel) -> Self {
        unsafe {
            self.inner
                .__bindgen_anon_1
                .IsSet
                .set_ServerResumptionLevel(1)
        };
        self.inner
            .set_ServerResumptionLevel(crate::ffi::QUIC_SERVER_RESUMPTION_LEVEL::from(value) as u8);
        self
    }

    define_settings_entry!(set_MaxOperationsPerDrain, MaxOperationsPerDrain, u8);
    define_settings_entry!(
        set_MtuDiscoveryMissingProbeCount,
        MtuDiscoveryMissingProbeCount,
        u8
    );
    define_settings_entry!(
        set_DestCidUpdateIdleTimeoutMs,
        DestCidUpdateIdleTimeoutMs,
        u32
    );
    define_settings_entry_bitflag!(set_GreaseQuicBitEnabled);
    define_settings_entry_bitflag!(set_EcnEnabled);

    define_settings_entry_bitflag2!(set_HyStartEnabled);

    // preview features

    #[cfg(feature = "preview-api")]
    define_settings_entry_bitflag2!(set_EncryptionOffloadAllowed);
    #[cfg(feature = "preview-api")]
    define_settings_entry_bitflag2!(set_ReliableResetEnabled);
    #[cfg(feature = "preview-api")]
    define_settings_entry_bitflag2!(set_OneWayDelayEnabled);
    #[cfg(feature = "preview-api")]
    define_settings_entry_bitflag2!(set_NetStatsEventEnabled);
    #[cfg(feature = "preview-api")]
    define_settings_entry_bitflag2!(set_StreamMultiReceiveEnabled);

    define_settings_entry!(
        set_StreamRecvWindowBidiLocalDefault,
        StreamRecvWindowBidiLocalDefault,
        u32
    );
    define_settings_entry!(
        set_StreamRecvWindowBidiRemoteDefault,
        StreamRecvWindowBidiRemoteDefault,
        u32
    );
    define_settings_entry!(
        set_StreamRecvWindowUnidiDefault,
        StreamRecvWindowUnidiDefault,
        u32
    );
}

#[cfg(test)]
mod tests {
    use super::Settings;

    #[test]
    fn test_bit_field() {
        let s = Settings::new()
            .set_PeerBidiStreamCount(3)
            .set_PeerUnidiStreamCount(4);
        assert_eq!(3, s.as_ffi_ref().PeerBidiStreamCount);
        assert_eq!(4, s.as_ffi_ref().PeerUnidiStreamCount);
    }
}
