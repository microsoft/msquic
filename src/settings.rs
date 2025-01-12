use crate::ffi::QUIC_SETTINGS;

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

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_peer_bidi_stream_count(&mut self, value: u16) -> &mut Self {
        unsafe { self.inner.__bindgen_anon_1.IsSet.set_PeerBidiStreamCount(1) };
        self.inner.PeerBidiStreamCount = value;
        self
    }

    pub fn get_peer_bidi_stream_count(&self) -> Option<u16> {
        if unsafe { self.inner.__bindgen_anon_1.IsSet.PeerBidiStreamCount() } == 0 {
            None
        } else {
            Some(self.inner.PeerBidiStreamCount)
        }
    }

    pub fn set_peer_unidi_stream_count(&mut self, value: u16) -> &mut Self {
        unsafe {
            self.inner
                .__bindgen_anon_1
                .IsSet
                .set_PeerUnidiStreamCount(1)
        };
        self.inner.PeerUnidiStreamCount = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::Settings;

    #[test]
    fn test_bit_field() {
        let mut s = Settings::new();
        s.set_peer_bidi_stream_count(3)
            .set_peer_unidi_stream_count(4);
        assert_eq!(Some(3), s.get_peer_bidi_stream_count());
    }
}
