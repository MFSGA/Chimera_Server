use bytes::BytesMut;
use tracing::debug;

const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_AES_128_CCM_SHA256: u16 = 0x1304;
const TLS13_SUPPORTED_VERSION: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

#[derive(Debug)]
pub(crate) struct VisionTlsState {
    packets_left: u8,
    pub(crate) is_tls: bool,
    pub(crate) is_tls12_or_above: bool,
    pub(crate) enable_direct: bool,
    uplink_records: BytesMut,
    downlink_records: BytesMut,
    server_hello: Vec<u8>,
}

impl Default for VisionTlsState {
    fn default() -> Self {
        Self {
            packets_left: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_direct: false,
            uplink_records: BytesMut::new(),
            downlink_records: BytesMut::new(),
            server_hello: Vec::new(),
        }
    }
}

impl VisionTlsState {
    /// Mirrors xray-core's shared TrafficState filter. Both the uplink reader
    /// and downlink writer feed this state so ClientHello and ServerHello can
    /// jointly decide whether the inner TLS stream is safe to penetrate.
    pub(crate) fn observe_uplink(&mut self, data: &[u8]) {
        self.observe_records(data, false);
    }

    pub(crate) fn observe_downlink(&mut self, data: &[u8]) {
        self.observe_records(data, true);
    }

    fn observe_records(&mut self, data: &[u8], downlink: bool) {
        if data.is_empty() || self.packets_left == 0 {
            return;
        }

        if downlink {
            self.downlink_records.extend_from_slice(data);
        } else {
            self.uplink_records.extend_from_slice(data);
        }

        loop {
            let record = {
                let pending = if downlink {
                    &mut self.downlink_records
                } else {
                    &mut self.uplink_records
                };
                if pending.len() < 5 {
                    return;
                }
                if !(0x14..=0x18).contains(&pending[0])
                    || pending[1] != 0x03
                    || !(0x01..=0x03).contains(&pending[2])
                {
                    self.packets_left = self.packets_left.saturating_sub(1);
                    pending.clear();
                    return;
                }

                let record_len =
                    5 + u16::from_be_bytes([pending[3], pending[4]]) as usize;
                if pending.len() < record_len {
                    return;
                }
                pending.split_to(record_len)
            };
            self.packets_left = self.packets_left.saturating_sub(1);
            debug!(
                direction = if downlink { "downlink" } else { "uplink" },
                record_len = record.len(),
                content_type = record.first().copied().unwrap_or_default(),
                handshake_type = record.get(5).copied(),
                packets_left = self.packets_left,
                "VLESS Vision inspected inner TLS record"
            );

            if record.len() >= 6
                && record[0] == TLS_HANDSHAKE
                && record[5] == TLS_CLIENT_HELLO
                && !downlink
            {
                self.is_tls = true;
            }

            if record.len() >= 6
                && record[..3] == [TLS_HANDSHAKE, 0x03, 0x03]
                && record[5] == TLS_SERVER_HELLO
                && downlink
            {
                self.is_tls = true;
                self.is_tls12_or_above = true;
                self.server_hello.clear();
                self.server_hello.extend_from_slice(&record);
                self.finish_server_hello();
            }

            if self.packets_left == 0 {
                return;
            }
        }
    }

    pub(crate) fn should_end_padding_for_compatibility(&self) -> bool {
        !self.is_tls12_or_above && self.packets_left <= 1
    }

    fn finish_server_hello(&mut self) {
        let cipher = self
            .server_hello
            .get(43)
            .and_then(|session_id_len| {
                let offset = 44 + usize::from(*session_id_len);
                self.server_hello.get(offset..offset + 2)
            })
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        let is_tls13 = self
            .server_hello
            .windows(TLS13_SUPPORTED_VERSION.len())
            .any(|window| window == TLS13_SUPPORTED_VERSION);

        self.enable_direct = is_tls13 && cipher.is_some_and(supports_xtls_cipher);
        self.packets_left = 0;
    }
}

fn supports_xtls_cipher(cipher: u16) -> bool {
    matches!(
        cipher,
        TLS_AES_128_GCM_SHA256
            | TLS_AES_256_GCM_SHA384
            | TLS_CHACHA20_POLY1305_SHA256
            | TLS_AES_128_CCM_SHA256
    )
}

/// xray-core only ends padding at a MultiBuffer boundary containing complete
/// TLS application-data records. A partial record must never trigger Direct.
pub(crate) fn is_complete_tls_application_data(data: &[u8]) -> bool {
    let mut cursor = 0usize;
    if data.is_empty() {
        return false;
    }
    while cursor < data.len() {
        if cursor + 5 > data.len()
            || data[cursor] != TLS_APPLICATION_DATA
            || data[cursor + 1] != 0x03
            || data[cursor + 2] != 0x03
        {
            return false;
        }
        let payload_len =
            u16::from_be_bytes([data[cursor + 3], data[cursor + 4]]) as usize;
        cursor += 5 + payload_len;
        if cursor > data.len() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{VisionTlsState, is_complete_tls_application_data};

    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut record = vec![0u8; 80];
        record[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x4b, 0x02]);
        record[43] = 0;
        record[44..46].copy_from_slice(&cipher.to_be_bytes());
        if tls13 {
            record[60..66].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        }
        record
    }

    #[test]
    fn xray_tls13_cipher_matrix() {
        for cipher in [0x1301, 0x1302, 0x1303, 0x1304] {
            let mut state = VisionTlsState::default();
            state.observe_downlink(&server_hello(cipher, true));
            assert!(state.enable_direct, "cipher {cipher:#06x}");
        }

        for cipher in [0x1305, 0x0a0a, 0xc02f] {
            let mut state = VisionTlsState::default();
            state.observe_downlink(&server_hello(cipher, true));
            assert!(!state.enable_direct, "cipher {cipher:#06x}");
        }
    }

    #[test]
    fn collects_a_fragmented_server_hello() {
        let record = server_hello(0x1301, true);
        let mut state = VisionTlsState::default();
        state.observe_downlink(&record[..3]);
        assert!(!state.enable_direct);
        state.observe_downlink(&record[3..50]);
        assert!(!state.enable_direct);
        state.observe_downlink(&record[50..]);
        assert!(state.enable_direct);
    }

    #[test]
    fn rejects_tls12_and_non_tls_for_direct() {
        let mut tls12 = VisionTlsState::default();
        tls12.observe_downlink(&server_hello(0xc02f, false));
        assert!(!tls12.enable_direct);

        let mut plaintext = VisionTlsState::default();
        plaintext.observe_uplink(b"GET / HTTP/1.1\r\n");
        assert!(!plaintext.is_tls);
        assert!(!plaintext.enable_direct);
    }

    #[test]
    fn requires_complete_application_records() {
        let record = [0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02];
        assert!(is_complete_tls_application_data(&record));
        assert!(!is_complete_tls_application_data(&record[..6]));
    }
}
