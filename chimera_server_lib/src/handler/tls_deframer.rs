#![allow(dead_code)]

use std::io;

use bytes::{Bytes, BytesMut};

const TLS_RECORD_HEADER_SIZE: usize = 5;
const MAX_TLS_CIPHERTEXT_LEN: usize = 16_384 + 2_048;
const TLS_PROTOCOL_VERSION_MAJOR: u8 = 0x03;
const TLS_PROTOCOL_VERSION_MINOR_MIN: u8 = 0x01;
const TLS_PROTOCOL_VERSION_MINOR_MAX: u8 = 0x03;

pub const TLS_MAX_RECORD_SIZE: usize =
    MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

#[derive(Debug, PartialEq)]
pub struct TlsDeframer {
    buffer: BytesMut,
    state: DeframerState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DeframerState {
    ReadingHeader,
    ReadingPayload { payload_len: usize },
}

impl TlsDeframer {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(TLS_MAX_RECORD_SIZE),
            state: DeframerState::ReadingHeader,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn next_record(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.state {
                DeframerState::ReadingHeader => {
                    if self.buffer.len() < TLS_RECORD_HEADER_SIZE {
                        return Ok(None);
                    }

                    let content_type = self.buffer[0];
                    let version_major = self.buffer[1];
                    let version_minor = self.buffer[2];
                    let payload_len =
                        u16::from_be_bytes([self.buffer[3], self.buffer[4]])
                            as usize;

                    if version_major != TLS_PROTOCOL_VERSION_MAJOR
                        || !(TLS_PROTOCOL_VERSION_MINOR_MIN
                            ..=TLS_PROTOCOL_VERSION_MINOR_MAX)
                            .contains(&version_minor)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid TLS protocol version: 0x{version_major:02x}{version_minor:02x} (expected 0x0301 to 0x0303)"
                            ),
                        ));
                    }

                    if payload_len > MAX_TLS_CIPHERTEXT_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "TLS record ciphertext length {payload_len} exceeds maximum {MAX_TLS_CIPHERTEXT_LEN} (TLS 1.2 limit)"
                            ),
                        ));
                    }

                    if !(0x14..=0x18).contains(&content_type) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid TLS content type: 0x{content_type:02x}"
                            ),
                        ));
                    }

                    self.state = DeframerState::ReadingPayload { payload_len };
                }
                DeframerState::ReadingPayload { payload_len } => {
                    let total_len = TLS_RECORD_HEADER_SIZE + payload_len;
                    if self.buffer.len() < total_len {
                        return Ok(None);
                    }

                    let record = self.buffer.split_to(total_len).freeze();
                    self.state = DeframerState::ReadingHeader;
                    return Ok(Some(record));
                }
            }
        }
    }

    pub fn next_records(&mut self) -> io::Result<Vec<Bytes>> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }

    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn into_remaining_data(self) -> Bytes {
        self.buffer.freeze()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.state = DeframerState::ReadingHeader;
    }
}

impl Default for TlsDeframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn deframes_complete_record() {
        let mut deframer = TlsDeframer::new();
        let record = make_tls_record(0x17, b"hello");

        deframer.feed(&record);

        assert_eq!(deframer.next_record().unwrap().unwrap(), record);
        assert!(deframer.next_record().unwrap().is_none());
    }

    #[test]
    fn preserves_partial_record_boundary() {
        let mut deframer = TlsDeframer::new();
        let record = make_tls_record(0x16, b"partial");

        deframer.feed(&record[..3]);
        assert!(deframer.next_record().unwrap().is_none());
        assert_eq!(deframer.pending_bytes(), 3);

        deframer.feed(&record[3..]);
        assert_eq!(deframer.next_record().unwrap().unwrap(), record);
        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn extracts_all_complete_records_and_leaves_partial() {
        let mut deframer = TlsDeframer::new();
        let record1 = make_tls_record(0x16, b"one");
        let record2 = make_tls_record(0x17, b"two");
        let record3 = make_tls_record(0x17, b"partial");

        let mut combined = Vec::new();
        combined.extend_from_slice(&record1);
        combined.extend_from_slice(&record2);
        combined.extend_from_slice(&record3[..7]);
        deframer.feed(&combined);

        let records = deframer.next_records().unwrap();

        assert_eq!(records, vec![Bytes::from(record1), Bytes::from(record2)]);
        assert_eq!(deframer.pending_bytes(), 7);
    }

    #[test]
    fn rejects_invalid_header() {
        let mut deframer = TlsDeframer::new();
        deframer.feed(&[0xff, 0x03, 0x03, 0x00, 0x00]);

        let err = deframer.next_record().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Invalid TLS content type"));
    }

    #[test]
    fn returns_remaining_data() {
        let mut deframer = TlsDeframer::new();
        let partial = [0x16, 0x03, 0x03];
        deframer.feed(&partial);

        assert_eq!(
            deframer.into_remaining_data(),
            Bytes::copy_from_slice(&partial)
        );
    }

    #[test]
    fn clear_discards_pending_data() {
        let mut deframer = TlsDeframer::new();
        deframer.feed(&[0x16, 0x03, 0x03]);

        deframer.clear();

        assert_eq!(deframer.pending_bytes(), 0);
        assert!(deframer.next_record().unwrap().is_none());
    }
}
