use anyhow::{Context, Result, bail};

pub const REQUEST_LEN: usize = 40;
pub const ACK_LEN: usize = 16;
pub const READY_LEN: usize = 8;

const REQUEST_MAGIC: [u8; 8] = *b"CHMPRF01";
const ACK_MAGIC: [u8; 8] = *b"CHMACK01";
pub const DOWNLOAD_READY: [u8; READY_LEN] = *b"CHMRDY01";
const VERSION: u16 = 1;

pub const FLAG_FULL_VERIFY: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub flags: u8,
    pub upload_len: u64,
    pub download_len: u64,
    pub seed: u64,
}

impl Request {
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut out = [0_u8; REQUEST_LEN];
        out[..8].copy_from_slice(&REQUEST_MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10] = 1;
        out[11] = self.flags;
        out[12..20].copy_from_slice(&self.upload_len.to_be_bytes());
        out[20..28].copy_from_slice(&self.download_len.to_be_bytes());
        out[28..36].copy_from_slice(&self.seed.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != REQUEST_LEN {
            bail!("request must be {REQUEST_LEN} bytes, got {}", input.len());
        }
        if input[..8] != REQUEST_MAGIC {
            bail!("invalid request magic");
        }
        let version = u16::from_be_bytes(
            input[8..10]
                .try_into()
                .context("invalid request version field")?,
        );
        if version != VERSION {
            bail!("unsupported protocol version {version}");
        }
        if input[10] != 1 {
            bail!("unsupported benchmark mode {}", input[10]);
        }
        Ok(Self {
            flags: input[11],
            upload_len: u64::from_be_bytes(input[12..20].try_into()?),
            download_len: u64::from_be_bytes(input[20..28].try_into()?),
            seed: u64::from_be_bytes(input[28..36].try_into()?),
        })
    }

    pub fn full_verify(self) -> bool {
        self.flags & FLAG_FULL_VERIFY != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub status: u16,
}

impl Ack {
    pub const OK: Self = Self { status: 0 };

    pub fn encode(self) -> [u8; ACK_LEN] {
        let mut out = [0_u8; ACK_LEN];
        out[..8].copy_from_slice(&ACK_MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10..12].copy_from_slice(&self.status.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != ACK_LEN {
            bail!("ack must be {ACK_LEN} bytes, got {}", input.len());
        }
        if input[..8] != ACK_MAGIC {
            bail!("invalid ack magic");
        }
        let version = u16::from_be_bytes(input[8..10].try_into()?);
        if version != VERSION {
            bail!("unsupported ack version {version}");
        }
        Ok(Self {
            status: u16::from_be_bytes(input[10..12].try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let request = Request {
            flags: FLAG_FULL_VERIFY,
            upload_len: 65_536,
            download_len: 1_048_576,
            seed: 0x1234_5678_90ab_cdef,
        };
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
        assert!(request.full_verify());
    }

    #[test]
    fn request_rejects_bad_magic() {
        let mut encoded = Request {
            flags: 0,
            upload_len: 1,
            download_len: 2,
            seed: 3,
        }
        .encode();
        encoded[0] ^= 0xff;
        assert!(Request::decode(&encoded).is_err());
    }

    #[test]
    fn ack_round_trip() {
        assert_eq!(Ack::decode(&Ack::OK.encode()).unwrap(), Ack::OK);
    }
}
