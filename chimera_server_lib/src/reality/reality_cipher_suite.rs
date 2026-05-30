//! TLS 1.3 cipher suite definitions for REALITY.

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305},
    digest,
    hmac::{self, HMAC_SHA256, HMAC_SHA384},
};

/// Default TLS 1.3 cipher suites in preference order.
pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

/// TLS 1.3 cipher suite with its AEAD, digest, and HKDF algorithms.
#[derive(Clone, Copy)]
pub struct CipherSuite {
    id: u16,
    algorithm: &'static Algorithm,
    digest_algorithm: &'static digest::Algorithm,
    hmac_algorithm: hmac::Algorithm,
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for CipherSuite {}

impl CipherSuite {
    pub const AES_128_GCM_SHA256: Self = Self {
        id: 0x1301,
        algorithm: &AES_128_GCM,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    pub const AES_256_GCM_SHA384: Self = Self {
        id: 0x1302,
        algorithm: &AES_256_GCM,
        digest_algorithm: &digest::SHA384,
        hmac_algorithm: HMAC_SHA384,
    };

    pub const CHACHA20_POLY1305_SHA256: Self = Self {
        id: 0x1303,
        algorithm: &CHACHA20_POLY1305,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    /// Get a cipher suite from its wire-format ID.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::AES_128_GCM_SHA256),
            0x1302 => Some(Self::AES_256_GCM_SHA384),
            0x1303 => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Get a cipher suite from its standard TLS name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "TLS_AES_128_GCM_SHA256" => Some(Self::AES_128_GCM_SHA256),
            "TLS_AES_256_GCM_SHA384" => Some(Self::AES_256_GCM_SHA384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Standard TLS name for this cipher suite.
    pub fn name(&self) -> &'static str {
        match self.id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.id
    }

    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    #[inline]
    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    #[inline]
    pub fn nonce_len(&self) -> usize {
        self.algorithm.nonce_len()
    }

    #[inline]
    pub fn hash_len(&self) -> usize {
        self.digest_algorithm.output_len()
    }

    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_algorithm
    }

    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.hmac_algorithm
    }
}

impl std::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::LowerHex for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.id, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_metadata_matches_tls13_ids() {
        let suite = CipherSuite::from_id(0x1301).unwrap();
        assert_eq!(suite, CipherSuite::AES_128_GCM_SHA256);
        assert_eq!(suite.name(), "TLS_AES_128_GCM_SHA256");
        assert_eq!(suite.key_len(), 16);
        assert_eq!(suite.nonce_len(), 12);
        assert_eq!(suite.hash_len(), 32);

        let suite = CipherSuite::from_name("TLS_AES_256_GCM_SHA384").unwrap();
        assert_eq!(suite.id(), 0x1302);
        assert_eq!(suite.key_len(), 32);
        assert_eq!(suite.hash_len(), 48);
    }
}
