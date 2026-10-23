#[cfg(feature = "ws")]
pub mod line_reader;

pub mod option;

pub mod rustls_util;

pub mod socket;

pub mod bandwidth;

pub mod prefixed_stream;

#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}
