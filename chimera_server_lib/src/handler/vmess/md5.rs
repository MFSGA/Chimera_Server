use md5::{Digest, Md5};

#[inline]
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    context.update(data);
    context.finalize().into()
}

#[inline]
pub fn create_chacha_key(data: &[u8]) -> [u8; 32] {
    let mut ret = [0u8; 32];
    let mut context = Md5::new();
    context.update(data);
    let first_half: [u8; 16] = context.finalize_reset().into();
    ret[0..16].copy_from_slice(&first_half);
    context.update(&first_half);
    let second_half: [u8; 16] = context.finalize().into();
    ret[16..].copy_from_slice(&second_half);
    ret
}
