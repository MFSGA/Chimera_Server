use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_PADDING_SIZE: usize = 8171;

pub fn pad_with_uuid_and_command(
    data: &[u8],
    uuid: &[u8; 16],
    command: u8,
    is_tls: bool,
) -> io::Result<Bytes> {
    let mut output = BytesMut::new();
    append_with_uuid_and_command(&mut output, data, uuid, command, is_tls)?;
    Ok(output.freeze())
}

pub fn pad_with_command(
    data: &[u8],
    command: u8,
    is_tls: bool,
) -> io::Result<Bytes> {
    let mut output = BytesMut::new();
    append_with_command(&mut output, data, command, is_tls)?;
    Ok(output.freeze())
}

pub fn append_with_uuid_and_command(
    output: &mut BytesMut,
    data: &[u8],
    uuid: &[u8; 16],
    command: u8,
    is_tls: bool,
) -> io::Result<()> {
    append(output, data, Some(uuid), command, is_tls)
}

pub fn append_with_command(
    output: &mut BytesMut,
    data: &[u8],
    command: u8,
    is_tls: bool,
) -> io::Result<()> {
    append(output, data, None, command, is_tls)
}

fn append(
    output: &mut BytesMut,
    data: &[u8],
    uuid: Option<&[u8; 16]>,
    command: u8,
    is_tls: bool,
) -> io::Result<()> {
    let content_len = u16::try_from(data.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Vision frame content exceeds {} bytes: {}",
                u16::MAX,
                data.len(),
            ),
        )
    })?;
    let padding_len = calculate_padding_length(data.len(), is_tls);
    let padding_len_u16 = u16::try_from(padding_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Vision frame padding exceeds {} bytes", u16::MAX),
        )
    })?;

    let uuid_len = usize::from(uuid.is_some()) * 16;
    let total_size = uuid_len + 1 + 2 + 2 + data.len() + padding_len;
    output.reserve(total_size);

    if let Some(uuid) = uuid {
        output.put_slice(uuid);
    }
    output.put_u8(command);
    output.put_u16(content_len);
    output.put_u16(padding_len_u16);
    output.put_slice(data);

    if padding_len > 0 {
        let padding_start = output.len();
        output.resize(padding_start + padding_len, 0);
        rand::rng().fill(&mut output[padding_start..]);
    }
    Ok(())
}

fn calculate_padding_length(content_len: usize, is_tls: bool) -> usize {
    let mut rng = rand::rng();
    let max_allowable = MAX_PADDING_SIZE.saturating_sub(content_len);

    if is_tls && content_len < LONG_PADDING_MIN {
        let random_part = rng.random_range(0..LONG_PADDING_RANDOM_MAX);
        let padding = LONG_PADDING_MIN
            .saturating_sub(content_len)
            .saturating_add(random_part);
        std::cmp::min(padding, max_allowable)
    } else {
        let padding = rng.random_range(0..SHORT_PADDING_RANDOM_MAX);
        std::cmp::min(padding, max_allowable)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Buf;

    use super::*;

    #[test]
    fn append_preserves_existing_prefix() {
        let mut output = BytesMut::from(&b"prefix"[..]);
        append_with_command(&mut output, b"payload", 0, false).unwrap();
        assert_eq!(&output[..6], b"prefix");
    }

    #[test]
    fn accepts_maximum_u16_content_length() {
        let payload = vec![0_u8; u16::MAX as usize];
        let encoded = pad_with_command(&payload, 0, false).unwrap();
        let mut header = &encoded[..5];
        assert_eq!(header.get_u8(), 0);
        assert_eq!(header.get_u16(), u16::MAX);
    }

    #[test]
    fn rejects_content_larger_than_u16() {
        let payload = vec![0_u8; u16::MAX as usize + 1];
        let error = pad_with_command(&payload, 0, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
