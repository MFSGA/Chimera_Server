use std::{collections::HashMap, io};

use crate::{async_stream::AsyncStream, util::line_reader::LineReader};

const XRAY_WEBSOCKET_MAX_HEADER_BYTES: usize = 8192 + 4096;

#[derive(Debug)]
pub enum ParsedHttpError {
    Io(io::Error),
    HeaderTooLarge,
    InvalidHeaderName { trailing_space: bool },
    InvalidHeaderValue,
}

impl From<io::Error> for ParsedHttpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub struct ParsedHttpData {
    pub first_line: String,
    pub headers: HashMap<String, Vec<String>>,
    pub line_reader: LineReader,
}

impl ParsedHttpData {
    pub async fn parse(
        stream: &mut Box<dyn AsyncStream>,
    ) -> Result<Self, ParsedHttpError> {
        let mut line_reader = LineReader::new();
        let mut first_line: Option<String> = None;
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        let mut header_bytes = 0usize;

        loop {
            let line = line_reader.read_line_bytes(stream).await?;
            // Xray v26.2.6 configures net/http MaxHeaderBytes=8192. Go's
            // HTTP/1 server adds 4096 bytes of read slop, and that budget
            // includes the request line and terminating CRLF. Do not impose
            // the old per-line 4096-byte / 40-line limits on top of it.
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > XRAY_WEBSOCKET_MAX_HEADER_BYTES {
                return Err(ParsedHttpError::HeaderTooLarge);
            }
            if line.is_empty() {
                break;
            }

            if first_line.is_none() {
                first_line = Some(
                    std::str::from_utf8(line)
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Failed to decode utf8: {error}"),
                            )
                        })?
                        .to_string(),
                );
            } else {
                let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                    return Err(io::Error::other("invalid http header line").into());
                };
                let raw_header_key = &line[..colon];
                if !raw_header_key.iter().copied().all(is_http_token_byte) {
                    return Err(ParsedHttpError::InvalidHeaderName {
                        trailing_space: raw_header_key.ends_with(b" "),
                    });
                }
                let header_key = std::str::from_utf8(raw_header_key)
                    .expect("validated HTTP token is ASCII")
                    .to_ascii_lowercase();
                let raw_header_value = &line[colon + 1..];
                if !raw_header_value
                    .iter()
                    .copied()
                    .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
                {
                    return Err(ParsedHttpError::InvalidHeaderValue);
                }
                let start = raw_header_value
                    .iter()
                    .position(|byte| !matches!(*byte, b' ' | b'\t'))
                    .unwrap_or(raw_header_value.len());
                let end = raw_header_value
                    .iter()
                    .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
                    .map_or(start, |position| position + 1);
                // Go header values are byte strings and permit obs-text. Rust's
                // String cannot preserve arbitrary invalid UTF-8, but lossy
                // decoding keeps ASCII protocol tokens exact while accepting
                // the same wire bytes instead of rejecting the request early.
                let header_value =
                    String::from_utf8_lossy(&raw_header_value[start..end])
                        .into_owned();
                headers.entry(header_key).or_default().push(header_value);
            }
        }

        let first_line =
            first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            line_reader,
        })
    }
}
