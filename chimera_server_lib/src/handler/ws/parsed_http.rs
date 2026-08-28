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
    pub first_line_raw: Vec<u8>,
    pub headers: HashMap<String, Vec<String>>,
    pub line_reader: LineReader,
}

impl ParsedHttpData {
    pub async fn parse(
        stream: &mut Box<dyn AsyncStream>,
    ) -> Result<Self, ParsedHttpError> {
        let mut line_reader = LineReader::new();
        let mut first_line: Option<String> = None;
        let mut first_line_raw: Option<Vec<u8>> = None;
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        let mut last_header: Option<(String, usize)> = None;
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
                // Go's net/http keeps the request line as a byte string and can
                // therefore route request-targets containing non-UTF-8 bytes.
                // Chimera's downstream parser is string-based, so preserve the
                // parse flow with lossy decoding instead of rejecting the whole
                // handshake before Xray's path-mismatch handling can run.
                first_line = Some(String::from_utf8_lossy(line).into_owned());
                first_line_raw = Some(line.to_vec());
            } else {
                if matches!(line.first(), Some(b' ' | b'\t')) {
                    let Some((header_key, value_index)) = last_header.as_ref()
                    else {
                        return Err(ParsedHttpError::InvalidHeaderValue);
                    };
                    if !line
                        .iter()
                        .copied()
                        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
                    {
                        return Err(ParsedHttpError::InvalidHeaderValue);
                    }
                    let start = line
                        .iter()
                        .position(|byte| !matches!(*byte, b' ' | b'\t'))
                        .unwrap_or(line.len());
                    let end = line
                        .iter()
                        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
                        .map_or(start, |position| position + 1);
                    let continuation = String::from_utf8_lossy(&line[start..end]);
                    let value = headers
                        .get_mut(header_key)
                        .and_then(|values| values.get_mut(*value_index))
                        .expect("last parsed HTTP header must still exist");
                    if !value.is_empty() && !continuation.is_empty() {
                        value.push(' ');
                    }
                    value.push_str(&continuation);
                    continue;
                }

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
                let values = headers.entry(header_key.clone()).or_default();
                values.push(header_value);
                last_header = Some((header_key, values.len() - 1));
            }
        }

        let first_line =
            first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;
        let first_line_raw = first_line_raw
            .expect("raw HTTP request line is captured together with decoded text");

        Ok(Self {
            first_line,
            first_line_raw,
            headers,
            line_reader,
        })
    }
}
