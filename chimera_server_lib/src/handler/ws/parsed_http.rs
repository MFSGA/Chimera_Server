use std::collections::HashMap;

use tracing::debug;

use crate::{async_stream::AsyncStream, util::line_reader::LineReader};

pub struct ParsedHttpData {
    pub first_line: String,
    pub headers: HashMap<String, String>,
    pub line_reader: LineReader,
}

impl ParsedHttpData {
    pub async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut line_reader = LineReader::new();
        let mut first_line: Option<String> = None;
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = line_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "http request line is too long",
                ));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid http request line: {}", line),
                    ));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "http request is too long",
                ));
            }
        }

        let first_line = first_line
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            line_reader,
        })
    }
}
