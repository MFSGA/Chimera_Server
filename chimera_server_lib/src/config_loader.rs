use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{Error, config::def::LiteralConfig};

#[derive(Debug, Clone, Copy)]
pub enum ConfigFormat {
    Json,
    Json5,
}

pub fn resolve_config_source(
    raw: &str,
    cwd: Option<&Path>,
) -> Result<String, Error> {
    let expanded = expand_env_placeholders(raw)?;
    if is_external_config_source(&expanded) || Path::new(&expanded).is_absolute() {
        return Ok(expanded);
    }

    let base = match cwd {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()?,
    };
    Ok(base.join(expanded).to_string_lossy().to_string())
}

pub fn parse_config_source(
    source: &str,
    format: Option<ConfigFormat>,
) -> Result<LiteralConfig, Error> {
    let source = expand_env_placeholders(source)?;

    if is_external_config_source(&source) {
        let content = load_external_config_source(&source)?;
        return parse_config_content(&content, format);
    }

    let path = PathBuf::from(&source);
    if format.is_some() {
        let content = std::fs::read_to_string(&path)?;
        return parse_config_content(&content, format);
    }

    LiteralConfig::try_from(path)
}

fn is_external_config_source(source: &str) -> bool {
    source == "stdin:" || source.starts_with("http+unix://")
}

fn load_external_config_source(source: &str) -> Result<String, Error> {
    match source {
        "stdin:" => {
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            Ok(content)
        }
        _ if source.starts_with("http+unix://") => {
            fetch_unix_socket_http_content(source)
        }
        _ => Err(Error::InvalidConfig(format!(
            "unsupported external config source: {source}"
        ))),
    }
}

fn parse_config_content(
    content: &str,
    format: Option<ConfigFormat>,
) -> Result<LiteralConfig, Error> {
    match format {
        Some(ConfigFormat::Json) => serde_json::from_str(content).map_err(|err| {
            Error::InvalidConfig(format!("could not parse JSON: {err}"))
        }),
        Some(ConfigFormat::Json5) => json5::from_str(content).map_err(|err| {
            Error::InvalidConfig(format!("could not parse JSON5: {err}"))
        }),
        None => serde_json::from_str(content).or_else(|json_err| {
            json5::from_str(content).map_err(|json5_err| {
                Error::InvalidConfig(format!(
                    "could not parse config as JSON ({json_err}) or JSON5 ({json5_err})"
                ))
            })
        }),
    }
}

#[cfg(unix)]
fn fetch_unix_socket_http_content(target: &str) -> Result<String, Error> {
    use std::os::unix::net::UnixStream;

    let (socket_path, http_path) = parse_unix_socket_target(target)?;
    let mut stream = UnixStream::connect(&socket_path)?;
    let request = format!(
        "GET {http_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let (headers, body) = split_http_response(&response)?;
    let status = parse_http_status(headers)?;
    if status != 200 {
        return Err(Error::InvalidConfig(format!(
            "unexpected HTTP status code: {status}"
        )));
    }

    let body = if is_chunked_response(headers) {
        decode_chunked_body(body)?
    } else {
        body.to_vec()
    };

    String::from_utf8(body).map_err(|err| {
        Error::InvalidConfig(format!(
            "http+unix response was not valid UTF-8: {err}"
        ))
    })
}

#[cfg(not(unix))]
fn fetch_unix_socket_http_content(target: &str) -> Result<String, Error> {
    Err(Error::InvalidConfig(format!(
        "http+unix config source is not supported on this platform: {target}"
    )))
}

fn parse_unix_socket_target(target: &str) -> Result<(PathBuf, String), Error> {
    let path = target.strip_prefix("http+unix://").ok_or_else(|| {
        Error::InvalidConfig(format!("invalid config source: {target}"))
    })?;

    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(
            "unix socket path must be absolute".to_string(),
        ));
    }

    let socket_end = path.find(".sock").map(|idx| idx + 5).ok_or_else(|| {
        Error::InvalidConfig(
            "cannot determine socket path; expected a .sock suffix".to_string(),
        )
    })?;

    let socket_path = PathBuf::from(&path[..socket_end]);
    let http_path = match &path[socket_end..] {
        "" => "/".to_string(),
        suffix if suffix.starts_with('/') => suffix.to_string(),
        suffix => format!("/{suffix}"),
    };

    Ok((socket_path, http_path))
}

fn split_http_response(response: &[u8]) -> Result<(&str, &[u8]), Error> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            Error::InvalidConfig(
                "invalid http+unix response: missing header/body separator"
                    .to_string(),
            )
        })?;

    let headers = std::str::from_utf8(&response[..header_end]).map_err(|err| {
        Error::InvalidConfig(format!("invalid http+unix response headers: {err}"))
    })?;

    Ok((headers, &response[header_end + 4..]))
}

fn parse_http_status(headers: &str) -> Result<u16, Error> {
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| {
            Error::InvalidConfig(
                "invalid http+unix response: missing status line".to_string(),
            )
        })?;

    status.parse::<u16>().map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid http+unix response status code {status}: {err}"
        ))
    })
}

fn is_chunked_response(headers: &str) -> bool {
    headers.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    })
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();

    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "invalid chunked http+unix response".to_string(),
                )
            })?;

        let line = std::str::from_utf8(&body[..line_end]).map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid chunked http+unix response: {err}"
            ))
        })?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|err| {
            Error::InvalidConfig(format!("invalid chunk size {size_hex}: {err}"))
        })?;

        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }

        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(Error::InvalidConfig(
                "invalid chunk framing in http+unix response".to_string(),
            ));
        }

        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }

    Ok(decoded)
}

fn expand_env_placeholders(input: &str) -> Result<String, Error> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("%(") {
        output.push_str(&rest[..start]);
        let placeholder = &rest[start + 2..];

        let Some(end) = placeholder.find(")s") else {
            output.push_str(&rest[start..]);
            return Ok(output);
        };

        let key = &placeholder[..end];
        let value = std::env::var(key).map_err(|err| {
            Error::InvalidConfig(format!(
                "missing environment variable {key}: {err}"
            ))
        })?;
        output.push_str(&value);
        rest = &placeholder[end + 2..];
    }

    output.push_str(rest);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_chunked_body, expand_env_placeholders, parse_unix_socket_target,
    };

    #[test]
    fn expands_env_placeholders() {
        // SAFETY: tests run in-process and use a unique variable name.
        unsafe {
            std::env::set_var("ENV_CHIMERA_CONFIG_TEST", "/tmp/chimera.sock");
        }

        let expanded = expand_env_placeholders(
            "http+unix://%(ENV_CHIMERA_CONFIG_TEST)s/internal/get-config",
        )
        .expect("placeholder expansion should succeed");

        assert_eq!(
            expanded,
            "http+unix:///tmp/chimera.sock/internal/get-config"
        );
    }

    #[test]
    fn parses_unix_socket_target() {
        let (socket, path) = parse_unix_socket_target(
            "http+unix:///tmp/chimera.sock/internal/get-config?token=abc",
        )
        .expect("target parsing should succeed");

        assert_eq!(socket, PathBuf::from("/tmp/chimera.sock"));
        assert_eq!(path, "/internal/get-config?token=abc");
    }

    #[test]
    fn decodes_chunked_response_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let decoded =
            decode_chunked_body(body).expect("chunk decoding should succeed");

        assert_eq!(decoded, b"hello world");
    }

    use std::path::PathBuf;
}
