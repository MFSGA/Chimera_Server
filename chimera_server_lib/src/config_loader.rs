use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    Error,
    config::{def::LiteralConfig, parse_error},
};

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
    source == "stdin:"
        || source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("http+unix://")
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
        _ if source.starts_with("http://") || source.starts_with("https://") => {
            fetch_http_content(source)
        }
        _ => Err(Error::InvalidConfig(format!(
            "unsupported external config source: {}",
            safe_config_source_label(source)
        ))),
    }
}

fn safe_config_source_label(source: &str) -> String {
    if source == "stdin:" {
        return source.to_string();
    }
    if source.starts_with("http+unix://") {
        return "http+unix://<redacted>".to_string();
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        let scheme = if source.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        return reqwest::Url::parse(source)
            .ok()
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_else(|| format!("{scheme}://<redacted>"));
    }
    "<redacted config source>".to_string()
}

fn fetch_http_content(target: &str) -> Result<String, Error> {
    // Preserve the historical config-loader behavior when reqwest's gzip
    // support is enabled for Xray Hysteria reverse-proxy compatibility.
    let client = reqwest::blocking::Client::builder()
        .no_gzip()
        .http1_only()
        .build()
        .map_err(|err| {
            Error::InvalidConfig(format!(
                "could not build config source client: {err}"
            ))
        })?;
    let source = safe_config_source_label(target);
    let response = client.get(target).send().map_err(|err| {
        let category = if err.is_timeout() {
            "request timed out"
        } else if err.is_connect() {
            "connection failed"
        } else if err.is_builder() {
            "request could not be built"
        } else {
            "request failed"
        };
        Error::InvalidConfig(format!(
            "could not fetch config source {source}: {category}"
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::InvalidConfig(format!(
            "unexpected HTTP status code from config source {source}: {status}"
        )));
    }

    response.text().map_err(|_| {
        Error::InvalidConfig(format!(
            "config source {source} did not contain valid UTF-8 text"
        ))
    })
}

pub(crate) fn parse_config_content(
    content: &str,
    format: Option<ConfigFormat>,
) -> Result<LiteralConfig, Error> {
    match format {
        Some(ConfigFormat::Json) => serde_json::from_str(content).map_err(|err| {
            Error::InvalidConfig(format!(
                "could not parse JSON: {}",
                parse_error::json(
                    &err,
                    parse_error::json_field_path::<LiteralConfig>(content),
                )
            ))
        }),
        Some(ConfigFormat::Json5) => json5::from_str(content).map_err(|err| {
            Error::InvalidConfig(format!(
                "could not parse JSON5: {}",
                parse_error::json5(
                    &err,
                    parse_error::json5_field_path::<LiteralConfig>(content),
                )
            ))
        }),
        None => serde_json::from_str(content).or_else(|json_err| {
            json5::from_str(content).map_err(|json5_err| {
                Error::InvalidConfig(format!(
                    "could not parse config as JSON ({}) or JSON5 ({})",
                    parse_error::json(
                        &json_err,
                        parse_error::json_field_path::<LiteralConfig>(content),
                    ),
                    parse_error::json5(
                        &json5_err,
                        parse_error::json5_field_path::<LiteralConfig>(content),
                    )
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
        ConfigFormat, decode_chunked_body, expand_env_placeholders,
        is_external_config_source, parse_config_content, parse_unix_socket_target,
        safe_config_source_label,
    };

    #[test]
    fn config_parse_errors_redact_input_and_keep_format_location() {
        let secret = "config-password-sentinel";
        let content = format!("\"{secret}\"");

        for (format, expected_format) in [
            (Some(ConfigFormat::Json), "JSON"),
            (Some(ConfigFormat::Json5), "JSON5"),
            (None, "JSON"),
        ] {
            let error = parse_config_content(&content, format)
                .expect_err("a scalar cannot be used as the full server config")
                .to_string();

            assert!(error.contains(expected_format), "{error}");
            assert!(error.contains("line 1"), "{error}");
            assert!(!error.contains(secret), "{error}");
        }
    }

    #[test]
    fn config_parse_errors_report_safe_paths_without_values_or_dynamic_keys() {
        let secret_value = "config-field-secret-sentinel";
        let json = format!(
            r#"{{"inbounds":[{{"tag":"{secret_value}","protocol":7}}],"outbounds":[]}}"#
        );
        let json_error = parse_config_content(&json, Some(ConfigFormat::Json))
            .expect_err("invalid protocol type should fail")
            .to_string();
        assert!(
            json_error.contains("field path `inbounds[0].protocol`"),
            "{json_error}"
        );
        assert!(!json_error.contains(secret_value), "{json_error}");

        let json5 = format!(
            "{{inbounds: [{{tag: '{secret_value}', protocol: 7}}], outbounds: []}}"
        );
        let json5_error = parse_config_content(&json5, Some(ConfigFormat::Json5))
            .expect_err("invalid protocol type should fail")
            .to_string();
        assert!(
            json5_error.contains("field path `inbounds[0].protocol`"),
            "{json5_error}"
        );
        assert!(!json5_error.contains(secret_value), "{json5_error}");

        let secret_key = "dynamic-secret-key-sentinel";
        let json5_dynamic_key = format!(
            "{{inbounds: [], outbounds: [], dns: {{hosts: {{'{secret_key}': 7}}}}}}"
        );
        let dynamic_key_error =
            parse_config_content(&json5_dynamic_key, Some(ConfigFormat::Json5))
                .expect_err("invalid DNS host value should fail")
                .to_string();
        assert!(
            dynamic_key_error.contains("field path `dns.hosts.<key>`"),
            "{dynamic_key_error}"
        );
        assert!(
            !dynamic_key_error.contains(secret_key),
            "{dynamic_key_error}"
        );

        let invalid_dns_field =
            r#"{"inbounds":[],"outbounds":[],"dns":{"serveExpiredTtl":"bad"}}"#;
        let dns_field_error =
            parse_config_content(invalid_dns_field, Some(ConfigFormat::Json))
                .expect_err("invalid DNS TTL type should fail")
                .to_string();
        assert!(
            dns_field_error.contains("field path `dns.serveExpiredTtl`"),
            "{dns_field_error}"
        );
        assert!(!dns_field_error.contains("bad"), "{dns_field_error}");

        let invalid_log_field =
            r#"{"inbounds":[],"outbounds":[],"log":{"dnsLog":"bad"}}"#;
        let log_field_error =
            parse_config_content(invalid_log_field, Some(ConfigFormat::Json))
                .expect_err("invalid log option type should fail")
                .to_string();
        assert!(
            log_field_error.contains("field path `log.dnsLog`"),
            "{log_field_error}"
        );
        assert!(!log_field_error.contains("bad"), "{log_field_error}");

        let invalid_acronym_field = r#"{"inbounds":[{"tag":"in","protocol":"vless","settings":{},"streamSettings":{"network":"xhttp","xhttpSettings":{"noGRPCHeader":"bad"}}}],"outbounds":[]}"#;
        let acronym_field_error =
            parse_config_content(invalid_acronym_field, Some(ConfigFormat::Json))
                .expect_err("invalid XHTTP option type should fail")
                .to_string();
        assert!(
            acronym_field_error.contains(
                "field path `inbounds[0].streamSettings.xhttpSettings.noGRPCHeader`"
            ),
            "{acronym_field_error}"
        );
        assert!(
            !acronym_field_error.contains("bad"),
            "{acronym_field_error}"
        );

        // A malformed raw settings value can fail while the parser is inside
        // its arbitrary object. Even keys matching known config fields stay
        // redacted once parsing has entered a Value subtree.
        let malformed_settings = r#"{"inbounds":[{"protocol":"vless","settings":{"password": }}],"outbounds":[]}"#;
        let settings_error =
            parse_config_content(malformed_settings, Some(ConfigFormat::Json))
                .expect_err("malformed settings JSON should fail")
                .to_string();
        assert!(
            settings_error.contains("field path `inbounds[0].settings.<key>`"),
            "{settings_error}"
        );
        assert!(!settings_error.contains("password"), "{settings_error}");

        let malformed_outbound_stream = r#"{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"out","streamSettings":{"password": }}]}"#;
        let outbound_stream_error = parse_config_content(
            malformed_outbound_stream,
            Some(ConfigFormat::Json),
        )
        .expect_err("malformed outbound stream settings should fail")
        .to_string();
        assert!(
            outbound_stream_error
                .contains("field path `outbounds[0].streamSettings.<key>`"),
            "{outbound_stream_error}"
        );
        assert!(
            !outbound_stream_error.contains("password"),
            "{outbound_stream_error}"
        );

        let invalid_selector_alias = r#"{"inbounds":[],"outbounds":[],"routing":{"balancers":[{"tag":"balance","selector":["selector-secret-sentinel",7]}]}}"#;
        let selector_alias_error =
            parse_config_content(invalid_selector_alias, Some(ConfigFormat::Json))
                .expect_err("invalid balancer selector type should fail")
                .to_string();
        assert!(
            selector_alias_error
                .contains("field path `routing.balancers[0].selector`"),
            "{selector_alias_error}"
        );
        assert!(
            !selector_alias_error.contains("selector-secret-sentinel"),
            "{selector_alias_error}"
        );

        let malformed_unknown_object =
            r#"{"inbounds":[],"outbounds":[],"futureField":{"password": }}"#;
        let unknown_object_error =
            parse_config_content(malformed_unknown_object, Some(ConfigFormat::Json))
                .expect_err("malformed unknown config object should fail")
                .to_string();
        assert!(
            !unknown_object_error.contains("password"),
            "{unknown_object_error}"
        );
    }

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

    #[test]
    fn treats_http_urls_as_external_sources() {
        assert!(is_external_config_source(
            "https://example.com/chimera/config.json5"
        ));
        assert!(is_external_config_source(
            "http://127.0.0.1:8080/config.json"
        ));
    }

    #[test]
    fn safe_config_source_label_redacts_credentials_and_paths() {
        assert_eq!(
            safe_config_source_label(
                "https://user:secret@example.com/private/config.json?token=abc#fragment"
            ),
            "https://example.com"
        );
        assert_eq!(
            safe_config_source_label(
                "http://127.0.0.1:8080/config.json?signature=secret"
            ),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            safe_config_source_label(
                "http+unix:///tmp/chimera.sock/internal/get-config?token=abc"
            ),
            "http+unix://<redacted>"
        );
    }

    use std::path::PathBuf;
}
