use bytes::Bytes;
use http::{Response, StatusCode};
use std::io::Error;

pub(in super::super) fn xray_is_zero_modtime(
    modified: std::time::SystemTime,
) -> bool {
    modified == std::time::UNIX_EPOCH
}

pub(in super::super) fn xray_system_time_seconds(
    time: std::time::SystemTime,
) -> i128 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i128,
        Err(err) => {
            let duration = err.duration();
            let seconds = duration.as_secs() as i128;
            if duration.subsec_nanos() == 0 {
                -seconds
            } else {
                -seconds - 1
            }
        }
    }
}

pub(in super::super) fn xray_modified_not_after(
    modified: std::time::SystemTime,
    validator: std::time::SystemTime,
) -> bool {
    xray_system_time_seconds(modified) <= xray_system_time_seconds(validator)
}

pub(in super::super) fn xray_etag_list_has_wildcard(mut value: &[u8]) -> bool {
    loop {
        while value
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            value = &value[1..];
        }
        if value.is_empty() {
            return false;
        }
        if value[0] == b',' {
            value = &value[1..];
            continue;
        }
        if value[0] == b'*' {
            return true;
        }

        let quote = if value.starts_with(b"W/\"") {
            2
        } else if value.starts_with(b"\"") {
            0
        } else {
            return false;
        };
        let mut end = None;
        for (index, byte) in value.iter().copied().enumerate().skip(quote + 1) {
            match byte {
                b'!' | b'#'..=b'~' | 0x80..=0xff => {}
                b'"' => {
                    end = Some(index + 1);
                    break;
                }
                _ => return false,
            }
        }
        let Some(end) = end else {
            return false;
        };
        value = &value[end..];
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct XrayByteRange {
    pub(super) start: usize,
    pub(super) length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum XrayRangeError {
    Invalid,
    NoOverlap,
}

pub(in super::super) fn xray_if_range_matches(
    method: &http::Method,
    request_headers: &http::HeaderMap,
    modified: Option<std::time::SystemTime>,
) -> bool {
    if !matches!(*method, http::Method::GET | http::Method::HEAD) {
        return true;
    }
    let Some(value) = request_headers.get(http::header::IF_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    // Xray's FileServer does not set an ETag, so an entity-tag If-Range can
    // never match. A date validator must match Last-Modified to the second.
    if value.trim_start().starts_with('"') || value.trim_start().starts_with("W/\"")
    {
        return false;
    }
    let Some(if_range) = xray_parse_http_date(value) else {
        return false;
    };
    modified.is_some_and(|modified| {
        modified
            .duration_since(if_range)
            .is_ok_and(|delta| delta.as_secs() == 0)
    })
}

pub(in super::super) fn xray_parse_http_date(
    value: &str,
) -> Option<std::time::SystemTime> {
    // Go's time.RFC850 maps two-digit years 69..99 to 1969..1999 and 00..68
    // to 2000..2068. httpdate instead maps 69 to 2069, so handle RFC850
    // before its fast path.
    if let Some(parsed) = xray_parse_rfc850_http_date(value) {
        return Some(parsed);
    }
    if let Ok(parsed) = httpdate::parse_http_date(value) {
        return Some(parsed);
    }

    // httpdate rejects years before 1970 and validates weekday/date
    // consistency. Go's http.ParseTime accepts pre-epoch dates and treats the
    // weekday as syntax only, so use time's calendar-date parser as fallback.
    xray_parse_http_date_with_format(
        value,
        "[weekday repr:short], [day padding:zero] [month repr:short] [year repr:full] [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT",
    )
    .or_else(|| {
        xray_parse_http_date_with_format(
            value,
            "[weekday repr:short] [month repr:short] [day padding:space] [hour padding:zero]:[minute padding:zero]:[second padding:zero] [year repr:full]",
        )
    })
}

pub(in super::super) fn xray_parse_rfc850_http_date(
    value: &str,
) -> Option<std::time::SystemTime> {
    let (weekday, rest) = value.split_once(", ")?;
    if !matches!(
        weekday,
        "Monday"
            | "Tuesday"
            | "Wednesday"
            | "Thursday"
            | "Friday"
            | "Saturday"
            | "Sunday"
    ) || rest.len() != 22
        || rest.as_bytes().get(2) != Some(&b'-')
        || rest.as_bytes().get(6) != Some(&b'-')
        || rest.as_bytes().get(9) != Some(&b' ')
    {
        return None;
    }
    let year = rest.get(7..9)?.parse::<u16>().ok()?;
    let year = if year >= 69 { 1900 + year } else { 2000 + year };
    let expanded = format!("{weekday}, {}{year:04}{}", &rest[..7], &rest[9..]);
    xray_parse_http_date_with_format(
        &expanded,
        "[weekday repr:long], [day padding:zero]-[month repr:short]-[year repr:full] [hour padding:zero]:[minute padding:zero]:[second padding:zero] GMT",
    )
}

pub(in super::super) fn xray_parse_http_date_with_format(
    value: &str,
    format: &str,
) -> Option<std::time::SystemTime> {
    let format = time::format_description::parse(format).ok()?;
    let parsed = time::PrimitiveDateTime::parse(value, &format).ok()?;
    let seconds = parsed.assume_utc().unix_timestamp();
    if seconds >= 0 {
        std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(seconds as u64))
    } else {
        std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
    }
}

pub(in super::super) fn xray_format_http_date(
    value: std::time::SystemTime,
) -> String {
    if value.duration_since(std::time::UNIX_EPOCH).is_ok() {
        return httpdate::fmt_http_date(value);
    }

    let value = time::OffsetDateTime::from(value);
    let weekday = match value.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match value.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        value.day(),
        value.year(),
        value.hour(),
        value.minute(),
        value.second(),
    )
}

pub(in super::super) fn xray_parse_ranges(
    value: &[u8],
    size: usize,
) -> Result<Vec<XrayByteRange>, XrayRangeError> {
    let value = std::str::from_utf8(value).map_err(|_| XrayRangeError::Invalid)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let Some(value) = value.strip_prefix("bytes=") else {
        return Err(XrayRangeError::Invalid);
    };
    let size_i64 = i64::try_from(size).map_err(|_| XrayRangeError::Invalid)?;
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((start, end)) = raw.split_once('-') else {
            return Err(XrayRangeError::Invalid);
        };
        let start = start.trim();
        let end = end.trim();
        let range = if start.is_empty() {
            if end.starts_with('-') {
                return Err(XrayRangeError::Invalid);
            }
            let suffix = end.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
            if suffix < 0 {
                return Err(XrayRangeError::Invalid);
            }
            let length = suffix.min(size_i64);
            let start = size_i64 - length;
            XrayByteRange {
                start: usize::try_from(start)
                    .map_err(|_| XrayRangeError::Invalid)?,
                length: usize::try_from(length)
                    .map_err(|_| XrayRangeError::Invalid)?,
            }
        } else {
            let start = start.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
            if start < 0 {
                return Err(XrayRangeError::Invalid);
            }
            if start >= size_i64 {
                no_overlap = true;
                continue;
            }
            let end = if end.is_empty() {
                size_i64 - 1
            } else {
                let end = end.parse::<i64>().map_err(|_| XrayRangeError::Invalid)?;
                if start > end {
                    return Err(XrayRangeError::Invalid);
                }
                end.min(size_i64 - 1)
            };
            XrayByteRange {
                start: usize::try_from(start)
                    .map_err(|_| XrayRangeError::Invalid)?,
                length: usize::try_from(end - start + 1)
                    .map_err(|_| XrayRangeError::Invalid)?,
            }
        };
        ranges.push(range);
    }
    if no_overlap && ranges.is_empty() {
        Err(XrayRangeError::NoOverlap)
    } else {
        Ok(ranges)
    }
}

pub(in super::super) fn xray_range_error_response(
    error: XrayRangeError,
    size: usize,
) -> std::io::Result<(Response<()>, Option<Bytes>)> {
    let text = match error {
        XrayRangeError::Invalid => "invalid range\n",
        XrayRangeError::NoOverlap => "invalid range: failed to overlap\n",
    };
    let body = Bytes::from_static(text.as_bytes());
    let mut response = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    if matches!(error, XrayRangeError::NoOverlap) {
        response =
            response.header(http::header::CONTENT_RANGE, format!("bytes */{size}"));
    }
    Ok((response.body(()).map_err(Error::other)?, Some(body)))
}

pub(in super::super) fn xray_multipart_ranges(
    ranges: &[XrayByteRange],
    body: &[u8],
    content_type: &str,
) -> (Bytes, String) {
    let boundary = xray_multipart_boundary();
    let mut multipart = Vec::new();
    for range in ranges {
        let end = range.start + range.length;
        multipart.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        multipart.extend_from_slice(
            format!(
                "Content-Range: bytes {}-{}/{}\r\nContent-Type: {}\r\n\r\n",
                range.start,
                end.saturating_sub(1),
                body.len(),
                content_type
            )
            .as_bytes(),
        );
        multipart.extend_from_slice(&body[range.start..end]);
        multipart.extend_from_slice(b"\r\n");
    }
    multipart.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (
        Bytes::from(multipart),
        format!("multipart/byteranges; boundary={boundary}"),
    )
}

pub(in super::super) fn xray_multipart_boundary() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let random = rand::random::<[u8; 30]>();
    let mut boundary = String::with_capacity(60);
    for byte in random {
        boundary.push(HEX[(byte >> 4) as usize] as char);
        boundary.push(HEX[(byte & 0x0f) as usize] as char);
    }
    boundary
}
