use serde::Deserialize;

const BYTE: u64 = 1;
const KILOBYTE: u64 = BYTE * 1_000;
const MEGABYTE: u64 = KILOBYTE * 1_000;
const GIGABYTE: u64 = MEGABYTE * 1_000;
const TERABYTE: u64 = GIGABYTE * 1_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BandwidthValue {
    Number(u64),
    String(String),
}

pub fn parse_bandwidth(value: BandwidthValue) -> Result<u64, String> {
    match value {
        BandwidthValue::Number(number) => Ok(number),
        BandwidthValue::String(value) => parse_bandwidth_string(&value),
    }
}

fn parse_bandwidth_string(input: &str) -> Result<u64, String> {
    let value = input.trim().to_ascii_lowercase();
    let split = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    if split == 0 {
        return Err("invalid bandwidth format".to_string());
    }

    let (number, unit) = value.split_at(split);
    let number = number
        .parse::<u64>()
        .map_err(|_| "invalid bandwidth value".to_string())?;
    let unit = unit.trim();

    match unit {
        "b" | "bps" => Ok(number / 8),
        "k" | "kb" | "kbps" => scale_bandwidth(number, KILOBYTE),
        "m" | "mb" | "mbps" => scale_bandwidth(number, MEGABYTE),
        "g" | "gb" | "gbps" => scale_bandwidth(number, GIGABYTE),
        "t" | "tb" | "tbps" => scale_bandwidth(number, TERABYTE),
        _ => Err("unsupported bandwidth unit".to_string()),
    }
}

fn scale_bandwidth(value: u64, unit: u64) -> Result<u64, String> {
    value
        .checked_mul(unit)
        .ok_or_else(|| "bandwidth value too large".to_string())
        .map(|value| value / 8)
}
