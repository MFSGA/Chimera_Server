use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use prost::Message;

pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/xray.common.geodata.rs"));
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GeodataStore {
    geo_ips: HashMap<String, proto::GeoIp>,
    geo_sites: HashMap<String, proto::GeoSite>,
}

impl GeodataStore {
    pub(crate) fn load_geoip_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        let list = proto::GeoIpList::decode(bytes)
            .map_err(|error| format!("failed to decode xray geoip data: {error}"))?;
        let mut entries = HashMap::new();
        for entry in list.entry {
            validate_geoip(&entry)?;
            insert_unique(&mut entries, entry.code.clone(), entry, "geoip")?;
        }
        self.geo_ips = entries;
        Ok(())
    }

    pub(crate) fn load_geosite_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        let list = proto::GeoSiteList::decode(bytes).map_err(|error| {
            format!("failed to decode xray geosite data: {error}")
        })?;
        let mut entries = HashMap::new();
        for entry in list.entry {
            validate_geosite(&entry)?;
            insert_unique(&mut entries, entry.code.clone(), entry, "geosite")?;
        }
        self.geo_sites = entries;
        Ok(())
    }

    pub(crate) fn load_geoip_file(&mut self, path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(path).map_err(|error| {
            format!("failed to read xray geoip data {}: {error}", path.display())
        })?;
        self.load_geoip_bytes(&bytes)
    }

    pub(crate) fn load_geosite_file(&mut self, path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(path).map_err(|error| {
            format!(
                "failed to read xray geosite data {}: {error}",
                path.display()
            )
        })?;
        self.load_geosite_bytes(&bytes)
    }

    pub(crate) fn geoip(&self, code: &str) -> Option<&proto::GeoIp> {
        self.geo_ips.get(&normalize_code(code))
    }

    pub(crate) fn geosite(&self, code: &str) -> Option<&proto::GeoSite> {
        self.geo_sites.get(&normalize_code(code))
    }

    pub(crate) fn ensure_default_geoip(&mut self) -> Result<(), String> {
        if self.geo_ips.is_empty() {
            self.load_geoip_file(&xray_asset_location("geoip.dat"))?;
        }
        Ok(())
    }

    pub(crate) fn ensure_default_geosite(&mut self) -> Result<(), String> {
        if self.geo_sites.is_empty() {
            self.load_geosite_file(&xray_asset_location("geosite.dat"))?;
        }
        Ok(())
    }

    pub(crate) fn expand_geoip(
        &self,
        code: &str,
        reverse: bool,
    ) -> Result<Vec<String>, String> {
        let entry = self.geoip(code).ok_or_else(|| {
            format!("xray geoip entry not found: {}", normalize_code(code))
        })?;
        entry
            .cidr
            .iter()
            .map(|cidr| {
                let address = match cidr.ip.as_slice() {
                    [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                    bytes if bytes.len() == 16 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes)
                            .expect("validated xray geoip IPv6 bytes"),
                    )),
                    _ => unreachable!("xray geoip CIDR validated during load"),
                };
                Ok(format!(
                    "{}{address}/{}",
                    if reverse ^ entry.reverse_match {
                        "!"
                    } else {
                        ""
                    },
                    cidr.prefix
                ))
            })
            .collect()
    }

    pub(crate) fn expand_geoip_file(
        &self,
        file: &str,
        code: &str,
        reverse: bool,
    ) -> Result<Vec<String>, String> {
        validate_asset_file(file)?;
        if file == "geoip.dat" {
            return self.expand_geoip(code, reverse);
        }
        let mut external = Self::default();
        external.load_geoip_file(&xray_asset_location(file))?;
        external.expand_geoip(code, reverse)
    }

    pub(crate) fn expand_geosite(
        &self,
        code: &str,
        attrs: &[&str],
    ) -> Result<Vec<String>, String> {
        let entry = self.geosite(code).ok_or_else(|| {
            format!("xray geosite entry not found: {}", normalize_code(code))
        })?;
        entry
            .domain
            .iter()
            .filter(|domain| {
                attrs.iter().all(|expected| {
                    domain
                        .attribute
                        .iter()
                        .any(|attribute| attribute.key == *expected)
                })
            })
            .map(|domain| {
                let domain_type = proto::domain::Type::try_from(domain.r#type)
                    .expect("xray geosite domain type validated during load");
                Ok(match domain_type {
                    proto::domain::Type::Substr => domain.value.clone(),
                    proto::domain::Type::Regex => {
                        format!("regexp:{}", domain.value)
                    }
                    proto::domain::Type::Domain => {
                        format!("domain:{}", domain.value)
                    }
                    proto::domain::Type::Full => {
                        format!("full:{}", domain.value)
                    }
                })
            })
            .collect()
    }

    pub(crate) fn expand_geosite_file(
        &self,
        file: &str,
        code: &str,
        attrs: &[&str],
    ) -> Result<Vec<String>, String> {
        validate_asset_file(file)?;
        if file == "geosite.dat" {
            return self.expand_geosite(code, attrs);
        }
        let mut external = Self::default();
        external.load_geosite_file(&xray_asset_location(file))?;
        external.expand_geosite(code, attrs)
    }
}

fn validate_asset_file(file: &str) -> Result<(), String> {
    use std::path::Component;

    let path = Path::new(file);
    if file.is_empty()
        || file == "."
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("asset path must stay in asset directory".into());
    }
    Ok(())
}

fn xray_asset_location(file: &str) -> PathBuf {
    let executable_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    let asset_dir = std::env::var_os("xray.location.asset")
        .or_else(|| std::env::var_os("XRAY_LOCATION_ASSET"))
        .map(PathBuf::from)
        .unwrap_or(executable_dir);
    let default_path = asset_dir.join(file);
    for candidate in [
        default_path.clone(),
        PathBuf::from("/usr/local/share/xray").join(file),
        PathBuf::from("/usr/share/xray").join(file),
        PathBuf::from("/opt/share/xray").join(file),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    default_path
}

fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

fn insert_unique<T>(
    entries: &mut HashMap<String, T>,
    code: String,
    value: T,
    kind: &str,
) -> Result<(), String> {
    let normalized = normalize_code(&code);
    if normalized.is_empty() {
        return Err(format!("xray {kind} entry code is required"));
    }
    if entries.insert(normalized.clone(), value).is_some() {
        return Err(format!("duplicate xray {kind} entry code {normalized}"));
    }
    Ok(())
}

fn validate_geoip(entry: &proto::GeoIp) -> Result<(), String> {
    if normalize_code(&entry.code).is_empty() {
        return Err("xray geoip entry code is required".into());
    }
    for cidr in &entry.cidr {
        let max_prefix = match cidr.ip.len() {
            4 => 32,
            16 => 128,
            length => {
                return Err(format!(
                    "xray geoip {} contains CIDR with invalid IP length {length}",
                    entry.code
                ));
            }
        };
        if cidr.prefix > max_prefix {
            return Err(format!(
                "xray geoip {} CIDR prefix {} exceeds {max_prefix}",
                entry.code, cidr.prefix
            ));
        }
    }
    Ok(())
}

fn validate_geosite(entry: &proto::GeoSite) -> Result<(), String> {
    if normalize_code(&entry.code).is_empty() {
        return Err("xray geosite entry code is required".into());
    }
    for domain in &entry.domain {
        proto::domain::Type::try_from(domain.r#type).map_err(|_| {
            format!(
                "xray geosite {} contains unknown domain type {}",
                entry.code, domain.r#type
            )
        })?;
        if domain.value.is_empty() {
            return Err(format!(
                "xray geosite {} contains an empty domain value",
                entry.code
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_geoip(entries: Vec<proto::GeoIp>) -> Vec<u8> {
        proto::GeoIpList { entry: entries }.encode_to_vec()
    }

    fn encode_geosite(entries: Vec<proto::GeoSite>) -> Vec<u8> {
        proto::GeoSiteList { entry: entries }.encode_to_vec()
    }

    #[test]
    fn geoip_codes_are_case_insensitive_and_cidrs_are_preserved() {
        let mut store = GeodataStore::default();
        store
            .load_geoip_bytes(&encode_geoip(vec![proto::GeoIp {
                code: "Cn".into(),
                cidr: vec![proto::Cidr {
                    ip: vec![203, 0, 113, 0],
                    prefix: 24,
                }],
                reverse_match: true,
            }]))
            .expect("load xray geoip fixture");

        let entry = store.geoip(" cn ").expect("case-insensitive geoip code");
        assert_eq!(entry.code, "Cn");
        assert!(entry.reverse_match);
        assert_eq!(entry.cidr[0].ip, vec![203, 0, 113, 0]);
        assert_eq!(entry.cidr[0].prefix, 24);
        assert!(store.geoip("missing").is_none());
    }

    #[test]
    fn geosite_domain_types_and_attributes_are_preserved() {
        let mut store = GeodataStore::default();
        store
            .load_geosite_bytes(&encode_geosite(vec![proto::GeoSite {
                code: "TEST".into(),
                domain: vec![proto::Domain {
                    r#type: proto::domain::Type::Domain as i32,
                    value: "example.com".into(),
                    attribute: vec![proto::domain::Attribute {
                        key: "ads".into(),
                        typed_value: Some(
                            proto::domain::attribute::TypedValue::BoolValue(true),
                        ),
                    }],
                }],
            }]))
            .expect("load xray geosite fixture");

        let domain = &store.geosite("test").expect("geosite code").domain[0];
        assert_eq!(domain.r#type, proto::domain::Type::Domain as i32);
        assert_eq!(domain.value, "example.com");
        assert_eq!(domain.attribute[0].key, "ads");
    }

    #[test]
    fn malformed_geoip_cidr_is_rejected_without_replacing_old_data() {
        let mut store = GeodataStore::default();
        store
            .load_geoip_bytes(&encode_geoip(vec![proto::GeoIp {
                code: "OLD".into(),
                cidr: vec![],
                reverse_match: false,
            }]))
            .expect("load old geoip data");

        let error = store
            .load_geoip_bytes(&encode_geoip(vec![proto::GeoIp {
                code: "BROKEN".into(),
                cidr: vec![proto::Cidr {
                    ip: vec![1, 2, 3],
                    prefix: 24,
                }],
                reverse_match: false,
            }]))
            .expect_err("invalid geoip CIDR must be rejected");

        assert!(error.contains("invalid IP length 3"));
        assert!(store.geoip("OLD").is_some());
        assert!(store.geoip("BROKEN").is_none());
    }

    #[test]
    fn duplicate_codes_are_rejected_case_insensitively() {
        let mut store = GeodataStore::default();
        let error = store
            .load_geosite_bytes(&encode_geosite(vec![
                proto::GeoSite {
                    code: "test".into(),
                    domain: vec![proto::Domain {
                        r#type: proto::domain::Type::Full as i32,
                        value: "a.example".into(),
                        attribute: vec![],
                    }],
                },
                proto::GeoSite {
                    code: "TEST".into(),
                    domain: vec![proto::Domain {
                        r#type: proto::domain::Type::Full as i32,
                        value: "b.example".into(),
                        attribute: vec![],
                    }],
                },
            ]))
            .expect_err("duplicate geosite codes must be rejected");

        assert!(error.contains("duplicate xray geosite entry code TEST"));
        assert!(store.geosite("test").is_none());
    }

    #[test]
    fn asset_paths_follow_xray_local_path_rules() {
        for accepted in ["custom.dat", "nested/custom.dat", "nested\\custom.dat"] {
            assert_eq!(validate_asset_file(accepted), Ok(()), "path {accepted}");
        }
        for rejected in ["", ".", "../custom.dat", "/tmp/custom.dat"] {
            let error = validate_asset_file(rejected)
                .expect_err("non-local asset path must be rejected");
            assert_eq!(error, "asset path must stay in asset directory");
        }
    }

    #[test]
    fn default_asset_aliases_reuse_preloaded_store() {
        let mut store = GeodataStore::default();
        store
            .load_geoip_bytes(&encode_geoip(vec![proto::GeoIp {
                code: "TEST".into(),
                cidr: vec![proto::Cidr {
                    ip: vec![203, 0, 113, 0],
                    prefix: 24,
                }],
                reverse_match: false,
            }]))
            .expect("load default geoip alias fixture");
        store
            .load_geosite_bytes(&encode_geosite(vec![proto::GeoSite {
                code: "TEST".into(),
                domain: vec![proto::Domain {
                    r#type: proto::domain::Type::Full as i32,
                    value: "only.example".into(),
                    attribute: vec![],
                }],
            }]))
            .expect("load default geosite alias fixture");

        assert_eq!(
            store
                .expand_geoip_file("geoip.dat", "test", false)
                .expect("expand default geoip alias"),
            vec!["203.0.113.0/24"]
        );
        assert_eq!(
            store
                .expand_geosite_file("geosite.dat", "test", &[])
                .expect("expand default geosite alias"),
            vec!["full:only.example"]
        );
    }

    #[test]
    fn truncated_protobuf_is_rejected() {
        let mut store = GeodataStore::default();
        let error = store
            .load_geoip_bytes(&[0x0a, 0x05, 0x01])
            .expect_err("truncated geoip protobuf must fail");
        assert!(error.contains("failed to decode xray geoip data"));
    }
}
