use std::{collections::HashSet, path::PathBuf};

use chimera_server_lib::{ConfigFormat, ConfigType, Options, validate};

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("examples")
        .join("xray-compatible")
}

fn example_files() -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(examples_dir())
        .expect("examples/xray-compatible should exist")
        .map(|entry| entry.expect("example dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json5"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn load_json5(path: &PathBuf) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    json5::from_str(&content).unwrap_or_else(|err| {
        panic!("failed to parse {} as JSON5: {err}", path.display())
    })
}

#[test]
fn xray_compatible_examples_validate_through_public_config_path() {
    let files = example_files();
    assert!(!files.is_empty(), "expected xray-compatible examples");

    for path in files {
        validate(Options {
            config: ConfigType::File(path.to_string_lossy().into_owned()),
            config_format: Some(ConfigFormat::Json5),
            cwd: None,
            rt: None,
            log_file: None,
        })
        .unwrap_or_else(|err| panic!("{} should validate: {err}", path.display()));
    }
}

#[test]
fn xray_compatible_examples_use_unique_tags_and_ports() {
    let mut tags = HashSet::new();
    let mut ports = HashSet::new();

    for path in example_files() {
        let value = load_json5(&path);
        let inbounds = value
            .get("inbounds")
            .and_then(|value| value.as_array())
            .unwrap_or_else(|| panic!("{} missing inbounds array", path.display()));
        assert_eq!(
            inbounds.len(),
            1,
            "{} should contain one focused inbound example",
            path.display()
        );

        let inbound = &inbounds[0];
        let tag = inbound
            .get("tag")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("{} missing inbound tag", path.display()));
        assert!(
            tags.insert(tag.to_string()),
            "duplicate inbound tag {tag} in {}",
            path.display()
        );

        let port = inbound
            .get("port")
            .and_then(|value| value.as_u64())
            .unwrap_or_else(|| panic!("{} missing inbound port", path.display()));
        assert!(
            ports.insert(port),
            "duplicate inbound port {port} in {}",
            path.display()
        );
    }
}

#[test]
fn xray_compatible_example_matrix_contains_materialized_stage_one_files() {
    let files = example_files()
        .into_iter()
        .map(|path| {
            path.file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<HashSet<_>>();

    for expected in [
        "socks-tcp-noauth.json5",
        "socks-tcp-password.json5",
        "dokodemo-door-tcp.json5",
        "vless-tcp-none.json5",
        "vless-ws-none.json5",
        "vless-ws-tls.json5",
        "vless-tcp-tls-vision.json5",
        "vless-xhttp-none.json5",
        "vless-xhttp-tls.json5",
        "vmess-tcp-none.json5",
        "vmess-ws-none.json5",
        "vmess-ws-tls.json5",
        "trojan-tcp-none.json5",
        "trojan-tcp-tls.json5",
        "trojan-ws-tls.json5",
        "hysteria-quic-tls.json5",
    ] {
        assert!(files.contains(expected), "missing {expected}");
    }
}
