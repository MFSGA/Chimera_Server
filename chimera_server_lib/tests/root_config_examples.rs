use std::path::PathBuf;

use chimera_server_lib::{ConfigFormat, ConfigType, Options, validate};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn root_config_examples_validate_through_public_config_path() {
    let root = workspace_root();

    for file_name in [
        "config_reality_min.json",
        "config_reality_xray.json5",
        "config_all_combos.json5",
    ] {
        let path = root.join(file_name);
        validate(Options {
            config: ConfigType::File(path.to_string_lossy().into_owned()),
            config_format: Some(ConfigFormat::Json5),
            cwd: Some(root.to_string_lossy().into_owned()),
            rt: None,
            log_file: None,
        })
        .unwrap_or_else(|err| panic!("{file_name} should validate: {err}"));
    }
}
