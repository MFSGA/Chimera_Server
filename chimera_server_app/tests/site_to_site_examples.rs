#![cfg(all(feature = "tun-gateway", feature = "vless-reverse-tls"))]

use std::path::Path;

use chimera_server_lib::{ConfigType, Options, validate};

#[test]
fn site_to_site_role_examples_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("app crate must be inside the workspace");

    for role in ["hub", "edge", "office-gateway"] {
        let config_path = workspace_root
            .join("examples/site-to-site")
            .join(format!("{role}.yaml"));
        let config_path = config_path
            .to_str()
            .expect("workspace path must be valid UTF-8")
            .to_owned();

        validate(Options {
            config: ConfigType::File(config_path.clone()),
            config_format: None,
            cwd: Some(workspace_root.to_string_lossy().into_owned()),
            rt: None,
            log_file: None,
        })
        .unwrap_or_else(|error| {
            panic!("site-to-site {role} example failed validation: {error}")
        });
    }
}
