#![cfg(all(feature = "tun-gateway", feature = "vless-reverse-tls"))]

use std::path::Path;

use chimera_server_lib::{ConfigType, Error, Options, validate};

#[test]
fn site_to_site_role_examples_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("app crate must be inside the workspace");

    for role in ["hub", "edge"] {
        validate_example(workspace_root, role).unwrap_or_else(|error| {
            panic!("site-to-site {role} example failed validation: {error}")
        });
    }

    let office_gateway = validate_example(workspace_root, "office-gateway");
    #[cfg(target_os = "linux")]
    office_gateway.unwrap_or_else(|error| {
        panic!("site-to-site office-gateway example failed validation: {error}")
    });

    #[cfg(not(target_os = "linux"))]
    assert!(matches!(
        office_gateway,
        Err(Error::InvalidConfig(message))
            if message.contains("tunGateway currently requires a Linux server build")
    ));
}

fn validate_example(workspace_root: &Path, role: &str) -> Result<(), Error> {
    let config_path = workspace_root
        .join("examples/site-to-site")
        .join(format!("{role}.yaml"));
    let config_path = config_path
        .to_str()
        .expect("workspace path must be valid UTF-8")
        .to_owned();

    validate(Options {
        config: ConfigType::File(config_path),
        config_format: None,
        cwd: Some(workspace_root.to_string_lossy().into_owned()),
        rt: None,
        log_file: None,
    })
}
