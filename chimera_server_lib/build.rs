fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .map_err(|err| format!("failed to locate vendored protoc: {err}"))?;
    std::env::set_var("PROTOC", protoc_path);

    let proto_root = "proto";
    println!("cargo:rerun-if-changed={}", proto_root);
    tonic_build::configure().build_client(false).compile(
        &[
            "proto/app/stats/command/command.proto",
            "proto/app/log/command/config.proto",
            "proto/app/proxyman/command/command.proto",
            "proto/app/router/command/command.proto",
            "proto/app/observatory/command/command.proto",
            "proto/app/observatory/config.proto",
            "proto/core/config.proto",
            "proto/common/serial/typed_message.proto",
            "proto/common/protocol/user.proto",
            "proto/common/net/network.proto",
        ],
        &[proto_root],
    )?;
    Ok(())
}
