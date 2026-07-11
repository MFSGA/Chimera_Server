{
  description = "Chimera_Server development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      mkPkgs = system:
        import nixpkgs {
          inherit system;
        };

      mkChimera = pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "chimera-server";
          version = "0.3.2";

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let
                baseName = baseNameOf path;
              in
              !(type == "directory" && builtins.elem baseName [
                ".direnv"
                "target"
                "ref"
              ])
              && !(type == "directory" && baseName == "__pycache__")
              && !(pkgs.lib.hasSuffix ".pyc" path);
          };

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = with pkgs; [
            clang
            cmake
            llvmPackages.libclang
            pkg-config
            protobuf
          ];

          buildInputs = with pkgs; [
            openssl
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          PROTOC = "${pkgs.protobuf}/bin/protoc";

          doCheck = false;

          meta = {
            description = "Rust networking core for Chimera Server";
            homepage = "https://github.com/Chimera-Server/Chimera_Server";
            license = pkgs.lib.licenses.lgpl3Plus;
            mainProgram = "chimera_server_app";
          };
        };

      mkDevShell = pkgs:
        pkgs.mkShell {
          packages = with pkgs; [
            cargo
            cargo-watch
            clang
            clippy
            cmake
            gnumake
            llvmPackages.libclang
            ninja
            openssl
            pkg-config
            protobuf
            rust-analyzer
            rustc
            rustfmt
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          RUST_BACKTRACE = "1";
          RUST_LOG = "info";
        };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = mkChimera pkgs;
          chimera-server = mkChimera pkgs;
        });

      apps = forAllSystems (system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = {
            type = "app";
            program = "${mkChimera pkgs}/bin/chimera_server_app";
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = mkDevShell pkgs;
        });
      };
}
