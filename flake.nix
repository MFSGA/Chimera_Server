{
  description = "Chimera_Server development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # nixos-unstable 26.11 dropped x86_64-darwin; keep both macOS
    # architectures on the last supported Darwin release branch.
    nixpkgsDarwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  };

  outputs = { nixpkgs, nixpkgsDarwin, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      darwinSystems = [
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      forAllDevSystems = nixpkgs.lib.genAttrs (supportedSystems ++ darwinSystems);

      windowsMsvcTarget = "x86_64-pc-windows-msvc";

      mkPkgs = system:
        let
          nixpkgsSource = if builtins.elem system darwinSystems then nixpkgsDarwin else nixpkgs;
        in
        import nixpkgsSource {
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
            # Xray-core v26.9.9 (52a412d9) requires Go 1.27.
            go_1_27
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

      mkMacosShell = pkgs:
        pkgs.mkShell {
          packages = with pkgs; [
            cargo
            cargo-watch
            cmake
            clippy
            gnumake
            llvmPackages.clang
            llvmPackages.libclang
            llvmPackages.llvm
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

          shellHook = ''
            echo "Chimera macOS development shell"
            if command -v xcrun >/dev/null 2>&1; then
              export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
              echo "Using Apple SDK: $SDKROOT"
            else
              echo "Xcode Command Line Tools are required (run: xcode-select --install)."
            fi
          '';
        };

      windowsMsvcPackages = pkgs: with pkgs; [
        cargo-xwin
        cmake
        llvmPackages.clang
        llvmPackages.libclang
        llvmPackages.lld
        llvmPackages.llvm
        ninja
        protobuf
        rustup
      ];

      # This shell prepares a Linux or macOS host for a Windows MSVC-targeted Cargo build.
      # It does not replace the native Windows runner: cargo-xwin supplies a
      # downloaded Windows SDK/CRT sysroot, while ml64.exe and native Windows
      # execution remain available only on a Windows MSVC environment.
      mkWindowsMsvcShell = pkgs:
        pkgs.mkShell {
          packages = windowsMsvcPackages pkgs;

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          RUST_BACKTRACE = "1";
          RUST_LOG = "info";
          RUSTUP_TOOLCHAIN = "stable";
          XWIN_ARCH = "x86_64";
          XWIN_CROSS_COMPILER = "clang-cl";

          shellHook = ''
            echo "Chimera Windows MSVC cross shell"
            echo
            echo "Before the first build, ensure the Rust target is installed:"
            echo "  rustup target add ${windowsMsvcTarget}"
            echo
            echo "Build with the Windows SDK/CRT sysroot managed by cargo-xwin:"
            echo "  cargo xwin build --release --locked --target ${windowsMsvcTarget} --package chimera_server_app"
            echo
            echo "On Linux, use nix develop .#windows-msvc-test for local Windows-binary smoke tests."
            echo "The windows-latest MSVC CI job remains the authoritative validation."
          '';
        };

      mkWindowsMsvcTestShell = pkgs:
        pkgs.mkShell {
          packages = windowsMsvcPackages pkgs ++ [
            pkgs.wineWow64Packages.stable
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          PROTOC = "${pkgs.protobuf}/bin/protoc";
          RUST_BACKTRACE = "1";
          RUST_LOG = "info";
          RUSTUP_TOOLCHAIN = "stable";
          XWIN_ARCH = "x86_64";
          XWIN_CROSS_COMPILER = "clang-cl";

          shellHook = ''
            echo "Chimera Windows MSVC cross-build and Wine test shell"
            echo "Ensure the Rust target is installed:"
            echo "  rustup target add ${windowsMsvcTarget}"
            echo "Build:"
            echo "  cargo xwin build --release --locked --target ${windowsMsvcTarget} --package chimera_server_app"
            echo "Run focused target tests with cargo xwin test when the Wine environment supports them."
          '';
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

      devShells = forAllDevSystems (system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = if builtins.elem system darwinSystems then mkMacosShell pkgs else mkDevShell pkgs;
          windows-msvc = mkWindowsMsvcShell pkgs;
        }
        // nixpkgs.lib.optionalAttrs (builtins.elem system darwinSystems) {
          macos = mkMacosShell pkgs;
        }
        // nixpkgs.lib.optionalAttrs (builtins.elem system supportedSystems) {
          windows-msvc-test = mkWindowsMsvcTestShell pkgs;
        });
      };
}
