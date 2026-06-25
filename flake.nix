{
  description = "Chimera_Server development environment";
  inputs.nixpkgs.url = "path:/nix/store/pzxxxg9vvzk63122vj38lcmqg9dl6qxk-nixos-26.05.1947.a0374025a863/nixos";
  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          cargo rustc rustfmt clippy cargo-watch
          clang llvmPackages.libclang cmake ninja gnumake pkg-config protobuf
        ];
        buildInputs = with pkgs; [ openssl ];
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        RUST_BACKTRACE = "1";
      };
    };
}
