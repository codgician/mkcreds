{
  description = "Create systemd-creds compatible TPM2-sealed credentials with custom PCR values";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common build inputs for TPM2
        buildInputs = with pkgs; [
          tpm2-tss
          openssl
        ];

        nativeBuildInputs = with pkgs; [
          pkg-config
          rustToolchain
        ];

        # Build the crate
        mkcreds = craneLib.buildPackage {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          inherit buildInputs nativeBuildInputs;

          # tss-esapi needs these at build time
          OPENSSL_NO_VENDOR = "1";
          TSS2_ESYS_2_3 = "1";
        };
      in
      {
        packages = {
          default = mkcreds;
          mkcreds = mkcreds;
        };

        # NixOS VM test with TPM
        checks = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          vm-test = import ./tests/vm-test.nix {
            inherit pkgs mkcreds;
          };
        };

        devShells.default = craneLib.devShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs;
          packages = with pkgs; [
            rust-analyzer
            cargo-watch
            tpm2-tools # For testing
            pkg-config
          ];

          OPENSSL_NO_VENDOR = "1";
          TSS2_ESYS_2_3 = "1";
        };
      }
    );
}
