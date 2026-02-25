{
  description = "Create systemd-creds compatible TPM2-sealed credentials with custom PCR values";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
          ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Treefmt configuration
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.rustfmt.enable = true;
          programs.yamlfmt.enable = true;
          programs.prettier.enable = true; # For markdown
          programs.nixfmt.enable = true;
        };
        # Common build inputs for TPM2
        buildInputs = with pkgs; [
          tpm2-tss
          openssl
        ];

        nativeBuildInputs = with pkgs; [
          pkg-config
          rustToolchain
        ];

        # Common args for all crane builds
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          inherit buildInputs nativeBuildInputs;

          # tss-esapi needs these at build time
          OPENSSL_NO_VENDOR = "1";
          TSS2_ESYS_2_3 = "1";
        };

        # Build dependencies only (for caching)
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the crate
        mkcreds = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );
      in
      {
        packages = {
          default = mkcreds;
          mkcreds = mkcreds;
        };

        # Checks run by `nix flake check`
        checks = {
          # Build the package
          inherit mkcreds;

          # Format check (all file types)
          formatting = treefmtEval.config.build.check self;

          # Clippy lints
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "-- -D warnings";
            }
          );
        }
        //
          pkgs.lib.optionalAttrs pkgs.stdenv.isLinux
            # VM tests (Linux only)
            (import ./tests { inherit pkgs mkcreds; });

        # Formatter for `nix fmt`
        formatter = treefmtEval.config.build.wrapper;

        devShells.default = craneLib.devShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs;
          packages = with pkgs; [
            rust-analyzer
            cargo-watch
            tpm2-tools # For testing
            pkg-config
            treefmtEval.config.build.wrapper # treefmt
          ];

          OPENSSL_NO_VENDOR = "1";
          TSS2_ESYS_2_3 = "1";
        };
      }
    );
}
