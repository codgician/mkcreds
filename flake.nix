{
  description = "Create systemd-creds compatible TPM2-sealed credentials with custom PCR values";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      treefmt-nix,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Per-system helper that computes all shared values once
      mkSystem =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rustfmt"
              "clippy"
            ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          treefmtEval = treefmt-nix.lib.evalModule pkgs {
            projectRootFile = "flake.nix";
            programs.rustfmt.enable = true;
            programs.yamlfmt.enable = true;
            programs.prettier.enable = true;
            programs.nixfmt.enable = true;
          };

          buildInputs = with pkgs; [
            tpm2-tss
            openssl
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];

          commonArgs = {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            inherit buildInputs nativeBuildInputs;
            OPENSSL_NO_VENDOR = "1";
            TSS2_ESYS_2_3 = "1";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          mkcreds = craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; });
        in
        {
          inherit
            pkgs
            craneLib
            treefmtEval
            buildInputs
            commonArgs
            cargoArtifacts
            mkcreds
            ;
        };

      # Memoized per-system values
      systemFor = forAllSystems mkSystem;
    in
    {
      packages = forAllSystems (system: {
        default = systemFor.${system}.mkcreds;
      });

      checks = forAllSystems (
        system:
        let
          s = systemFor.${system};
        in
        {
          formatting = s.treefmtEval.config.build.check self;
          clippy = s.craneLib.cargoClippy (
            s.commonArgs
            // {
              inherit (s) cargoArtifacts;
              cargoClippyExtraArgs = "-- -D warnings";
            }
          );
        }
        // import ./tests { inherit (s) pkgs mkcreds; }
      );

      formatter = forAllSystems (system: systemFor.${system}.treefmtEval.config.build.wrapper);

      devShells = forAllSystems (
        system:
        let
          s = systemFor.${system};
        in
        {
          default = s.craneLib.devShell {
            inherit (s) buildInputs;
            packages = [
              s.pkgs.rust-analyzer
              s.pkgs.cargo-watch
              s.pkgs.tpm2-tools
              s.treefmtEval.config.build.wrapper
            ];
            OPENSSL_NO_VENDOR = "1";
            TSS2_ESYS_2_3 = "1";
          };
        }
      );
    };
}
