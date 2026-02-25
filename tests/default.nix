# Auto-discover all VM tests in subdirectories
# Usage in flake.nix: checks = import ./tests { inherit pkgs mkcreds; };
#
# To add a new test:
#   1. Create a subdirectory: tests/my-test/
#   2. Add tests/my-test/default.nix that imports ../common.nix
#
# Structure:
#   tests/
#   ├── default.nix   # This file (auto-discovery)
#   ├── common.nix    # Shared machine config
#   ├── basic/
#   │   └── default.nix
#   └── my-test/
#       └── default.nix
{ pkgs, mkcreds }:

let
  # Read directory contents
  dirContents = builtins.readDir ./.;

  # Filter: only directories (each test is a subdirectory)
  isTestDir = name: type: type == "directory";

  testDirs = pkgs.lib.filterAttrs isTestDir dirContents;

  # Import each test directory's default.nix
  importTest = name: _: import ./${name} { inherit pkgs mkcreds; };
in
pkgs.lib.mapAttrs importTest testDirs
