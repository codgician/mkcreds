# Shared VM configuration for mkcreds tests
{ pkgs, mkcreds }:

{
  # Machine configuration shared by all tests
  machineConfig =
    { pkgs, ... }:
    {
      virtualisation.tpm.enable = true;

      environment.systemPackages = [
        mkcreds
        pkgs.tpm2-tools
        pkgs.openssl
        pkgs.unixtools.xxd
      ];

      # Enable TPM2 support
      security.tpm2 = {
        enable = true;
        abrmd.enable = true;
      };
    };

  # Helper to create a test with shared config
  mkTest =
    { name, testScript }:
    pkgs.testers.runNixOSTest {
      inherit name testScript;
      nodes.machine =
        { pkgs, ... }:
        {
          virtualisation.tpm.enable = true;

          environment.systemPackages = [
            mkcreds
            pkgs.tpm2-tools
            pkgs.openssl
            pkgs.unixtools.xxd
          ];

          security.tpm2 = {
            enable = true;
            abrmd.enable = true;
          };
        };
    };
}
