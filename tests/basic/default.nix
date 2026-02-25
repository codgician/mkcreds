# Basic functionality tests for mkcreds
# Run with: nix build .#checks.x86_64-linux.basic
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-basic";

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("Check TPM device exists"):
        machine.succeed("test -e /dev/tpm0")
        machine.succeed("test -e /dev/tpmrm0")

    with subtest("Check mkcreds binary works"):
        machine.succeed("mkcreds --help")
        machine.succeed("mkcreds --version")

    with subtest("Credential with current PCR values"):
        # Create credential using CURRENT PCR 15 value (no expected value)
        machine.succeed("echo -n 'current-pcr-secret' | mkcreds --tpm2-pcrs=15 - /tmp/current_pcr.cred")
        machine.succeed("test -s /tmp/current_pcr.cred")

        # Should decrypt immediately since PCR 15 hasn't changed
        decrypted = machine.succeed("systemd-creds decrypt --name=current_pcr /tmp/current_pcr.cred -").strip()
        assert decrypted == "current-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Current PCR credential test passed")

    with subtest("Multiple PCRs (7+15)"):
        machine.succeed("echo -n 'multi-pcr-secret' | mkcreds --tpm2-pcrs='7+15' - /tmp/multi_pcr.cred")
        machine.succeed("test -s /tmp/multi_pcr.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=multi_pcr /tmp/multi_pcr.cred -").strip()
        assert decrypted == "multi-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Multiple PCR credential test passed")

    with subtest("File input (not stdin)"):
        machine.succeed("echo -n 'file-input-secret' > /tmp/secret_input.txt")
        machine.succeed("mkcreds --tpm2-pcrs=15 /tmp/secret_input.txt /tmp/file_input.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=file_input /tmp/file_input.cred -").strip()
        assert decrypted == "file-input-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("File input test passed")

    machine.log("All basic tests passed!")
  '';
}
