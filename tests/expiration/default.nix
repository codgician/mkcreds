# Test credential expiration (--not-after)
# Run with: nix build .#checks.x86_64-linux.expiration
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-expiration";

  testScript = ''
    import time

    machine.wait_for_unit("multi-user.target")

    with subtest("Credential expiration (--not-after)"):
        # Create credential that expires in 2 seconds
        machine.succeed("echo -n 'expiring-secret' | mkcreds --tpm2-pcrs=15 --not-after=+2s - /tmp/expiring.cred")

        # Should work immediately
        decrypted = machine.succeed("systemd-creds decrypt --name=expiring /tmp/expiring.cred -").strip()
        assert decrypted == "expiring-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Credential decrypted before expiration")

        # Wait for expiration
        time.sleep(3)

        # Should fail after expiration
        exit_code, output = machine.execute("systemd-creds decrypt --name=expiring /tmp/expiring.cred - 2>&1")
        machine.log(f"Decrypt after expiration: exit={exit_code}, output={output}")
        assert exit_code != 0, "Decryption should fail after expiration"
        machine.log("Expiration test passed")

    with subtest("Long expiration (--not-after with days)"):
        # Create credential that expires in 7 days (should work now)
        machine.succeed("echo -n 'long-expiry-secret' | mkcreds --tpm2-pcrs=15 --not-after=+7d - /tmp/long_expiry.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=long_expiry /tmp/long_expiry.cred -").strip()
        assert decrypted == "long-expiry-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Long expiration test passed")

    with subtest("No expiration (infinity)"):
        machine.succeed("echo -n 'no-expiry-secret' | mkcreds --tpm2-pcrs=15 --not-after=infinity - /tmp/no_expiry.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=no_expiry /tmp/no_expiry.cred -").strip()
        assert decrypted == "no-expiry-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("No expiration test passed")

    machine.log("All expiration tests passed!")
  '';
}
