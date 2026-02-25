# Test CLI options: --name, --print-policy
# Run with: nix build .#checks.x86_64-linux.options
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-options";

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("Explicit credential name (--name)"):
        machine.succeed("echo -n 'named-secret' | mkcreds --tpm2-pcrs=15 --name=my-custom-name - /tmp/named.cred")

        # Must use matching --name on decrypt
        decrypted = machine.succeed("systemd-creds decrypt --name=my-custom-name /tmp/named.cred -").strip()
        assert decrypted == "named-secret", f"Decrypted content mismatch: got '{decrypted}'"

        # Wrong name should fail
        exit_code, _ = machine.execute("systemd-creds decrypt --name=wrong-name /tmp/named.cred - 2>&1")
        assert exit_code != 0, "Decryption with wrong name should fail"
        machine.log("Explicit name test passed")

    with subtest("Print policy hash (--print-policy)"):
        policy_hash = machine.succeed("mkcreds --tpm2-pcrs=15 --print-policy").strip()
        # Policy hash should be 64 hex chars (SHA256)
        assert len(policy_hash) == 64, f"Policy hash should be 64 hex chars, got {len(policy_hash)}"
        assert all(c in '0123456789abcdef' for c in policy_hash), "Policy hash should be hex"
        machine.log(f"Policy hash: {policy_hash}")
    machine.log("All options tests passed!")
  '';
}
