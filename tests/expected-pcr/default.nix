# Test credential enrollment with expected (future) PCR values
# This is the main feature that distinguishes mkcreds from systemd-creds
# Run with: nix build .#checks.x86_64-linux.expected-pcr
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-expected-pcr";

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("Enroll credential against expected PCR value, extend PCR, decrypt"):
        # Step 1: Get current PCR 15 value (should be all zeros initially)
        machine.succeed("tpm2_pcrread sha256:15 -o /tmp/pcr15_initial.bin")
        pcr15_initial = machine.succeed("xxd -p -c64 /tmp/pcr15_initial.bin").strip()
        machine.log(f"Initial PCR 15: {pcr15_initial}")

        # Step 2: Define what we'll extend with
        extend_data = "my-unique-fingerprint-12345"

        # Step 3: Compute the hash of extend_data
        extend_hash = machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha256 -binary | xxd -p -c64").strip()
        machine.log(f"Extend data hash: {extend_hash}")

        # Step 4: Compute expected PCR 15 value after extension
        # PCR_new = SHA256(PCR_old || extend_hash)
        expected_pcr15 = machine.succeed(
            f"cat /tmp/pcr15_initial.bin <(echo -n '{extend_hash}' | xxd -r -p) | openssl dgst -sha256 -binary | xxd -p -c64"
        ).strip()
        machine.log(f"Expected PCR 15 after extend: {expected_pcr15}")

        # Step 5: Create credential bound to the EXPECTED (future) PCR 15 value
        machine.succeed(f"echo -n 'expected-pcr-secret' | mkcreds --tpm2-pcrs='15:sha256={expected_pcr15}' - /tmp/expected_pcr.cred")
        machine.succeed("test -s /tmp/expected_pcr.cred")
        machine.log("Credential created successfully")

        # Step 6: Verify decryption FAILS before PCR extension (PCR 15 doesn't match)
        exit_code, output = machine.execute("systemd-creds decrypt /tmp/expected_pcr.cred - 2>&1")
        machine.log(f"Decrypt before extend (should fail): exit={exit_code}, output={output}")
        assert exit_code != 0, "Decryption should fail before PCR extension"

        # Step 7: Extend PCR 15 with the fingerprint data
        machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha256 -binary | xxd -p -c64 | tpm2_pcrextend 15:sha256=$(cat)")

        # Verify PCR 15 now matches expected
        machine.succeed("tpm2_pcrread sha256:15 -o /tmp/pcr15_after.bin")
        pcr15_after = machine.succeed("xxd -p -c64 /tmp/pcr15_after.bin").strip()
        machine.log(f"PCR 15 after extend: {pcr15_after}")
        assert pcr15_after == expected_pcr15, f"PCR mismatch: got {pcr15_after}, expected {expected_pcr15}"

        # Step 8: NOW decryption should succeed with systemd-creds
        decrypted = machine.succeed("systemd-creds decrypt --name=expected_pcr /tmp/expected_pcr.cred -").strip()
        machine.log(f"Decrypted: {decrypted}")
        assert decrypted == "expected-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"

    machine.log("Expected PCR test passed!")
  '';
}
