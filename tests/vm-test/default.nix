# Main VM test for mkcreds (comprehensive)
# Run with: nix build .#checks.x86_64-linux.vm-test
#
# This test validates all mkcreds features including:
# - Current PCR values
# - Expected (future) PCR values (main feature)
# - Multiple PCRs
# - CLI options (--name, --print-policy)
# - Credential expiration (--not-after)
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds";
  testScript = ''
    import time

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

    with subtest("Credential with expected PCR value (main feature)"):
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

    with subtest("Multiple PCRs (7+15)"):
        # Use current PCR 7 value (typically contains UEFI Secure Boot state)
        # and current PCR 15 value (already extended from previous test)
        machine.succeed("echo -n 'multi-pcr-secret' | mkcreds --tpm2-pcrs='7+15' - /tmp/multi_pcr.cred")
        machine.succeed("test -s /tmp/multi_pcr.cred")
        
        # Should decrypt since we're using current values
        decrypted = machine.succeed("systemd-creds decrypt --name=multi_pcr /tmp/multi_pcr.cred -").strip()
        assert decrypted == "multi-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Multiple PCR credential test passed")

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

    with subtest("File input (not stdin)"):
        machine.succeed("echo -n 'file-input-secret' > /tmp/secret_input.txt")
        machine.succeed("mkcreds --tpm2-pcrs=15 /tmp/secret_input.txt /tmp/file_input.cred")
        
        decrypted = machine.succeed("systemd-creds decrypt --name=file_input /tmp/file_input.cred -").strip()
        assert decrypted == "file-input-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("File input test passed")

    machine.log("All tests passed!")
  '';
}
