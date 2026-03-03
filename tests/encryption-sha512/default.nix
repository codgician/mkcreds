# Encryption tests for mkcreds using SHA512 PCR bank
# Tests SHA512 policy calculation and sealing
# Run with: nix build .#checks.x86_64-linux.encryption-sha512
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-encryption-sha512";

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # ==========================================================================
    # Verify SHA512 policy hash calculation
    # ==========================================================================

    with subtest("Print policy hash (--print-policy) for SHA512"):
        policy_hash = machine.succeed("mkcreds --tpm2-pcrs='15:sha512' --print-policy").strip()
        # Policy hash is ALWAYS SHA256 (64 hex chars) regardless of PCR bank
        # This is because systemd uses SHA256 for policy session calculations
        assert len(policy_hash) == 64, f"Policy hash should be 64 hex chars (SHA256), got {len(policy_hash)}"
        assert all(c in '0123456789abcdef' for c in policy_hash), "Policy hash should be hex"
        machine.log(f"Policy hash (SHA256): {policy_hash}")

    with subtest("Print PCR values (--print-pcrs) for SHA512"):
        output = machine.succeed("mkcreds --tpm2-pcrs='7:sha512+15:sha512' --print-pcrs").strip()
        lines = output.split('\n')
        assert len(lines) == 2, f"Expected 2 PCR values, got {len(lines)}"

        for line in lines:
            assert ':sha512=' in line, f"Expected format 'index:sha512=hex', got '{line}'"
            parts = line.split('=')
            # SHA512 = 128 hex chars (512 bits / 4 bits per hex char)
            assert len(parts[1]) == 128, f"Expected 128 hex chars for SHA512, got {len(parts[1])}"
        machine.log("SHA512 PCR values verified")

    # ==========================================================================
    # Test SHA512 encryption with expected PCR value (main feature)
    # This tests the core functionality - sealing against FUTURE state
    # ==========================================================================

    with subtest("SHA512 with expected PCR value (enroll against future state)"):
        # Get current PCR 16 value in SHA512 bank (as raw binary)
        machine.succeed("tpm2_pcrread sha512:16 -o /tmp/pcr16_initial.bin")
        pcr16_initial = machine.succeed("xxd -p -c128 /tmp/pcr16_initial.bin").strip()
        machine.log(f"Initial PCR 16 (SHA512): {pcr16_initial}")

        # Define extend data and compute expected value
        # PCR_new = SHA512(PCR_old || SHA512(data))
        extend_data = "sha512-fingerprint"
        extend_hash = machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha512 -binary | xxd -p -c128").strip()
        machine.log(f"Extend hash: {extend_hash}")

        expected_pcr16 = machine.succeed(
            f"cat /tmp/pcr16_initial.bin <(echo -n '{extend_hash}' | xxd -r -p) | openssl dgst -sha512 -binary | xxd -p -c128"
        ).strip()
        machine.log(f"Expected PCR 16 after extend: {expected_pcr16}")

        # Create credential for expected PCR value using SHA512
        machine.succeed(f"echo -n 'expected-secret' | mkcreds --tpm2-pcrs='16:sha512={expected_pcr16}' - /tmp/expected.cred")
        machine.succeed("test -s /tmp/expected.cred")
        machine.log("Credential created successfully")

        # Should fail before extend (PCR doesn't match expected value)
        result = machine.execute("systemd-creds decrypt --name=expected /tmp/expected.cred - 2>&1")
        assert result[0] != 0, "Decryption should fail before PCR extension"
        machine.log(f"Decryption correctly failed before extend: {result[1]}")

        # Extend PCR 16 with the data
        machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha512 -binary | tpm2_pcrextend 16:sha512=$(xxd -p -c128)")

        # Verify the PCR was extended correctly (read just the binary and convert to hex)
        machine.succeed("tpm2_pcrread sha512:16 -o /tmp/pcr16_new.bin")
        new_pcr = machine.succeed("xxd -p -c128 /tmp/pcr16_new.bin").strip()
        machine.log(f"Actual PCR 16 after extend: {new_pcr}")
        assert new_pcr == expected_pcr16, f"PCR mismatch: expected {expected_pcr16}, got {new_pcr}"

        # Now try to decrypt - should succeed after extend
        result = machine.execute("systemd-creds decrypt --name=expected /tmp/expected.cred - 2>&1")
        machine.log(f"Decrypt result after extend: exit_code={result[0]}, output={result[1]}")

        if result[0] != 0:
            machine.log("ERROR: Decryption failed even after PCR extend!")
            machine.log("This likely means the credential format is incompatible with systemd.")
            # Debug: show some info about the credential
            machine.succeed("xxd /tmp/expected.cred | head -20")
            raise Exception(f"Decryption failed: {result[1]}")

        decrypted = result[1].strip()
        assert decrypted == "expected-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("SHA512 expected PCR value test passed!")

    machine.log("All SHA512 encryption tests passed!")
  '';
}
