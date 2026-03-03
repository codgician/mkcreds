# Comprehensive encryption tests for mkcreds (SHA256 bank)
# Tests all encryption scenarios with SHA256 PCR bank (default)
# Run with: nix build .#checks.x86_64-linux.encryption-sha256
{ pkgs, mkcreds }:

let
  common = import ../common.nix { inherit pkgs mkcreds; };
in
common.mkTest {
  name = "mkcreds-encryption-sha256";

  testScript = ''
    import time

    machine.wait_for_unit("multi-user.target")

    # ==========================================================================
    # Basic functionality
    # ==========================================================================

    with subtest("Check TPM device exists"):
        machine.succeed("test -e /dev/tpm0")
        machine.succeed("test -e /dev/tpmrm0")

    with subtest("Check mkcreds binary works"):
        machine.succeed("mkcreds --help")
        machine.succeed("mkcreds --version")

    # ==========================================================================
    # PCR bank definition scenarios
    # ==========================================================================

    with subtest("No hash algo defined (auto-select bank)"):
        # Should auto-select SHA256 (preferred bank)
        machine.succeed("echo -n 'auto-bank-secret' | mkcreds --tpm2-pcrs=15 - /tmp/auto_bank.cred")
        machine.succeed("test -s /tmp/auto_bank.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=auto_bank /tmp/auto_bank.cred -").strip()
        assert decrypted == "auto-bank-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Auto bank selection test passed")

    with subtest("Explicit SHA256 bank"):
        machine.succeed("echo -n 'sha256-secret' | mkcreds --tpm2-pcrs='15:sha256' - /tmp/sha256_bank.cred")
        machine.succeed("test -s /tmp/sha256_bank.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=sha256_bank /tmp/sha256_bank.cred -").strip()
        assert decrypted == "sha256-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Explicit SHA256 bank test passed")

    with subtest("First PCR has algo, second inherits (7:sha256+15)"):
        # First specifies algorithm, second inherits it
        machine.succeed("echo -n 'first-algo-secret' | mkcreds --tpm2-pcrs='7:sha256+15' - /tmp/first_algo.cred")
        machine.succeed("test -s /tmp/first_algo.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=first_algo /tmp/first_algo.cred -").strip()
        assert decrypted == "first-algo-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("First PCR has algo test passed")

    with subtest("Second PCR has algo, first inherits (7+15:sha256)"):
        # Second specifies algorithm, first inherits it (systemd-cryptenroll compatible)
        machine.succeed("echo -n 'second-algo-secret' | mkcreds --tpm2-pcrs='7+15:sha256' - /tmp/second_algo.cred")
        machine.succeed("test -s /tmp/second_algo.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=second_algo /tmp/second_algo.cred -").strip()
        assert decrypted == "second-algo-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Second PCR has algo test passed (systemd-cryptenroll compatible)")

    with subtest("All PCRs with explicit hash algo"):
        machine.succeed("echo -n 'all-algo-secret' | mkcreds --tpm2-pcrs='7:sha256+15:sha256' - /tmp/all_algo.cred")
        machine.succeed("test -s /tmp/all_algo.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=all_algo /tmp/all_algo.cred -").strip()
        assert decrypted == "all-algo-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("All explicit algorithm test passed")

    with subtest("Inconsistent hash algo should fail"):
        # Different algorithms for different PCRs should fail
        exit_code = machine.execute("echo -n 'should-fail' | mkcreds --tpm2-pcrs='7:sha256+15:sha384' - /tmp/mixed.cred")[0]
        assert exit_code != 0, "Mixed banks should have failed"
        machine.log("Mixed banks correctly rejected")

    with subtest("PCR name support"):
        # Using well-known PCR names instead of numbers
        machine.succeed("echo -n 'pcr-name-secret' | mkcreds --tpm2-pcrs='system-identity' - /tmp/pcr_name.cred")
        machine.succeed("test -s /tmp/pcr_name.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=pcr_name /tmp/pcr_name.cred -").strip()
        assert decrypted == "pcr-name-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("PCR name support test passed")

    with subtest("Mixed PCR name and number"):
        machine.succeed("echo -n 'mixed-name-num' | mkcreds --tpm2-pcrs='secure-boot-policy+15' - /tmp/mixed_name.cred")
        machine.succeed("test -s /tmp/mixed_name.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=mixed_name /tmp/mixed_name.cred -").strip()
        assert decrypted == "mixed-name-num", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Mixed name and number test passed")

    # ==========================================================================
    # Expected PCR value scenarios (main feature)
    # ==========================================================================

    with subtest("Without expected PCR value (use current)"):
        machine.succeed("echo -n 'current-pcr-secret' | mkcreds --tpm2-pcrs=15 - /tmp/current_pcr.cred")
        machine.succeed("test -s /tmp/current_pcr.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=current_pcr /tmp/current_pcr.cred -").strip()
        assert decrypted == "current-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Current PCR value test passed")

    with subtest("With expected PCR value (enroll against future state)"):
        # Get current PCR 16 value (use PCR 16 to avoid affecting other tests)
        machine.succeed("tpm2_pcrread sha256:16 -o /tmp/pcr16_initial.bin")
        pcr16_initial = machine.succeed("xxd -p -c64 /tmp/pcr16_initial.bin").strip()
        machine.log(f"Initial PCR 16: {pcr16_initial}")

        # Define what we'll extend with
        extend_data = "my-unique-fingerprint-12345"

        # Compute the hash of extend_data
        extend_hash = machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha256 -binary | xxd -p -c64").strip()
        machine.log(f"Extend data hash: {extend_hash}")

        # Compute expected PCR 16 value after extension: PCR_new = SHA256(PCR_old || extend_hash)
        expected_pcr16 = machine.succeed(
            f"cat /tmp/pcr16_initial.bin <(echo -n '{extend_hash}' | xxd -r -p) | openssl dgst -sha256 -binary | xxd -p -c64"
        ).strip()
        machine.log(f"Expected PCR 16 after extend: {expected_pcr16}")

        # Create credential bound to the EXPECTED (future) PCR 16 value
        machine.succeed(f"echo -n 'expected-pcr-secret' | mkcreds --tpm2-pcrs='16:sha256={expected_pcr16}' - /tmp/expected_pcr.cred")
        machine.succeed("test -s /tmp/expected_pcr.cred")
        machine.log("Credential created for expected PCR value")

        # Verify decryption FAILS before PCR extension
        exit_code, output = machine.execute("systemd-creds decrypt /tmp/expected_pcr.cred - 2>&1")
        machine.log(f"Decrypt before extend (should fail): exit={exit_code}")
        assert exit_code != 0, "Decryption should fail before PCR extension"

        # Extend PCR 16 with the fingerprint data
        machine.succeed(f"echo -n '{extend_data}' | openssl dgst -sha256 -binary | xxd -p -c64 | tpm2_pcrextend 16:sha256=$(cat)")

        # Verify PCR 16 now matches expected
        machine.succeed("tpm2_pcrread sha256:16 -o /tmp/pcr16_after.bin")
        pcr16_after = machine.succeed("xxd -p -c64 /tmp/pcr16_after.bin").strip()
        machine.log(f"PCR 16 after extend: {pcr16_after}")
        assert pcr16_after == expected_pcr16, f"PCR mismatch: got {pcr16_after}, expected {expected_pcr16}"

        # NOW decryption should succeed
        decrypted = machine.succeed("systemd-creds decrypt --name=expected_pcr /tmp/expected_pcr.cred -").strip()
        assert decrypted == "expected-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Expected PCR value test passed")

    # ==========================================================================
    # Expiration scenarios
    # ==========================================================================

    with subtest("Without expiration (default)"):
        machine.succeed("echo -n 'no-expiry-default' | mkcreds --tpm2-pcrs=15 - /tmp/no_expiry_default.cred")
        decrypted = machine.succeed("systemd-creds decrypt --name=no_expiry_default /tmp/no_expiry_default.cred -").strip()
        assert decrypted == "no-expiry-default", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("No expiration (default) test passed")

    with subtest("With expiration (--not-after with short duration)"):
        machine.succeed("echo -n 'expiring-secret' | mkcreds --tpm2-pcrs=15 --not-after=+2s - /tmp/expiring.cred")

        # Should work immediately
        decrypted = machine.succeed("systemd-creds decrypt --name=expiring /tmp/expiring.cred -").strip()
        assert decrypted == "expiring-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Credential decrypted before expiration")

        # Wait for expiration
        time.sleep(3)

        # Should fail after expiration
        exit_code, _ = machine.execute("systemd-creds decrypt --name=expiring /tmp/expiring.cred - 2>&1")
        assert exit_code != 0, "Decryption should fail after expiration"
        machine.log("Expiration test passed")

    with subtest("With expiration (--not-after with days)"):
        machine.succeed("echo -n 'long-expiry-secret' | mkcreds --tpm2-pcrs=15 --not-after=+7d - /tmp/long_expiry.cred")
        decrypted = machine.succeed("systemd-creds decrypt --name=long_expiry /tmp/long_expiry.cred -").strip()
        assert decrypted == "long-expiry-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Long expiration test passed")

    with subtest("With expiration infinity"):
        machine.succeed("echo -n 'infinity-secret' | mkcreds --tpm2-pcrs=15 --not-after=infinity - /tmp/infinity.cred")
        decrypted = machine.succeed("systemd-creds decrypt --name=infinity /tmp/infinity.cred -").strip()
        assert decrypted == "infinity-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Infinity expiration test passed")

    # ==========================================================================
    # Credential name scenarios
    # ==========================================================================

    with subtest("Without credential name (derive from filename)"):
        machine.succeed("echo -n 'unnamed-secret' | mkcreds --tpm2-pcrs=15 - /tmp/derived_name.cred")
        # Name derived from output filename
        decrypted = machine.succeed("systemd-creds decrypt --name=derived_name /tmp/derived_name.cred -").strip()
        assert decrypted == "unnamed-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Derived name test passed")

    with subtest("With explicit credential name (--name)"):
        machine.succeed("echo -n 'named-secret' | mkcreds --tpm2-pcrs=15 --name=my-custom-name - /tmp/named.cred")

        # Must use matching --name on decrypt
        decrypted = machine.succeed("systemd-creds decrypt --name=my-custom-name /tmp/named.cred -").strip()
        assert decrypted == "named-secret", f"Decrypted content mismatch: got '{decrypted}'"

        # Wrong name should fail
        exit_code, _ = machine.execute("systemd-creds decrypt --name=wrong-name /tmp/named.cred - 2>&1")
        assert exit_code != 0, "Decryption with wrong name should fail"
        machine.log("Explicit name test passed")

    # ==========================================================================
    # Other CLI options
    # ==========================================================================

    with subtest("Print policy hash (--print-policy, auto-select bank)"):
        policy_hash = machine.succeed("mkcreds --tpm2-pcrs=15 --print-policy").strip()
        # Policy hash should be 64 hex chars (SHA256 - auto-selected)
        assert len(policy_hash) == 64, f"Policy hash should be 64 hex chars, got {len(policy_hash)}"
        assert all(c in '0123456789abcdef' for c in policy_hash), "Policy hash should be hex"
        machine.log(f"Policy hash (auto bank): {policy_hash}")

    with subtest("Print policy hash (--print-policy, explicit SHA256 bank)"):
        policy_hash_explicit = machine.succeed("mkcreds --tpm2-pcrs=15:sha256 --print-policy").strip()
        assert len(policy_hash_explicit) == 64, f"Policy hash should be 64 hex chars, got {len(policy_hash_explicit)}"
        # Should match the auto-selected one since SHA256 is preferred
        assert policy_hash == policy_hash_explicit, "Explicit SHA256 should match auto-selected"
        machine.log(f"Policy hash (explicit SHA256): {policy_hash_explicit}")

    with subtest("Print current PCR values (--print-pcrs)"):
        output = machine.succeed("mkcreds --tpm2-pcrs='7+15' --print-pcrs").strip()
        lines = output.split('\n')
        assert len(lines) == 2, f"Expected 2 PCR values, got {len(lines)}"
        
        # Each line should be in format: index:alg=hexvalue
        for line in lines:
            assert ':sha256=' in line, f"Expected format 'index:sha256=hex', got '{line}'"
            parts = line.split('=')
            assert len(parts) == 2, f"Invalid format: {line}"
            # SHA256 = 64 hex chars
            assert len(parts[1]) == 64, f"Expected 64 hex chars, got {len(parts[1])}"
        machine.log(f"PCR values: {lines}")

    with subtest("File input (not stdin)"):
        machine.succeed("echo -n 'file-input-secret' > /tmp/secret_input.txt")
        machine.succeed("mkcreds --tpm2-pcrs=15 /tmp/secret_input.txt /tmp/file_input.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=file_input /tmp/file_input.cred -").strip()
        assert decrypted == "file-input-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("File input test passed")

    with subtest("Multiple PCRs (7+15)"):
        machine.succeed("echo -n 'multi-pcr-secret' | mkcreds --tpm2-pcrs='7+15' - /tmp/multi_pcr.cred")
        machine.succeed("test -s /tmp/multi_pcr.cred")

        decrypted = machine.succeed("systemd-creds decrypt --name=multi_pcr /tmp/multi_pcr.cred -").strip()
        assert decrypted == "multi-pcr-secret", f"Decrypted content mismatch: got '{decrypted}'"
        machine.log("Multiple PCRs test passed")

    machine.log("All encryption tests passed!")
  '';
}
