# mkcreds

Create systemd-creds compatible TPM2-sealed credentials with **custom PCR values**.

This tool solves a limitation of `systemd-creds encrypt`: it cannot seal credentials against *expected* (future) PCR values, only current ones. This is problematic for anti-replay protection scenarios where you need to:

1. Extend a PCR with application-specific data (e.g., ZFS pool fingerprint)
2. Seal a credential against the *extended* PCR state
3. Enroll the credential *before* the system has booted with that configuration

## The Problem

`systemd-creds encrypt` reads current PCR values and seals against them:

```bash
# This reads the CURRENT value of PCR 15, which is all zeros before boot
systemd-creds encrypt --tpm2-pcrs=15 - - < secret.txt
```

But if your boot process extends PCR 15 with custom data, the credential won't unseal.

`systemd-cryptenroll` supports specifying expected values:

```bash
# This works - seals against the specified value
systemd-cryptenroll --tpm2-pcrs="15:sha256=abc123..." /dev/sda
```

But `systemd-creds` doesn't support this syntax ([systemd issue #38763](https://github.com/systemd/systemd/issues/38763)).

## The Solution

`mkcreds` creates systemd-creds compatible credentials that can be sealed against **expected** PCR values:

```bash
# Seal against expected PCR 15 value (after your boot process extends it)
echo "my-secret" | mkcreds \
    --name mycred \
    --tpm2-pcrs="7+15:sha256=9305fd411ed713f0e9e3f116880563f2d06a3f85d8cf8c5041d4479da2e0fea8"
```

The resulting credential can be decrypted with standard `systemd-creds`:

```bash
systemd-creds decrypt mycred.cred -
```

## Installation

### With Nix

```bash
nix build github:your-username/mkcreds
# Or run directly
nix run github:your-username/mkcreds -- --help
```

### From Source

```bash
cargo build --release
```

Requires `tpm2-tss` development libraries and `pkg-config`.

## Usage

### Basic (use current PCR values)

```bash
echo "secret-data" | mkcreds --name mycred --tpm2-pcrs=7+15 > mycred.cred
```

### With expected PCR values

```bash
echo "secret-data" | mkcreds \
    --name mycred \
    --tpm2-pcrs="7+15:sha256=<expected-hex-value>" \
    --output mycred.cred
```

### Print policy hash only

Useful for verifying your PCR policy calculation:

```bash
mkcreds --name test --tpm2-pcrs="7+15:sha256=..." --print-policy
```

## PCR Specification Format

- `7` or `7+15` - Use current value(s) from TPM
- `7:sha256=abc123...` - Use specified value for PCR 7 (64 hex chars for SHA256)
- `7+15:sha256=abc...` - PCR 7 current, PCR 15 with expected value
- `7:sha256=xxx+15:sha256=yyy` - Both with expected values

## Motivation

This tool addresses a community request to support expected PCR values in `systemd-creds` (see [systemd/systemd#38763](https://github.com/systemd/systemd/issues/38763)).

## Compatibility

- Output format is compatible with `systemd-creds decrypt`
- Tested with systemd 254+
- Requires TPM 2.0

## Security Notes

- The sealed HMAC key is generated randomly and never leaves the TPM in plaintext
- AES-256-GCM is used for payload encryption (same as systemd-creds)
- PCR policy is calculated according to TPM2 spec (PolicyPCR command)

## License

LGPL-2.1
