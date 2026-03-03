# mkcreds

[![Build](https://github.com/codgician/mkcreds/actions/workflows/build.yml/badge.svg)](https://github.com/codgician/mkcreds/actions/workflows/build.yml)
[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL--2.1-blue.svg)](https://opensource.org/licenses/LGPL-2.1)

Create systemd-creds compatible TPM2-sealed credentials with **expected PCR values**.

This addresses [systemd/systemd#38763](https://github.com/systemd/systemd/issues/38763) — `systemd-creds encrypt` cannot seal against future PCR states, only current ones.

## Quick Start

```bash
# Run directly with Nix (no installation needed)
nix run github:codgician/mkcreds -- --tpm2-pcrs=7+15 - mycred.cred
```

## Usage

```bash
# Compatible with systemd-creds encrypt syntax
mkcreds [OPTIONS] --tpm2-pcrs=PCRS INPUT OUTPUT

# Seal with current PCR values
echo "secret" | mkcreds --tpm2-pcrs=7+15 - mycred.cred

# Seal with EXPECTED PCR value (main feature)
echo "secret" | mkcreds --tpm2-pcrs="7+15:sha256=<expected-hex>" - mycred.cred

# With expiration
echo "secret" | mkcreds --tpm2-pcrs=7+15 --not-after=+7d - mycred.cred

# Decrypt with standard systemd-creds
systemd-creds decrypt mycred.cred -
```

## Options

| Option               | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `--tpm2-pcrs=PCRS`   | PCRs to seal against (required)                       |
| `--name=NAME`        | Credential name (default: output filename)            |
| `--not-after=TIME`   | Expiration (`+1h`, `+7d`, Unix timestamp, `infinity`) |
| `--tpm2-device=PATH` | TPM device (default: `/dev/tpmrm0`)                   |
| `--print-policy`     | Print TPM2 policy hash (for debugging)                |
| `--print-pcrs`       | Print current PCR values (for debugging)              |

### Debugging Options

- **`--print-pcrs`**: Shows the current PCR values from the TPM in `index:alg=hex` format. Useful for capturing the current state before sealing.

- **`--print-policy`**: Shows the TPM2 policy hash — a cryptographic digest representing the constraint "these PCRs must have these values". This hash is embedded in the credential and used by the TPM to enforce access control. Two credentials with identical PCR bindings will have the same policy hash.

## PCR Format

The `--tpm2-pcrs` syntax is compatible with [`systemd-cryptenroll`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html#--tpm2-pcrs=PCR):

| Format            | Description                             |
| ----------------- | --------------------------------------- |
| `7`               | PCR 7, auto-select bank, current value  |
| `7:sha256`        | PCR 7, SHA256 bank, current value       |
| `7=<hex>`         | PCR 7, auto-select bank, expected value |
| `7:sha256=<hex>`  | PCR 7, SHA256 bank, expected value      |
| `system-identity` | PCR 15 by name, current value           |

Multiple PCRs: `7+15` or `secure-boot-policy+system-identity`

Supported banks: `sha1`, `sha256`, `sha384`, `sha512`

When no bank is specified, auto-selects the best available (prefers SHA256 > SHA384 > SHA512 > SHA1).

## License

LGPL-2.1
