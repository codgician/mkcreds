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
| `--print-policy`     | Print policy hash only                                |
| `-q, --quiet`        | Suppress messages                                     |

## PCR Format

Compatible with `systemd-cryptenroll` syntax:

- `7+15` — Use current values
- `15:sha256=<hex>` — Use expected value
- `7+15:sha256=<hex>` — Mix current and expected

## License

LGPL-2.1
