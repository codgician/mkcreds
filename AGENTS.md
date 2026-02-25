# AGENTS.md - mkcreds

Guide for AI coding agents working in this repository.

## Commands

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build (LTO + stripped)
cargo check                    # Check without building
nix build                      # Build with Nix (preferred)

# Test
cargo test                     # Run all tests
cargo test test_name           # Run single test by name
cargo test module_name::       # Run tests in module
cargo test -- --nocapture      # Run with output
nix build .#checks.x86_64-linux.vm-test  # VM integration test

# Lint & Format
cargo fmt                      # Format code
cargo fmt --check              # Check formatting
cargo clippy                   # Run lints
cargo clippy -- -D warnings    # Lints as errors
```

## Project Overview

Rust CLI tool (Edition 2024) that creates systemd-creds compatible TPM2-sealed credentials with **custom PCR values**. Solves limitation where `systemd-creds encrypt` cannot seal against expected (future) PCR values.

**Key files:**

- `src/main.rs` - CLI entry point, argument parsing
- `src/credential.rs` - systemd-creds compatible credential format builder
- `src/tpm.rs` - TPM2 operations: policy calculation and sealing
- `tests/vm-test.nix` - NixOS VM integration test (the source of truth)

## Boundaries

### ✅ Always

- Use `anyhow::Result<T>` with `.context()` for error handling
- Use `Zeroizing<T>` for secrets and key material
- Run `cargo clippy` before commits
- Test format changes with VM test - unit tests can't validate systemd compatibility

### ⚠️ Ask First

- Adding new dependencies
- Modifying credential format (must match systemd exactly)
- Changing TPM2 blob marshalling order

### 🚫 Never

- Use `.unwrap()` in library code - use `?` operator
- Log secrets or key material
- Suppress type errors with `as any`, `@ts-ignore`
- Modify format without verifying against systemd source

## systemd Compatibility (CRITICAL)

This tool must produce credentials that `systemd-creds decrypt` can read.

**TPM2 blob order** (`tpm.rs:marshal_sealed_blob`):

1. TPM2B_PRIVATE (size BE + data) — **PRIVATE FIRST**
2. TPM2B_PUBLIC (size BE + marshalled data)
3. TPM2B_ENCRYPTED_SECRET (size BE, typically 0)

**tpm2_credential_header order** (`credential.rs:build_headers`):

- blob FIRST, policy_hash SECOND in `policy_hash_and_blob[]`

**AES-256-GCM params**: `block_size=1` (GCM stream mode), `iv_size=12`, `tag_size=16`

**Reference**: Verify against systemd `src/shared/tpm2-util.c` and `src/shared/creds-util.c`.

## Code Style

### Imports

Group in order, separated by blank lines: std → external crates (alphabetical) → crate-internal

```rust
use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use clap::Parser;

use crate::credential::CredentialBuilder;
```

### Error Handling

```rust
// Good - contextual errors
let sealer = Tpm2Sealer::new(&args.tpm2_device)
    .context("Failed to initialize TPM2 context")?;

// Good - early return
if pcr_values.is_empty() {
    anyhow::bail!("At least one PCR must be specified");
}
```

### Naming

- Functions/methods: `snake_case`
- Types/structs/enums: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`

### Patterns

- Builder pattern for complex construction (see `CredentialBuilder`)
- Implement `Default` when sensible
- Doc comments (`///`) for public items, module docs (`//!`) at file top

## Dependencies

| Crate       | Purpose                       |
| ----------- | ----------------------------- |
| `tss-esapi` | TPM2 bindings                 |
| `aes-gcm`   | AES-256-GCM encryption        |
| `sha2`      | SHA256 hashing                |
| `clap`      | CLI argument parsing (derive) |
| `anyhow`    | Error handling                |
| `zeroize`   | Secure memory clearing        |

## Environment Setup

### With Nix (recommended)

```bash
nix develop        # Enter dev shell
direnv allow       # Or use direnv
```

### Without Nix

Requires: Rust toolchain, `tpm2-tss` dev libs, `pkg-config`, `openssl` dev libs

```bash
export OPENSSL_NO_VENDOR=1
export TSS2_ESYS_2_3=1
```

## Debugging

**Credential decryption fails:**

1. Check blob order (PRIVATE first)
2. Check header order (blob before policy_hash)
3. Verify AES params (block_size=1, iv_size=12)
4. Use `--name=X` on decrypt if name mismatch

**Policy mismatch:**

1. Use `--print-policy` to see computed hash
2. PCR values must be sorted by index
3. Check PCR selection bytes format

**VM test is the source of truth** - unit tests cannot validate TPM operations or systemd compatibility.
