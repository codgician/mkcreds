mod credential;
mod tpm;

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use zeroize::Zeroizing;

use crate::credential::CredentialBuilder;
use crate::tpm::{ExpectedPcrValue, Tpm2Sealer};

/// Create systemd-creds compatible TPM2-sealed credentials with custom PCR values.
///
/// This tool allows sealing credentials against EXPECTED PCR values (not current),
/// enabling offline enrollment for anti-replay protection scenarios.
///
/// Examples:
///   # Use current PCR 7 and 15 values
///   echo "secret" | mkcreds --name mycred --tpm2-pcrs=7+15
///
///   # Use current PCR 7, but expected value for PCR 15
///   echo "secret" | mkcreds --name mycred --tpm2-pcrs="7+15:sha256=abc123..."
///
/// The credential can be decrypted with:
///   systemd-creds decrypt mycred.cred -
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Credential name (embedded in encrypted payload, used for validation on decrypt)
    #[arg(short, long)]
    name: String,

    /// PCR values to seal against (systemd-creds compatible syntax).
    ///
    /// Format: PCR[+PCR...] where each PCR is either:
    ///   - INDEX              (use current value from TPM)
    ///   - INDEX:ALG=VALUE    (use specified expected value)
    ///
    /// Examples:
    ///   --tpm2-pcrs=7+15
    ///   --tpm2-pcrs="7+15:sha256=abc123..."
    ///   --tpm2-pcrs="7:sha256=xxx+15:sha256=yyy"
    #[arg(long = "tpm2-pcrs", required = true, verbatim_doc_comment)]
    tpm2_pcrs: String,

    /// TPM2 device path or TCTI string.
    #[arg(long = "tpm2-device", default_value = "device:/dev/tpmrm0")]
    tpm2_device: String,

    /// Read secret from file instead of stdin ("-" for stdin)
    #[arg(default_value = "-")]
    input: String,

    /// Write credential to file instead of stdout ("-" for stdout)
    #[arg(short, long, default_value = "-")]
    output: String,

    /// Print the expected policy hash (hex) without creating a credential
    #[arg(long)]
    print_policy: bool,

    /// Suppress informational messages
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse PCR specifications (systemd-creds compatible: "7+15:sha256=...")
    let pcr_values = parse_tpm2_pcrs(&args.tpm2_pcrs)?;

    if pcr_values.is_empty() {
        anyhow::bail!("At least one PCR must be specified");
    }

    // Initialize TPM
    let mut sealer =
        Tpm2Sealer::new(&args.tpm2_device).context("Failed to initialize TPM2 context")?;

    // Seal random key with expected PCR values
    let tpm2_data = sealer
        .seal_with_expected_pcrs(&pcr_values)
        .context("Failed to seal to TPM2")?;

    if args.print_policy {
        // Just print the policy hash and exit
        println!("{}", hex::encode(&tpm2_data.policy_hash));
        return Ok(());
    }

    // Read secret from stdin or file
    let secret = read_secret(&args.input, args.quiet)?;

    if secret.is_empty() {
        anyhow::bail!("Secret cannot be empty");
    }

    // Build systemd-creds compatible credential
    let credential = CredentialBuilder::new()
        .name(&args.name)
        .build(&secret, &tpm2_data)
        .context("Failed to build credential")?;

    // Output (base64 encoded, matching systemd-creds output format)
    let encoded = base64::engine::general_purpose::STANDARD.encode(&credential);

    if args.output == "-" {
        io::stdout().write_all(encoded.as_bytes())?;
        io::stdout().write_all(b"\n")?;
    } else {
        std::fs::write(&args.output, &encoded)
            .with_context(|| format!("Failed to write to {}", args.output))?;
        if !args.quiet {
            eprintln!("Credential written to {}", args.output);
        }
    }

    Ok(())
}

/// Parse systemd-creds compatible PCR specification.
/// Format: "PCR[+PCR...]" where each PCR is "INDEX" or "INDEX:ALG=VALUE"
///
/// Examples:
///   "7+15" -> [PCR 7 (current), PCR 15 (current)]
///   "7+15:sha256=abc" -> [PCR 7 (current), PCR 15 (expected: abc)]
///   "7:sha256=xxx+15:sha256=yyy" -> [PCR 7 (expected: xxx), PCR 15 (expected: yyy)]
fn parse_tpm2_pcrs(spec: &str) -> Result<Vec<ExpectedPcrValue>> {
    spec.split('+')
        .filter(|s| !s.is_empty())
        .map(ExpectedPcrValue::parse)
        .collect()
}

fn read_secret(path: &str, quiet: bool) -> Result<Zeroizing<Vec<u8>>> {
    let data = if path == "-" {
        if !quiet {
            eprintln!("Reading secret from stdin...");
        }
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read secret from stdin")?;
        buf
    } else {
        std::fs::read(path).with_context(|| format!("Failed to read secret from {}", path))?
    };
    Ok(Zeroizing::new(data))
}
