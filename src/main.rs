mod credential;
mod tpm;

use std::io::{self, Read, Write};
use std::path::Path;

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
/// Usage is compatible with systemd-creds encrypt:
///   mkcreds [OPTIONS] --tpm2-pcrs=PCRS INPUT OUTPUT
///   mkcreds [OPTIONS] --tpm2-pcrs=PCRS INPUT -      # output to stdout
///   mkcreds [OPTIONS] --tpm2-pcrs=PCRS - OUTPUT    # input from stdin
///
/// Examples:
///   # Use current PCR 7 and 15 values
///   echo "secret" | mkcreds --tpm2-pcrs=7+15 - mycred.cred
///
///   # Use expected value for PCR 15 (mkcreds extension)
///   echo "secret" | mkcreds --tpm2-pcrs="7+15:sha256=abc123..." - mycred.cred
///
/// The credential can be decrypted with:
///   systemd-creds decrypt mycred.cred -
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Credential name (embedded in encrypted payload, used for validation on decrypt).
    /// If not specified, defaults to the output filename (without path and .cred extension).
    #[arg(short, long)]
    name: Option<String>,

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

    /// Include specified invalidation time in encrypted credential.
    /// Accepts timestamps in various formats (systemd-compatible):
    ///   - Unix timestamp in seconds or microseconds
    ///   - ISO 8601 format: 2024-12-31T23:59:59
    ///   - Relative: +5min, +1h, +7d
    #[arg(long = "not-after", value_name = "TIME")]
    not_after: Option<String>,

    /// Input file ("-" for stdin)
    #[arg(default_value = "-")]
    input: String,

    /// Output file ("-" for stdout)
    #[arg(default_value = "-")]
    output: String,

    /// Print the expected policy hash (hex) without creating a credential
    #[arg(long)]
    print_policy: bool,
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
    let secret = read_secret(&args.input)?;

    if secret.is_empty() {
        anyhow::bail!("Secret cannot be empty");
    }

    // Derive credential name: explicit --name, or from output filename, or empty
    let cred_name = args
        .name
        .unwrap_or_else(|| derive_name_from_output(&args.output));

    // Parse not-after timestamp if provided
    let not_after = match &args.not_after {
        Some(s) => Some(parse_timestamp(s)?),
        None => None,
    };

    // Build systemd-creds compatible credential
    let mut builder = CredentialBuilder::new();
    if !cred_name.is_empty() {
        builder = builder.name(&cred_name);
    }
    if let Some(ts) = not_after {
        builder = builder.not_after(ts);
    }
    let credential = builder
        .build(&secret, &tpm2_data)
        .context("Failed to build credential")?;

    // Output (base64 encoded, matching systemd-creds output format)
    let encoded = base64::engine::general_purpose::STANDARD.encode(&credential);

    if args.output == "-" {
        io::stdout().write_all(encoded.as_bytes())?;
        io::stdout().write_all(b"\n")?;
    } else {
        std::fs::write(&args.output, format!("{}\n", encoded))
            .with_context(|| format!("Failed to write to {}", args.output))?;
        eprintln!("Credential written to {}", args.output);
    }

    Ok(())
}

/// Derive credential name from output filename.
/// Strips path and .cred extension if present.
fn derive_name_from_output(output: &str) -> String {
    if output == "-" {
        return String::new();
    }

    let path = Path::new(output);
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

    // Strip .cred extension if present
    filename
        .strip_suffix(".cred")
        .unwrap_or(filename)
        .to_string()
}

/// Parse timestamp string into microseconds since epoch.
/// Supports:
///   - Unix timestamp (seconds or microseconds)
///   - Relative: +5min, +1h, +7d
///   - "infinity" or "never" for no expiration
fn parse_timestamp(s: &str) -> Result<u64> {
    let s = s.trim();

    // Handle special values
    if s == "infinity" || s == "never" {
        return Ok(u64::MAX);
    }

    // Handle relative timestamps
    if let Some(rest) = s.strip_prefix('+') {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let duration = parse_duration(rest)?;
        return Ok(now.saturating_add(duration));
    }

    // Try parsing as numeric timestamp
    if let Ok(ts) = s.parse::<u64>() {
        // If it looks like seconds (< year 3000 in seconds), convert to microseconds
        if ts < 32503680000 {
            return Ok(ts.saturating_mul(1_000_000));
        }
        // Otherwise assume it's already in microseconds
        return Ok(ts);
    }

    anyhow::bail!(
        "Invalid timestamp format: {}. Use Unix timestamp, +DURATION, or 'infinity'",
        s
    )
}

/// Parse duration string like "5min", "1h", "7d" into microseconds.
fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();

    // Find where the number ends and unit begins
    let num_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_str, unit) = s.split_at(num_end);

    let num: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid duration number: {}", num_str))?;

    let multiplier: u64 = match unit.trim().to_lowercase().as_str() {
        "" | "s" | "sec" | "second" | "seconds" => 1_000_000,
        "m" | "min" | "minute" | "minutes" => 60 * 1_000_000,
        "h" | "hr" | "hour" | "hours" => 3600 * 1_000_000,
        "d" | "day" | "days" => 86400 * 1_000_000,
        "w" | "week" | "weeks" => 7 * 86400 * 1_000_000,
        other => anyhow::bail!("Unknown duration unit: {}", other),
    };

    Ok(num.saturating_mul(multiplier))
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

fn read_secret(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let data = if path == "-" {
        eprintln!("Reading secret from stdin...");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("5").unwrap(), 5_000_000);
        assert_eq!(parse_duration("5s").unwrap(), 5_000_000);
        assert_eq!(parse_duration("5sec").unwrap(), 5_000_000);
        assert_eq!(parse_duration("5second").unwrap(), 5_000_000);
        assert_eq!(parse_duration("5seconds").unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("5min").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("5minute").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("5minutes").unwrap(), 5 * 60 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), 2 * 3600 * 1_000_000);
        assert_eq!(parse_duration("2hr").unwrap(), 2 * 3600 * 1_000_000);
        assert_eq!(parse_duration("2hour").unwrap(), 2 * 3600 * 1_000_000);
        assert_eq!(parse_duration("2hours").unwrap(), 2 * 3600 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400 * 1_000_000);
        assert_eq!(parse_duration("7day").unwrap(), 7 * 86400 * 1_000_000);
        assert_eq!(parse_duration("7days").unwrap(), 7 * 86400 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_weeks() {
        assert_eq!(parse_duration("2w").unwrap(), 2 * 7 * 86400 * 1_000_000);
        assert_eq!(parse_duration("2week").unwrap(), 2 * 7 * 86400 * 1_000_000);
        assert_eq!(parse_duration("2weeks").unwrap(), 2 * 7 * 86400 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_case_insensitive() {
        assert_eq!(parse_duration("5MIN").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("5Min").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("2HOURS").unwrap(), 2 * 3600 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  5min  ").unwrap(), 5 * 60 * 1_000_000);
        assert_eq!(parse_duration("5 min").unwrap(), 5 * 60 * 1_000_000);
    }

    #[test]
    fn test_parse_duration_zero() {
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert_eq!(parse_duration("0s").unwrap(), 0);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5xyz").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_timestamp_infinity() {
        assert_eq!(parse_timestamp("infinity").unwrap(), u64::MAX);
        assert_eq!(parse_timestamp("never").unwrap(), u64::MAX);
        assert_eq!(parse_timestamp("  infinity  ").unwrap(), u64::MAX);
    }

    #[test]
    fn test_parse_timestamp_unix_seconds() {
        // Unix timestamp in seconds (should be converted to microseconds)
        assert_eq!(parse_timestamp("1000000000").unwrap(), 1000000000_000_000);
        assert_eq!(parse_timestamp("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_timestamp_unix_microseconds() {
        // Large value that looks like microseconds (> year 3000 in seconds)
        let ts_us = 33000000000_000_000u64; // ~year 3015 in microseconds
        assert_eq!(parse_timestamp(&ts_us.to_string()).unwrap(), ts_us);
    }

    #[test]
    fn test_parse_timestamp_relative() {
        // Relative timestamps should be in the future
        let result = parse_timestamp("+1h").unwrap();
        let now_approx = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        
        // Should be roughly 1 hour from now (with some tolerance)
        let one_hour_us = 3600 * 1_000_000;
        assert!(result > now_approx);
        assert!(result < now_approx + one_hour_us + 1_000_000); // 1 sec tolerance
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(parse_timestamp("not-a-timestamp").is_err());
        assert!(parse_timestamp("abc123").is_err());
    }

    #[test]
    fn test_derive_name_from_output() {
        assert_eq!(derive_name_from_output("mycred.cred"), "mycred");
        assert_eq!(derive_name_from_output("/path/to/mycred.cred"), "mycred");
        assert_eq!(derive_name_from_output("mycred"), "mycred");
        assert_eq!(derive_name_from_output("-"), "");
        assert_eq!(derive_name_from_output("/path/to/secret"), "secret");
    }
}
