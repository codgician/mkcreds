//! TPM2 operations: policy calculation and sealing with expected PCR values.

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use tss_esapi::{
    Context as TpmContext,
    attributes::ObjectAttributesBuilder,
    constants::{
        CapabilityType, CommandCode, SessionType,
        tss::{TPM2_ALG_ECC, TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512},
    },
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        CapabilityData, CreateKeyResult, CreatePrimaryKeyResult, Digest as TpmDigest, EccPoint,
        PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder,
        SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
};
use zeroize::Zeroizing;

use crate::credential::Tpm2SealedData;

/// Maximum sealed data size (TPM2 limit)
const TPM2_MAX_SEALED_DATA: usize = 128;

/// Size of random key to seal (matches systemd)
const SEALED_KEY_SIZE: usize = 32;

/// Expected PCR value for policy binding
#[derive(Debug, Clone)]
pub struct ExpectedPcrValue {
    pub index: u32,
    pub hash_alg: Option<HashingAlgorithm>, // None = use default bank
    pub value: Option<Vec<u8>>,             // None = read current value from TPM
}

impl ExpectedPcrValue {
    /// Parse a PCR specification string (systemd-cryptenroll compatible).
    ///
    /// Formats:
    ///   "7"                    - PCR 7, default bank, read current value
    ///   "7:sha256"             - PCR 7, SHA256 bank, read current value
    ///   "7=abcd..."            - PCR 7, default bank, expected value
    ///   "7:sha256=abcd..."     - PCR 7, SHA256 bank, expected value
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();

        // Check for "index:alg" or "index:alg=value" format
        if let Some(colon_pos) = spec.find(':') {
            let index_str = &spec[..colon_pos];
            let rest = &spec[colon_pos + 1..];

            let index = parse_pcr_index(index_str)?;

            // Check for "alg=value" or just "alg"
            if let Some(eq_pos) = rest.find('=') {
                let alg_str = &rest[..eq_pos];
                let value_str = &rest[eq_pos + 1..];

                let hash_alg = parse_hash_algorithm(alg_str)?;
                let value = hex::decode(value_str)
                    .with_context(|| format!("Invalid hex value: {value_str}"))?;

                Ok(Self {
                    index,
                    hash_alg: Some(hash_alg),
                    value: Some(value),
                })
            } else {
                // Just "index:alg"
                let hash_alg = parse_hash_algorithm(rest)?;
                Ok(Self {
                    index,
                    hash_alg: Some(hash_alg),
                    value: None,
                })
            }
        } else if let Some(eq_pos) = spec.find('=') {
            // "index=value" format (no algorithm specified)
            let index_str = &spec[..eq_pos];
            let value_str = &spec[eq_pos + 1..];

            let index = parse_pcr_index(index_str)?;
            let value = hex::decode(value_str)
                .with_context(|| format!("Invalid hex value: {value_str}"))?;

            Ok(Self {
                index,
                hash_alg: None,
                value: Some(value),
            })
        } else {
            // Just "index"
            let index = parse_pcr_index(spec)?;
            Ok(Self {
                index,
                hash_alg: None,
                value: None,
            })
        }
    }
}

/// Parse PCR index from string (supports numeric and well-known names)
fn parse_pcr_index(s: &str) -> Result<u32> {
    let s = s.trim();

    // Try numeric first
    if let Ok(index) = s.parse::<u32>() {
        if index > 23 {
            return Err(anyhow!("PCR index must be 0-23, got {index}"));
        }
        return Ok(index);
    }

    // Try well-known names (matching systemd)
    let index = match s.to_lowercase().as_str() {
        "platform-code" => 0,
        "platform-config" => 1,
        "external-code" => 2,
        "external-config" => 3,
        "boot-loader-code" => 4,
        "boot-loader-config" => 5,
        "secure-boot-policy" => 7,
        "kernel-initrd" => 9,
        "ima" => 10,
        "kernel-boot" => 11,
        "kernel-config" => 12,
        "sysexts" => 13,
        "shim-policy" => 14,
        "system-identity" => 15,
        "debug" => 16,
        "application-support" => 23,
        _ => return Err(anyhow!("Invalid PCR index or name: {s}")),
    };

    Ok(index)
}

/// Parse hash algorithm name
fn parse_hash_algorithm(s: &str) -> Result<HashingAlgorithm> {
    match s.trim().to_lowercase().as_str() {
        "sha1" => Ok(HashingAlgorithm::Sha1),
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        "sha512" => Ok(HashingAlgorithm::Sha512),
        other => Err(anyhow!("Unsupported hash algorithm: {other}")),
    }
}

/// Get the TPM2 algorithm ID for a HashingAlgorithm
const fn hash_alg_to_tpm2_alg(alg: HashingAlgorithm) -> u16 {
    match alg {
        HashingAlgorithm::Sha1 => TPM2_ALG_SHA1,
        HashingAlgorithm::Sha384 => TPM2_ALG_SHA384,
        HashingAlgorithm::Sha512 => TPM2_ALG_SHA512,
        // SHA256 and other algorithms default to SHA256
        _ => TPM2_ALG_SHA256,
    }
}

/// Get the digest size for a hash algorithm
const fn hash_alg_digest_size(alg: HashingAlgorithm) -> usize {
    match alg {
        HashingAlgorithm::Sha1 => 20,
        HashingAlgorithm::Sha384 => 48,
        HashingAlgorithm::Sha512 => 64,
        // SHA256 and other algorithms default to 32 bytes
        _ => 32,
    }
}

/// Resolve the PCR bank to use.
///
/// Algorithm (matching systemd-cryptenroll):
/// 1. If any PCR specifies an algorithm, that becomes the default
/// 2. All PCRs must use the same algorithm (error if mixed)
/// 3. If no algorithm specified, auto-detect best bank from TPM
pub fn resolve_pcr_bank(
    pcr_values: &[ExpectedPcrValue],
    available_banks: &[HashingAlgorithm],
) -> Result<HashingAlgorithm> {
    // Find first explicitly specified algorithm
    let mut specified_alg: Option<HashingAlgorithm> = None;

    for pv in pcr_values {
        if let Some(alg) = pv.hash_alg {
            if let Some(existing) = specified_alg {
                if existing != alg {
                    return Err(anyhow!(
                        "Mixed PCR banks not supported: got {} and {}. \
                         All PCRs must use the same hash algorithm.",
                        hash_alg_name(existing),
                        hash_alg_name(alg)
                    ));
                }
            } else {
                specified_alg = Some(alg);
            }
        }
    }

    // If an algorithm was specified, use it
    if let Some(alg) = specified_alg {
        if !available_banks.contains(&alg) {
            return Err(anyhow!(
                "TPM does not support {} PCR bank",
                hash_alg_name(alg)
            ));
        }
        return Ok(alg);
    }

    // Auto-detect best bank (systemd preference order: SHA256 > SHA384 > SHA512 > SHA1)
    let preference_order = [
        HashingAlgorithm::Sha256,
        HashingAlgorithm::Sha384,
        HashingAlgorithm::Sha512,
        HashingAlgorithm::Sha1,
    ];

    for alg in preference_order {
        if available_banks.contains(&alg) {
            return Ok(alg);
        }
    }

    Err(anyhow!("No supported PCR bank found on TPM"))
}

/// Get human-readable name for a hash algorithm
pub const fn hash_alg_name(alg: HashingAlgorithm) -> &'static str {
    match alg {
        HashingAlgorithm::Sha1 => "SHA1",
        HashingAlgorithm::Sha256 => "SHA256",
        HashingAlgorithm::Sha384 => "SHA384",
        HashingAlgorithm::Sha512 => "SHA512",
        _ => "unknown",
    }
}

/// TPM2 sealer that supports expected (future) PCR values
pub struct Tpm2Sealer {
    context: TpmContext,
}

impl Tpm2Sealer {
    /// Create a new TPM2 sealer
    pub fn new(device: &str) -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable()
            .or_else(|_| TctiNameConf::from_str(device))
            .with_context(|| format!("Invalid TCTI: {device}"))?;

        let context = TpmContext::new(tcti).context("Failed to create TPM2 context")?;

        Ok(Self { context })
    }

    /// Get available PCR banks from TPM using capability query.
    /// This avoids noisy error messages from failed PCR read probes.
    pub fn get_available_pcr_banks(&mut self) -> Vec<HashingAlgorithm> {
        // Query TPM for assigned PCR banks (TPM2_CAP_PCRS)
        let capability_result = self
            .context
            .get_capability(CapabilityType::AssignedPcr, 0, 8);

        match capability_result {
            Ok((CapabilityData::AssignedPcr(pcr_selection_list), _)) => pcr_selection_list
                .get_selections()
                .iter()
                .map(tss_esapi::structures::PcrSelection::hashing_algorithm)
                .collect(),
            _ => {
                // Fallback: SHA256 is mandatory per TPM2 spec
                vec![HashingAlgorithm::Sha256]
            }
        }
    }

    /// Seal a random key with expected PCR values.
    /// Returns Tpm2SealedData containing everything needed for the credential.
    pub fn seal_with_expected_pcrs(
        &mut self,
        pcr_values: &[ExpectedPcrValue],
    ) -> Result<Tpm2SealedData> {
        // Get available banks and resolve which one to use
        let available_banks = self.get_available_pcr_banks();
        let pcr_bank = resolve_pcr_bank(pcr_values, &available_banks)?;

        eprintln!("Using PCR bank: {}", hash_alg_name(pcr_bank));

        // Generate random key to seal
        let mut sealed_secret = Zeroizing::new(vec![0u8; SEALED_KEY_SIZE]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sealed_secret);

        // Resolve any PCR values that need to be read from TPM
        let resolved_values = self.resolve_pcr_values(pcr_values, pcr_bank)?;

        // Calculate the policy digest from expected PCR values
        let policy_hash = Self::calculate_pcr_policy(&resolved_values, pcr_bank);

        // Create primary key (SRK)
        let primary = self.create_primary_key()?;
        let primary_handle = primary.key_handle;

        // Create sealed object (name_alg=SHA256 to match policy session)
        let create_result = self.create_sealed_object(
            primary_handle,
            &sealed_secret,
            &policy_hash,
            HashingAlgorithm::Sha256,
        )?;

        // Serialize the sealed blob
        let blob =
            Self::marshal_sealed_blob(&create_result.out_public, &create_result.out_private)?;

        // Calculate PCR mask
        let pcr_mask = resolved_values
            .iter()
            .fold(0u64, |mask, (idx, _)| mask | (1u64 << idx));

        Ok(Tpm2SealedData {
            blob,
            policy_hash,
            pcr_mask,
            pcr_bank: hash_alg_to_tpm2_alg(pcr_bank),
            primary_alg: TPM2_ALG_ECC,
            sealed_secret,
        })
    }

    /// Calculate policy hash only (for --print-policy)
    pub fn calculate_policy_only(
        &mut self,
        pcr_values: &[ExpectedPcrValue],
    ) -> Result<(Vec<u8>, HashingAlgorithm)> {
        let available_banks = self.get_available_pcr_banks();
        let pcr_bank = resolve_pcr_bank(pcr_values, &available_banks)?;
        let resolved_values = self.resolve_pcr_values(pcr_values, pcr_bank)?;
        let policy_hash = Self::calculate_pcr_policy(&resolved_values, pcr_bank);
        Ok((policy_hash, pcr_bank))
    }

    /// Resolve PCR values - read current values for any that weren't specified
    fn resolve_pcr_values(
        &mut self,
        pcr_values: &[ExpectedPcrValue],
        bank: HashingAlgorithm,
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut resolved = Vec::new();

        for pv in pcr_values {
            let value = match &pv.value {
                Some(v) => {
                    // Validate that the provided value has correct length for the bank
                    let expected_len = hash_alg_digest_size(bank);
                    if v.len() != expected_len {
                        return Err(anyhow!(
                            "PCR {} value has wrong length: got {} bytes, expected {} for {}",
                            pv.index,
                            v.len(),
                            expected_len,
                            hash_alg_name(bank)
                        ));
                    }
                    v.clone()
                }
                None => self.read_pcr(pv.index, bank)?,
            };
            resolved.push((pv.index, value));
        }

        // Sort by PCR index for deterministic ordering
        resolved.sort_by_key(|(idx, _)| *idx);

        Ok(resolved)
    }

    /// Read a single PCR value from the TPM
    pub fn read_pcr(&mut self, index: u32, hash_alg: HashingAlgorithm) -> Result<Vec<u8>> {
        let slot_value = 1u32 << index;
        let slot = PcrSlot::try_from(slot_value)
            .map_err(|_| anyhow!("Invalid PCR index: {index} (slot value {slot_value})"))?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &[slot])
            .build()
            .context("Failed to build PCR selection")?;

        let (_, _, digests) = self
            .context
            .pcr_read(selection)
            .context("Failed to read PCR")?;

        let digest_list: Vec<_> = digests.value().to_vec();
        if digest_list.is_empty() {
            return Err(anyhow!("No PCR value returned for index {index}"));
        }

        Ok(digest_list[0].value().to_vec())
    }

    /// Calculate PolicyPCR digest from expected values.
    /// This is the core function that allows binding to FUTURE PCR states.
    ///
    /// IMPORTANT: Both digestTPM and the policy digest use SHA256, regardless of PCR bank.
    /// The PCR bank only affects which PCR values are read and the TPML_PCR_SELECTION.
    ///
    /// Reference: systemd's tpm2_calculate_policy_pcr() in tpm2-util.c
    fn calculate_pcr_policy(pcr_values: &[(u32, Vec<u8>)], bank: HashingAlgorithm) -> Vec<u8> {
        // PolicyPCR: H(policyDigestOld || TPM_CC_PolicyPCR || pcrs || digestTPM)
        // where H is always SHA256 (systemd's session hash)

        // digestTPM = SHA256(concatenated PCR values)
        let mut pcr_hasher = Sha256::new();
        for (_, value) in pcr_values {
            pcr_hasher.update(value);
        }
        let pcr_digest = pcr_hasher.finalize();

        // pcrs = TPML_PCR_SELECTION
        let pcr_selection = Self::build_pcr_selection_bytes(pcr_values, bank);

        // Extend empty policy with PolicyPCR
        let mut policy_hasher = Sha256::new();
        policy_hasher.update([0u8; 32]); // policyDigestOld = zeros
        policy_hasher.update((CommandCode::PolicyPcr as u32).to_be_bytes());
        policy_hasher.update(&pcr_selection);
        policy_hasher.update(pcr_digest);
        policy_hasher.finalize().to_vec()
    }

    /// Build PCR selection bytes in TPM2 wire format
    fn build_pcr_selection_bytes(pcr_values: &[(u32, Vec<u8>)], bank: HashingAlgorithm) -> Vec<u8> {
        // TPML_PCR_SELECTION format:
        // - count (4 bytes, big-endian)
        // - array of TPMS_PCR_SELECTION:
        //   - hash (2 bytes, big-endian)
        //   - sizeofSelect (1 byte) = 3
        //   - pcrSelect (3 bytes for 24 PCRs)

        let mut buf = Vec::new();

        // Count = 1 (single hash algorithm)
        buf.extend_from_slice(&1u32.to_be_bytes());

        // Hash algorithm
        buf.extend_from_slice(&hash_alg_to_tpm2_alg(bank).to_be_bytes());

        // sizeofSelect = 3 (24 PCRs / 8 bits)
        buf.push(3u8);

        // Build PCR mask
        let mut pcr_mask = [0u8; 3];
        for (idx, _) in pcr_values {
            if *idx < 24 {
                pcr_mask[(*idx / 8) as usize] |= 1 << (*idx % 8);
            }
        }
        buf.extend_from_slice(&pcr_mask);

        buf
    }

    /// Create primary key (Storage Root Key)
    fn create_primary_key(&mut self) -> Result<CreatePrimaryKeyResult> {
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .context("Failed to start auth session")?
            .ok_or_else(|| anyhow!("Failed to get auth session"))?;

        self.context.set_sessions((Some(session), None, None));

        // ECC P-256 primary key template (matches systemd's default)
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .context("Failed to build object attributes")?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    tss_esapi::interface_types::ecc::EccCurve::NistP256,
                )
                .build()
                .context("Failed to build ECC parameters")?,
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .context("Failed to build public template")?;

        let result = self
            .context
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .context("Failed to create primary key")?;

        Ok(result)
    }

    /// Create a sealed object bound to the policy
    fn create_sealed_object(
        &mut self,
        parent: KeyHandle,
        secret: &[u8],
        policy_digest: &[u8],
        name_alg: HashingAlgorithm,
    ) -> Result<CreateKeyResult> {
        if secret.len() > TPM2_MAX_SEALED_DATA {
            return Err(anyhow!(
                "Secret too large: {} bytes (max {})",
                secret.len(),
                TPM2_MAX_SEALED_DATA
            ));
        }

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .build()
            .context("Failed to build sealed object attributes")?;

        let policy = TpmDigest::try_from(policy_digest.to_vec())
            .context("Failed to create policy digest")?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(name_alg)
            .with_object_attributes(object_attributes)
            .with_auth_policy(policy)
            .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
                tss_esapi::structures::KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(TpmDigest::default())
            .build()
            .context("Failed to build sealed object public")?;

        let data = SensitiveData::try_from(secret.to_vec())
            .context("Secret too large for SensitiveData")?;

        let result = self
            .context
            .create(parent, public, None, Some(data), None, None)
            .context("Failed to create sealed object")?;

        Ok(result)
    }

    /// Marshal sealed blob in systemd-compatible format
    fn marshal_sealed_blob(
        public: &Public,
        private: &tss_esapi::structures::Private,
    ) -> Result<Vec<u8>> {
        // systemd's tpm2_marshal_blob format (CRITICAL: order matters!):
        // 1. TPM2B_PRIVATE (2-byte size BE + data)
        // 2. TPM2B_PUBLIC (2-byte size BE + marshalled data)
        // 3. TPM2B_ENCRYPTED_SECRET (2-byte size BE, typically 0 for non-duplication)
        //
        // See: https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c
        // tpm2_marshal_blob() marshals PRIVATE first, then PUBLIC, then SEED

        let mut blob = Vec::new();

        // 1. Marshal PRIVATE first (TPM2B_PRIVATE: size BE + raw buffer)
        let private_value = private.value();
        let private_len: u16 = private_value
            .len()
            .try_into()
            .map_err(|_| anyhow!("TPM2B_PRIVATE too large: {} bytes", private_value.len()))?;
        blob.extend_from_slice(&private_len.to_be_bytes());
        blob.extend_from_slice(private_value);

        // 2. Marshal PUBLIC second (TPM2B_PUBLIC: size BE + marshalled TPMT_PUBLIC)
        let public_bytes = public.marshall().context("Failed to marshal public")?;
        let public_len: u16 = public_bytes
            .len()
            .try_into()
            .map_err(|_| anyhow!("TPM2B_PUBLIC too large: {} bytes", public_bytes.len()))?;
        blob.extend_from_slice(&public_len.to_be_bytes());
        blob.extend_from_slice(&public_bytes);

        // 3. Empty encrypted secret (for non-duplication case)
        blob.extend_from_slice(&0u16.to_be_bytes());

        Ok(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // ExpectedPcrValue::parse tests
    // =========================================================================

    #[test]
    fn test_parse_pcr_index_only() {
        let pv = ExpectedPcrValue::parse("7").unwrap();
        assert_eq!(pv.index, 7);
        assert!(pv.hash_alg.is_none());
        assert!(pv.value.is_none());
    }

    #[test]
    fn test_parse_pcr_with_algorithm() {
        let pv = ExpectedPcrValue::parse("7:sha256").unwrap();
        assert_eq!(pv.index, 7);
        assert_eq!(pv.hash_alg, Some(HashingAlgorithm::Sha256));
        assert!(pv.value.is_none());
    }

    #[test]
    fn test_parse_pcr_with_value() {
        let pv = ExpectedPcrValue::parse("7=abcd1234").unwrap();
        assert_eq!(pv.index, 7);
        assert!(pv.hash_alg.is_none());
        assert_eq!(pv.value, Some(vec![0xab, 0xcd, 0x12, 0x34]));
    }

    #[test]
    fn test_parse_pcr_with_algorithm_and_value() {
        let pv = ExpectedPcrValue::parse("7:sha256=abcd").unwrap();
        assert_eq!(pv.index, 7);
        assert_eq!(pv.hash_alg, Some(HashingAlgorithm::Sha256));
        assert_eq!(pv.value, Some(vec![0xab, 0xcd]));
    }

    #[test]
    fn test_parse_pcr_all_algorithms() {
        assert_eq!(
            ExpectedPcrValue::parse("0:sha1").unwrap().hash_alg,
            Some(HashingAlgorithm::Sha1)
        );
        assert_eq!(
            ExpectedPcrValue::parse("0:sha256").unwrap().hash_alg,
            Some(HashingAlgorithm::Sha256)
        );
        assert_eq!(
            ExpectedPcrValue::parse("0:sha384").unwrap().hash_alg,
            Some(HashingAlgorithm::Sha384)
        );
        assert_eq!(
            ExpectedPcrValue::parse("0:sha512").unwrap().hash_alg,
            Some(HashingAlgorithm::Sha512)
        );
    }

    #[test]
    fn test_parse_pcr_whitespace() {
        let pv = ExpectedPcrValue::parse("  7  ").unwrap();
        assert_eq!(pv.index, 7);
    }

    #[test]
    fn test_parse_pcr_invalid_index() {
        assert!(ExpectedPcrValue::parse("24").is_err()); // Max is 23
        assert!(ExpectedPcrValue::parse("abc").is_err());
        assert!(ExpectedPcrValue::parse("-1").is_err());
    }

    #[test]
    fn test_parse_pcr_invalid_hex() {
        assert!(ExpectedPcrValue::parse("7=notahex").is_err());
        assert!(ExpectedPcrValue::parse("7:sha256=xyz").is_err());
    }

    #[test]
    fn test_parse_pcr_invalid_algorithm() {
        assert!(ExpectedPcrValue::parse("7:md5").is_err());
        assert!(ExpectedPcrValue::parse("7:sha3").is_err());
    }

    // =========================================================================
    // parse_pcr_index tests (well-known names)
    // =========================================================================

    #[test]
    fn test_parse_pcr_index_names() {
        assert_eq!(parse_pcr_index("platform-code").unwrap(), 0);
        assert_eq!(parse_pcr_index("platform-config").unwrap(), 1);
        assert_eq!(parse_pcr_index("secure-boot-policy").unwrap(), 7);
        assert_eq!(parse_pcr_index("kernel-initrd").unwrap(), 9);
        assert_eq!(parse_pcr_index("ima").unwrap(), 10);
        assert_eq!(parse_pcr_index("system-identity").unwrap(), 15);
        assert_eq!(parse_pcr_index("debug").unwrap(), 16);
        assert_eq!(parse_pcr_index("application-support").unwrap(), 23);
    }

    #[test]
    fn test_parse_pcr_index_case_insensitive() {
        assert_eq!(parse_pcr_index("SYSTEM-IDENTITY").unwrap(), 15);
        assert_eq!(parse_pcr_index("System-Identity").unwrap(), 15);
    }

    #[test]
    fn test_parse_pcr_index_numeric_bounds() {
        assert_eq!(parse_pcr_index("0").unwrap(), 0);
        assert_eq!(parse_pcr_index("23").unwrap(), 23);
        assert!(parse_pcr_index("24").is_err());
    }

    // =========================================================================
    // resolve_pcr_bank tests
    // =========================================================================

    #[test]
    fn test_resolve_pcr_bank_explicit() {
        let pcrs = vec![ExpectedPcrValue {
            index: 7,
            hash_alg: Some(HashingAlgorithm::Sha384),
            value: None,
        }];
        let available = vec![HashingAlgorithm::Sha256, HashingAlgorithm::Sha384];
        assert_eq!(
            resolve_pcr_bank(&pcrs, &available).unwrap(),
            HashingAlgorithm::Sha384
        );
    }

    #[test]
    fn test_resolve_pcr_bank_auto_prefers_sha256() {
        let pcrs = vec![ExpectedPcrValue {
            index: 7,
            hash_alg: None,
            value: None,
        }];
        let available = vec![
            HashingAlgorithm::Sha1,
            HashingAlgorithm::Sha256,
            HashingAlgorithm::Sha384,
        ];
        assert_eq!(
            resolve_pcr_bank(&pcrs, &available).unwrap(),
            HashingAlgorithm::Sha256
        );
    }

    #[test]
    fn test_resolve_pcr_bank_mixed_error() {
        let pcrs = vec![
            ExpectedPcrValue {
                index: 7,
                hash_alg: Some(HashingAlgorithm::Sha256),
                value: None,
            },
            ExpectedPcrValue {
                index: 15,
                hash_alg: Some(HashingAlgorithm::Sha384),
                value: None,
            },
        ];
        let available = vec![HashingAlgorithm::Sha256, HashingAlgorithm::Sha384];
        assert!(resolve_pcr_bank(&pcrs, &available).is_err());
    }

    #[test]
    fn test_resolve_pcr_bank_unavailable_error() {
        let pcrs = vec![ExpectedPcrValue {
            index: 7,
            hash_alg: Some(HashingAlgorithm::Sha512),
            value: None,
        }];
        let available = vec![HashingAlgorithm::Sha256];
        assert!(resolve_pcr_bank(&pcrs, &available).is_err());
    }

    #[test]
    fn test_resolve_pcr_bank_first_explicit_wins() {
        // First PCR specifies SHA384, second doesn't specify - should use SHA384
        let pcrs = vec![
            ExpectedPcrValue {
                index: 7,
                hash_alg: Some(HashingAlgorithm::Sha384),
                value: None,
            },
            ExpectedPcrValue {
                index: 15,
                hash_alg: None,
                value: None,
            },
        ];
        let available = vec![HashingAlgorithm::Sha256, HashingAlgorithm::Sha384];
        assert_eq!(
            resolve_pcr_bank(&pcrs, &available).unwrap(),
            HashingAlgorithm::Sha384
        );
    }

    // =========================================================================
    // Helper function tests
    // =========================================================================

    #[test]
    fn test_hash_alg_name() {
        assert_eq!(hash_alg_name(HashingAlgorithm::Sha1), "SHA1");
        assert_eq!(hash_alg_name(HashingAlgorithm::Sha256), "SHA256");
        assert_eq!(hash_alg_name(HashingAlgorithm::Sha384), "SHA384");
        assert_eq!(hash_alg_name(HashingAlgorithm::Sha512), "SHA512");
    }

    #[test]
    fn test_hash_alg_digest_size() {
        assert_eq!(hash_alg_digest_size(HashingAlgorithm::Sha1), 20);
        assert_eq!(hash_alg_digest_size(HashingAlgorithm::Sha256), 32);
        assert_eq!(hash_alg_digest_size(HashingAlgorithm::Sha384), 48);
        assert_eq!(hash_alg_digest_size(HashingAlgorithm::Sha512), 64);
    }

    #[test]
    fn test_hash_alg_to_tpm2_alg() {
        assert_eq!(hash_alg_to_tpm2_alg(HashingAlgorithm::Sha1), TPM2_ALG_SHA1);
        assert_eq!(
            hash_alg_to_tpm2_alg(HashingAlgorithm::Sha256),
            TPM2_ALG_SHA256
        );
        assert_eq!(
            hash_alg_to_tpm2_alg(HashingAlgorithm::Sha384),
            TPM2_ALG_SHA384
        );
        assert_eq!(
            hash_alg_to_tpm2_alg(HashingAlgorithm::Sha512),
            TPM2_ALG_SHA512
        );
    }
}
