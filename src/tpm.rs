//! TPM2 operations: policy calculation and sealing with expected PCR values.

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use tss_esapi::{
    Context as TpmContext,
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        CreateKeyResult, CreatePrimaryKeyResult, Digest as TpmDigest, EccPoint,
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
    pub hash_alg: HashingAlgorithm,
    pub value: Option<Vec<u8>>, // None = read current value from TPM
}

impl ExpectedPcrValue {
    /// Parse a PCR specification string.
    /// Formats:
    ///   "7"                    - PCR 7, read current value
    ///   "7:sha256=abcd..."     - PCR 7, expected SHA256 value
    pub fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.splitn(2, ':').collect();

        let index: u32 = parts[0]
            .parse()
            .with_context(|| format!("Invalid PCR index: {}", parts[0]))?;

        if index > 23 {
            return Err(anyhow!("PCR index must be 0-23, got {index}"));
        }

        if parts.len() == 1 {
            // No value specified, read from TPM
            return Ok(Self {
                index,
                hash_alg: HashingAlgorithm::Sha256,
                value: None,
            });
        }

        // Parse "alg=value"
        let alg_value: Vec<&str> = parts[1].splitn(2, '=').collect();
        if alg_value.len() != 2 {
            return Err(anyhow!("Invalid PCR spec format: {spec}"));
        }

        let hash_alg = match alg_value[0].to_lowercase().as_str() {
            "sha256" => HashingAlgorithm::Sha256,
            "sha1" => HashingAlgorithm::Sha1,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            other => return Err(anyhow!("Unsupported hash algorithm: {other}")),
        };

        let value = hex::decode(alg_value[1])
            .with_context(|| format!("Invalid hex value: {}", alg_value[1]))?;

        Ok(Self {
            index,
            hash_alg,
            value: Some(value),
        })
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

    /// Seal a random key with expected PCR values.
    /// Returns Tpm2SealedData containing everything needed for the credential.
    pub fn seal_with_expected_pcrs(
        &mut self,
        pcr_values: &[ExpectedPcrValue],
    ) -> Result<Tpm2SealedData> {
        // Generate random key to seal
        let mut sealed_secret = Zeroizing::new(vec![0u8; SEALED_KEY_SIZE]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sealed_secret);

        // Resolve any PCR values that need to be read from TPM
        let resolved_values = self.resolve_pcr_values(pcr_values)?;

        // Calculate the policy digest from expected PCR values
        let policy_hash = Self::calculate_pcr_policy(&resolved_values);

        // Create primary key (SRK)
        let primary = self.create_primary_key()?;
        let primary_handle = primary.key_handle;

        // Create sealed object with policy
        let create_result =
            self.create_sealed_object(primary_handle, &sealed_secret, &policy_hash)?;

        // Serialize the sealed blob
        let blob =
            Self::marshal_sealed_blob(&create_result.out_public, &create_result.out_private)?;

        // Calculate PCR mask
        let pcr_mask = resolved_values
            .iter()
            .fold(0u64, |mask, (idx, _)| mask | (1 << idx));

        Ok(Tpm2SealedData {
            blob,
            policy_hash,
            pcr_mask,
            primary_alg: 0x0023, // TPM2_ALG_ECC
            sealed_secret,
        })
    }

    /// Resolve PCR values - read current values for any that weren't specified
    fn resolve_pcr_values(
        &mut self,
        pcr_values: &[ExpectedPcrValue],
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut resolved = Vec::new();

        for pv in pcr_values {
            let value = match &pv.value {
                Some(v) => v.clone(),
                None => self.read_pcr_value(pv.index, pv.hash_alg)?,
            };
            resolved.push((pv.index, value));
        }

        // Sort by PCR index for deterministic ordering
        resolved.sort_by_key(|(idx, _)| *idx);

        Ok(resolved)
    }

    /// Read a single PCR value from the TPM
    fn read_pcr_value(&mut self, index: u32, hash_alg: HashingAlgorithm) -> Result<Vec<u8>> {
        // PcrSlot uses bit flags, so index 7 -> 1 << 7 = 0x80
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
    fn calculate_pcr_policy(pcr_values: &[(u32, Vec<u8>)]) -> Vec<u8> {
        // PolicyPCR calculation (from TPM2 spec Part 3):
        // policyDigestNew = H(policyDigestOld || TPM_CC_PolicyPCR || pcrs || digestTPM)
        // where:
        //   - policyDigestOld starts as all zeros
        //   - TPM_CC_PolicyPCR = 0x0000017F
        //   - pcrs = TPML_PCR_SELECTION
        //   - digestTPM = H(concatenated PCR values)

        // Start with empty policy (all zeros for SHA256)
        let mut policy = [0u8; 32];

        // Compute PCR composite digest
        let mut pcr_hasher = Sha256::new();
        for (_, value) in pcr_values {
            pcr_hasher.update(value);
        }
        let pcr_digest = pcr_hasher.finalize();

        // Build PCR selection structure
        let pcr_selection = Self::build_pcr_selection_bytes(pcr_values);

        // Extend policy: H(policy || TPM_CC_PolicyPCR || pcr_selection || pcr_digest)
        let mut policy_hasher = Sha256::new();
        policy_hasher.update(policy);
        policy_hasher.update(0x0000_017F_u32.to_be_bytes());
        policy_hasher.update(&pcr_selection);
        policy_hasher.update(pcr_digest);
        policy = policy_hasher.finalize().into();

        policy.to_vec()
    }

    /// Build PCR selection bytes in TPM2 wire format
    fn build_pcr_selection_bytes(pcr_values: &[(u32, Vec<u8>)]) -> Vec<u8> {
        // TPML_PCR_SELECTION format:
        // - count (4 bytes, big-endian)
        // - array of TPMS_PCR_SELECTION:
        //   - hash (2 bytes, big-endian) = 0x000B (SHA256)
        //   - sizeofSelect (1 byte) = 3
        //   - pcrSelect (3 bytes for 24 PCRs)

        let mut buf = Vec::new();

        // Count = 1 (single hash algorithm)
        buf.extend_from_slice(&1u32.to_be_bytes());

        // Hash algorithm = SHA256 (0x000B)
        buf.extend_from_slice(&0x000Bu16.to_be_bytes());

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
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
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
        blob.extend_from_slice(&(private_value.len() as u16).to_be_bytes());
        blob.extend_from_slice(private_value);

        // 2. Marshal PUBLIC second (TPM2B_PUBLIC: size BE + marshalled TPMT_PUBLIC)
        let public_bytes = public.marshall().context("Failed to marshal public")?;
        blob.extend_from_slice(&(public_bytes.len() as u16).to_be_bytes());
        blob.extend_from_slice(&public_bytes);

        // 3. Empty encrypted secret (for non-duplication case)
        blob.extend_from_slice(&0u16.to_be_bytes());

        Ok(blob)
    }
}
