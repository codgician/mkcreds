//! systemd-creds compatible credential format builder.
//!
//! File format (from systemd source):
//! 1. encrypted_credential_header (unencrypted)
//! 2. tpm2_credential_header (unencrypted, if TPM2)
//! 3. AES-256-GCM encrypted:
//!    - metadata_credential_header
//!    - actual secret data
//! 4. AES-256-GCM tag
//!
//! Key derivation:
//! - TPM seals a random HMAC key
//! - AES key = SHA256(tpm2_key)
//! - This is what systemd calls "sha256_hash_host_and_tpm2_key" (with host_key empty)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// systemd credential type IDs
const CRED_AES256_GCM_BY_TPM2_HMAC: [u8; 16] = [
    0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91,
    0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20, 0xfe,
];

/// Maximum credential size (1MB)
const CREDENTIAL_SIZE_MAX: usize = 1024 * 1024;

/// AES-256-GCM parameters
const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 12;  // GCM standard nonce size (systemd stores 16 but uses 12)
const AES_TAG_SIZE: usize = 16;
const AES_BLOCK_SIZE: usize = 1;  // AES-GCM is stream mode, block size = 1 (NOT 16!)

/// Sealed TPM2 data for credential
pub struct Tpm2SealedData {
    /// Marshalled TPM2 blob (public + private)
    pub blob: Vec<u8>,
    /// Policy hash used for sealing
    pub policy_hash: Vec<u8>,
    /// PCR mask (which PCRs are bound)
    pub pcr_mask: u64,
    /// Primary key algorithm (ECC = 0x0023, RSA = 0x0001)
    pub primary_alg: u16,
    /// The actual sealed secret (random HMAC key)
    pub sealed_secret: Zeroizing<Vec<u8>>,
}

/// Builder for systemd-creds compatible credentials
pub struct CredentialBuilder {
    name: Option<String>,
    timestamp: u64,
    not_after: u64,
}

impl CredentialBuilder {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(u64::MAX);

        Self {
            name: None,
            timestamp: now,
            not_after: u64::MAX, // Never expires
        }
    }

    /// Set the credential name (embedded in encrypted payload)
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set expiration timestamp (microseconds since epoch)
    pub fn not_after(mut self, not_after: u64) -> Self {
        self.not_after = not_after;
        self
    }

    /// Build the credential, encrypting the secret with TPM2-sealed key
    pub fn build(self, secret: &[u8], tpm2: &Tpm2SealedData) -> Result<Vec<u8>> {
        // Derive AES key from TPM2 sealed secret
        // systemd: sha256_hash_host_and_tpm2_key(NULL, tpm2_key)
        let aes_key = {
            let mut hasher = Sha256::new();
            hasher.update(&*tpm2.sealed_secret);
            Zeroizing::new(hasher.finalize().to_vec())
        };

        // Generate random IV
        let mut iv = [0u8; AES_IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);

        // Build headers
        let (main_header, tpm2_header) = self.build_headers(&iv, tpm2)?;

        // Build plaintext: metadata header + secret
        let mut plaintext = self.build_metadata_header()?;
        plaintext.extend_from_slice(secret);

        // AAD covers both headers
        let mut aad = Vec::new();
        aad.extend_from_slice(&main_header);
        aad.extend_from_slice(&tpm2_header);

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // GCM standard uses 12-byte nonce, but systemd stores 16 bytes
        // and uses first 12 for the actual nonce
        let nonce = Nonce::from_slice(&iv[..12]);

        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: &aad,
            })
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Build final output
        let mut output = Vec::new();
        output.extend_from_slice(&main_header);
        output.extend_from_slice(&tpm2_header);
        output.extend_from_slice(&ciphertext);

        if output.len() > CREDENTIAL_SIZE_MAX {
            return Err(anyhow!(
                "Credential too large: {} bytes (max {})",
                output.len(),
                CREDENTIAL_SIZE_MAX
            ));
        }

        Ok(output)
    }

    /// Build the main credential header
    fn build_headers(&self, iv: &[u8], tpm2: &Tpm2SealedData) -> Result<(Vec<u8>, Vec<u8>)> {
        // Main header (encrypted_credential_header)
        let mut main = Vec::new();
        main.extend_from_slice(&CRED_AES256_GCM_BY_TPM2_HMAC);
        main.write_u32::<LittleEndian>(AES_KEY_SIZE as u32)?;
        main.write_u32::<LittleEndian>(AES_BLOCK_SIZE as u32)?;
        main.write_u32::<LittleEndian>(AES_IV_SIZE as u32)?;
        main.write_u32::<LittleEndian>(AES_TAG_SIZE as u32)?;
        main.extend_from_slice(iv);
        // Pad to 8-byte boundary
        while main.len() % 8 != 0 {
            main.push(0);
        }

        // TPM2 header (tpm2_credential_header)
        // CRITICAL: blob comes FIRST, then policy_hash
        // See: https://github.com/systemd/systemd/blob/main/src/shared/creds-util.c
        // struct tpm2_credential_header { ... uint8_t policy_hash_and_blob[]; }
        // The policy_hash_and_blob array contains: blob[blob_size] then policy_hash[policy_hash_size]
        let mut tpm2_hdr = Vec::new();
        tpm2_hdr.write_u64::<LittleEndian>(tpm2.pcr_mask)?;
        tpm2_hdr.write_u16::<LittleEndian>(0x000B)?; // SHA256
        tpm2_hdr.write_u16::<LittleEndian>(tpm2.primary_alg)?;
        tpm2_hdr.write_u32::<LittleEndian>(tpm2.blob.len() as u32)?;
        tpm2_hdr.write_u32::<LittleEndian>(tpm2.policy_hash.len() as u32)?;
        tpm2_hdr.extend_from_slice(&tpm2.blob);        // BLOB FIRST
        tpm2_hdr.extend_from_slice(&tpm2.policy_hash); // POLICY_HASH SECOND
        // Pad to 8-byte boundary
        while tpm2_hdr.len() % 8 != 0 {
            tpm2_hdr.push(0);
        }

        Ok((main, tpm2_hdr))
    }

    /// Build the metadata header (will be encrypted)
    fn build_metadata_header(&self) -> Result<Vec<u8>> {
        let name = self.name.as_deref().unwrap_or("");
        let name_bytes = name.as_bytes();

        let mut header = Vec::new();
        header.write_u64::<LittleEndian>(self.timestamp)?;
        header.write_u64::<LittleEndian>(self.not_after)?;
        header.write_u32::<LittleEndian>(name_bytes.len() as u32)?;
        header.extend_from_slice(name_bytes);
        header.push(0); // NUL terminator
        // Pad to 8-byte boundary
        while header.len() % 8 != 0 {
            header.push(0);
        }

        Ok(header)
    }
}

impl Default for CredentialBuilder {
    fn default() -> Self {
        Self::new()
    }
}
