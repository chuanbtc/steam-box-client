use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Derive a 256-bit AES key from the machine ID string using SHA-256.
fn derive_key(machine_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt plaintext using AES-256-GCM with a key derived from the machine ID.
/// Output format: 12-byte nonce || ciphertext+tag
pub fn encrypt(plaintext: &[u8], machine_id: &str) -> Result<Vec<u8>, CryptoError> {
    let key_bytes = derive_key(machine_id);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend the 12-byte nonce to the ciphertext
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data that was encrypted with `encrypt()`.
/// Input format: 12-byte nonce || ciphertext+tag
pub fn decrypt(data: &[u8], machine_id: &str) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 + 16 {
        // 12 nonce + 16 tag minimum
        return Err(CryptoError::InvalidData(
            "Data too short to contain nonce and tag".to_string(),
        ));
    }

    let key_bytes = derive_key(machine_id);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let machine_id = "test-machine-id-12345";
        let plaintext = b"Hello, Steam Box! This is a session token.";

        let encrypted = encrypt(plaintext, machine_id).expect("Encryption should succeed");
        assert_ne!(&encrypted[..], &plaintext[..]);

        let decrypted = decrypt(&encrypted, machine_id).expect("Decryption should succeed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_rejection() {
        let machine_id_1 = "machine-a";
        let machine_id_2 = "machine-b";
        let plaintext = b"secret data";

        let encrypted = encrypt(plaintext, machine_id_1).expect("Encryption should succeed");
        let result = decrypt(&encrypted, machine_id_2);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_too_short_data() {
        let result = decrypt(&[0u8; 10], "machine");
        assert!(result.is_err());
    }
}
