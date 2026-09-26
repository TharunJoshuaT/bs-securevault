use wasm_bindgen::prelude::*;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, ParamsBuilder};
use getrandom::getrandom;
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const BUCKET_SIZE: usize = 256; // Fixed 256-byte bucket boundary

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    let params = ParamsBuilder::new()
        .m_cost(19456)
        .t_cost(2)
        .p_cost(1)
        .output_len(KEY_LEN)
        .build()
        .map_err(|e| format!("Argon2 params invalid: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    argon2
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}

#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt).map_err(|e| JsValue::from_str(&format!("Salt RNG failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&format!("Nonce RNG failed: {}", e)))?;

    // 1. Pad data to nearest bucket boundary before encryption
    let padded_data = pad_bytes(data, BUCKET_SIZE);

    // 2. Derive key wrapped in Zeroizing container
    let key = derive_key_argon2id(passphrase, &salt).map_err(|e| JsValue::from_str(&e))?;
    
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {}", e)))?;

    // 3. Explicitly drop key to zeroize key memory immediately
    drop(key);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded_data.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    let mut payload = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(payload)
}

#[wasm_bindgen]
pub fn decrypt_bytes(payload: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    if payload.len() < SALT_LEN + NONCE_LEN {
        return Err(JsValue::from_str("Invalid payload: truncated header"));
    }

    let salt = &payload[..SALT_LEN];
    let nonce_bytes = &payload[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &payload[SALT_LEN + NONCE_LEN..];

    let key = derive_key_argon2id(passphrase, salt).map_err(|e| JsValue::from_str(&e))?;
    
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {}", e)))?;

    // Explicitly drop key to zeroize key memory immediately
    drop(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    
    // 1. Decrypt raw bytes using AES-256-GCM
    let decrypted_padded = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| JsValue::from_str("ACCESS DENIED: Invalid passphrase or corrupted payload"))?;

    // 2. Remove CSPRNG padding to recover true original payload
    let plaintext = unpad_bytes(&decrypted_padded)
        .map_err(|e| JsValue::from_str(&format!("Unpadding failed: {}", e)))?;

    Ok(plaintext)
}

// ==========================================
// CIPHERTEXT PADDING / BUCKETING (v0.1.1)
// ==========================================

/// Pads plaintext to the nearest target bucket size using CSPRNG random noise.
/// Prepends a 4-byte Big-Endian header indicating original byte length.
pub fn pad_bytes(plaintext: &[u8], target_bucket_size: usize) -> Vec<u8> {
    let current_len = plaintext.len();
    
    // Calculate padding needed to hit the next bucket boundary
    let remainder = current_len % target_bucket_size;
    let pad_len = if remainder == 0 {
        target_bucket_size // Always add at least one full bucket frame for ambiguity
    } else {
        target_bucket_size - remainder
    };

    let total_len = current_len + pad_len;
    let mut padded = Vec::with_capacity(total_len + 4);

    // 1. Store original 32-bit length header (4 bytes, Big Endian)
    padded.extend_from_slice(&(current_len as u32).to_be_bytes());
    
    // 2. Append actual plaintext
    padded.extend_from_slice(plaintext);
    
    // 3. Fill remaining space with CSPRNG noise
    let mut rng_bytes = vec![0u8; pad_len];
    getrandom(&mut rng_bytes).expect("Failed to generate CSPRNG noise for padding");
    padded.extend_from_slice(&rng_bytes);

    padded
}

/// Strip CSPRNG padding and extract original payload based on the 4-byte header.
pub fn unpad_bytes(decrypted_padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if decrypted_padded.len() < 4 {
        return Err("Invalid payload length: missing header");
    }

    // Read original length from the first 4 bytes
    let orig_len = u32::from_be_bytes([
        decrypted_padded[0],
        decrypted_padded[1],
        decrypted_padded[2],
        decrypted_padded[3],
    ]) as usize;

    let payload_start = 4;
    let payload_end = payload_start + orig_len;

    if payload_end > decrypted_padded.len() {
        return Err("Payload bounds overflow: corrupted padding header");
    }

    // Return only the true original bytes
    Ok(decrypted_padded[payload_start..payload_end].to_vec())
}
