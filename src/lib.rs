use wasm_bindgen::prelude::*;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use getrandom::getrandom;

// Cryptographic Constants
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ITERATIONS: u32 = 100_000; // Hardened standard for PBKDF2

#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], password: &[u8]) -> Result<Vec<u8>, JsValue> {
    // 1. Generate 16 bytes of true randomness for the Salt
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;

    // 2. Hash the user's password 100,000 times to create a strict 32-byte key
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, &salt, ITERATIONS, &mut key);

    // 3. Generate a 12-byte random Nonce (Initialization Vector)
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4. Encrypt the payload using AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("Engine Error"))?;
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    // 5. Package the final payload: [Salt (16)] + [Nonce (12)] + [Ciphertext]
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_bytes(encrypted_data: &[u8], password: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Ensure the payload is at least large enough to hold our Salt and Nonce
    if encrypted_data.len() < SALT_LEN + NONCE_LEN {
        return Err(JsValue::from_str("Payload corrupted: too short."));
    }

    // 1. Unpack the Salt, Nonce, and Ciphertext from the raw bytes
    let salt = &encrypted_data[0..SALT_LEN];
    let nonce_bytes = &encrypted_data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted_data[SALT_LEN + NONCE_LEN..];

    // 2. Re-derive the exact 32-byte master key using the extracted Salt
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut key);

    // 3. Initialize the decryption engine
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("Engine Error"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // 4. Decrypt and verify authenticity
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| JsValue::from_str("ACCESS DENIED: Incorrect password or corrupted payload."))?;

    Ok(plaintext)
}