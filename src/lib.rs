use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use aes_gcm::aead::rand_core::RngCore;
use wasm_bindgen::prelude::*;

/// Encrypts raw bytes (files, text, images) in-memory using AES-256-GCM.
/// Zero server uploads — runs entirely inside the user's browser CPU via WebAssembly.
#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Encryption key must be exactly 32 bytes (256 bits)."));
    }

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a secure 12-byte random nonce (initialization vector)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the payload
    match cipher.encrypt(nonce, data) {
        Ok(mut ciphertext) => {
            // Prepend the 12-byte nonce to the encrypted data so we can decrypt it later
            let mut result = nonce_bytes.to_vec();
            result.append(&mut ciphertext);
            Ok(result)
        }
        Err(_) => Err(JsValue::from_str("Encryption failed.")),
    }
}

/// Decrypts AES-256-GCM encrypted bytes in-memory.
#[wasm_bindgen]
pub fn decrypt_bytes(encrypted_data: &[u8], key_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Decryption key must be exactly 32 bytes (256 bits)."));
    }

    if encrypted_data.len() < 12 {
        return Err(JsValue::from_str("Invalid payload: Data too short."));
    }

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Extract the 12-byte nonce from the front of the data
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(JsValue::from_str("Decryption failed: Incorrect password or corrupted payload.")),
    }
}
