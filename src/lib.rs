use wasm_bindgen::prelude::*;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, ParamsBuilder};
use getrandom::getrandom;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let mut key = [0u8; KEY_LEN];

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
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}

#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt).map_err(|e| JsValue::from_str(&format!("Salt RNG failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&format!("Nonce RNG failed: {}", e)))?;

    // Derive key and zeroize key buffer immediately after cipher instantiation
    let mut key = derive_key_argon2id(passphrase, &salt).map_err(|e| JsValue::from_str(&e))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {}", e)));
    
    key.zeroize(); // Overwrite WASM key memory with zeroes
    let cipher = cipher?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
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

    // Derive key and zeroize key buffer immediately after cipher instantiation
    let mut key = derive_key_argon2id(passphrase, salt).map_err(|e| JsValue::from_str(&e))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| JsValue::from_str(&format!("Cipher init failed: {}", e)));

    key.zeroize(); // Overwrite WASM key memory with zeroes
    let cipher = cipher?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| JsValue::from_str("ACCESS DENIED: Invalid passphrase or corrupted payload"))?;

    Ok(plaintext)
}