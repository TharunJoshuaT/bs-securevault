use aes_gcm::{
    aead::{
        stream::{DecryptorBE32, EncryptorBE32},
        KeyInit, Payload,
    },
    Aes256Gcm, Key,
};
use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::getrandom;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub const HEADER_LEN: usize = 46;
pub const MAGIC: &[u8; 4] = b"BSV\x02";
pub const FORMAT_VERSION: u8 = 0x02;
pub const KDF_ARGON2ID: u8 = 0x01;

const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 7;
const KEY_LEN: usize = 32;
const BUCKET_SIZE: usize = 256;
const GCM_TAG_LEN: usize = 16;

// Default Argon2id parameters (19 MiB, t=2, p=1) & default STREAM chunk size (64 KiB)
const DEFAULT_M_COST_KIB: u32 = 19_456;
const DEFAULT_T_COST: u32 = 2;
const DEFAULT_P_COST: u32 = 1;
const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

// Hard safety caps against crafted/malicious headers
pub const MAX_M_COST_KIB: u32 = 262_144; // 256 MiB
pub const MAX_T_COST: u32 = 10;
pub const MAX_P_COST: u32 = 4;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, Copy)]
pub struct VaultHeader {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub chunk_size: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl VaultHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4] = FORMAT_VERSION;
        buf[5] = KDF_ARGON2ID;
        buf[6..10].copy_from_slice(&self.m_cost_kib.to_be_bytes());
        buf[10..14].copy_from_slice(&self.t_cost.to_be_bytes());
        buf[14..18].copy_from_slice(&self.p_cost.to_be_bytes());
        buf[18..22].copy_from_slice(&self.chunk_size.to_be_bytes());
        buf[22..38].copy_from_slice(&self.salt);
        buf[38..45].copy_from_slice(&self.nonce_prefix);
        buf[45] = 0x00;
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < HEADER_LEN {
            return Err("Invalid payload: truncated header");
        }
        if &buf[0..4] != MAGIC || buf[4] != FORMAT_VERSION {
            return Err("Invalid magic bytes or unsupported format version");
        }
        if buf[5] != KDF_ARGON2ID {
            return Err("Unsupported KDF identifier");
        }

        let m_cost_kib = u32::from_be_bytes(buf[6..10].try_into().unwrap());
        let t_cost = u32::from_be_bytes(buf[10..14].try_into().unwrap());
        let p_cost = u32::from_be_bytes(buf[14..18].try_into().unwrap());
        let chunk_size = u32::from_be_bytes(buf[18..22].try_into().unwrap());

        if m_cost_kib == 0 || m_cost_kib > MAX_M_COST_KIB {
            return Err("Header m_cost exceeds safety limit");
        }
        if t_cost == 0 || t_cost > MAX_T_COST {
            return Err("Header t_cost exceeds safety limit");
        }
        if p_cost == 0 || p_cost > MAX_P_COST {
            return Err("Header p_cost exceeds safety limit");
        }
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err("Header chunk_size exceeds safety limit");
        }
        if buf[45] != 0x00 {
            return Err("Invalid reserved byte in header");
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[22..38]);

        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&buf[38..45]);

        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
            chunk_size,
            salt,
            nonce_prefix,
        })
    }
}

fn derive_key_argon2id(
    passphrase: &[u8],
    header: &VaultHeader,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    let params = Params::new(
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| format!("Argon2 params invalid: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, &header.salt, key.as_mut_slice())
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}

#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt)
        .map_err(|e| JsValue::from_str(&format!("Salt RNG failed: {}", e)))?;

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom(&mut nonce_prefix)
        .map_err(|e| JsValue::from_str(&format!("Nonce prefix RNG failed: {}", e)))?;

    let header = VaultHeader {
        m_cost_kib: DEFAULT_M_COST_KIB,
        t_cost: DEFAULT_T_COST,
        p_cost: DEFAULT_P_COST,
        chunk_size: DEFAULT_CHUNK_SIZE,
        salt,
        nonce_prefix,
    };
    let header_bytes = header.to_bytes();

    // 1. Pad data to bucket boundary before encryption
    let padded_data = pad_bytes(data, BUCKET_SIZE);

    // 2. Derive key ONCE per payload inside Zeroizing container
    let key = derive_key_argon2id(passphrase, &header).map_err(|e| JsValue::from_str(&e))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    drop(key);

    // 3. Initialize STREAM encryptor with 7-byte nonce prefix
    let mut encryptor = Some(EncryptorBE32::from_aead(cipher, &header.nonce_prefix.into()));

    let chunk_size = header.chunk_size as usize;
    let chunks: Vec<&[u8]> = if padded_data.is_empty() {
        vec![&[]]
    } else {
        padded_data.chunks(chunk_size).collect()
    };

    let mut output = Vec::with_capacity(
        HEADER_LEN + padded_data.len() + (chunks.len() * (GCM_TAG_LEN + 8)),
    );
    output.extend_from_slice(&header_bytes);

for (idx, chunk) in chunks.iter().enumerate() {
    let is_last = idx == chunks.len() - 1;
    let payload = Payload {
        msg: chunk,
        aad: &header_bytes,
    };

    let ct = if is_last {
        encryptor
            .take()
            .unwrap()
            .encrypt_last(payload)
            .map_err(|_| JsValue::from_str("Stream final block encryption failed"))?
    } else {
        encryptor
            .as_mut()
            .unwrap()
            .encrypt_next(payload)
            .map_err(|_| JsValue::from_str("Stream block encryption failed"))?
    };
    output.extend_from_slice(&ct);
}
    Ok(output)
}

#[wasm_bindgen]
pub fn decrypt_bytes(payload_bytes: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    if payload_bytes.len() < HEADER_LEN + GCM_TAG_LEN {
        return Err(JsValue::from_str("Invalid payload: truncated header or stream"));
    }

    let header_bytes = &payload_bytes[..HEADER_LEN];
    let header = VaultHeader::from_bytes(header_bytes).map_err(|e| JsValue::from_str(e))?;
    let stream_body = &payload_bytes[HEADER_LEN..];

    // Derive key ONCE per payload inside Zeroizing container
    let key = derive_key_argon2id(passphrase, &header).map_err(|e| JsValue::from_str(&e))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    drop(key);

    let mut decryptor = Some(DecryptorBE32::from_aead(cipher, &header.nonce_prefix.into()));

    // Each encrypted block produced by EncryptorBE32 contains `chunk_size` ciphertext bytes
    // plus the AEAD authentication tag (16 bytes for AES-256-GCM).
    let block_len = (header.chunk_size as usize) + GCM_TAG_LEN;
    let blocks: Vec<&[u8]> = stream_body.chunks(block_len).collect();

    let mut decrypted_padded = Vec::with_capacity(stream_body.len());

for (idx, block) in blocks.iter().enumerate() {
    let is_last = idx == blocks.len() - 1;
    let payload = Payload {
        msg: block,
        aad: header_bytes,
    };

    let pt = if is_last {
        decryptor
            .take()
            .unwrap()
            .decrypt_last(payload)
            .map_err(|_| {
                JsValue::from_str(
                    "ACCESS DENIED: Invalid passphrase, altered header, or truncated/reordered stream",
                )
            })?
    } else {
        decryptor
            .as_mut()
            .unwrap()
            .decrypt_next(payload)
            .map_err(|_| {
                JsValue::from_str(
                    "ACCESS DENIED: Invalid passphrase, altered header, or corrupted stream block",
                )
            })?
    };
    decrypted_padded.extend_from_slice(&pt);
}

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

    let remainder = current_len % target_bucket_size;
    let pad_len = if remainder == 0 {
        target_bucket_size
    } else {
        target_bucket_size - remainder
    };

    let total_len = current_len + pad_len;
    let mut padded = Vec::with_capacity(total_len + 4);

    padded.extend_from_slice(&(current_len as u32).to_be_bytes());
    padded.extend_from_slice(plaintext);

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

    Ok(decrypted_padded[payload_start..payload_end].to_vec())
}
