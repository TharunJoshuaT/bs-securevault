use aes_gcm::{
    aead::{
        stream::{DecryptorBE32, EncryptorBE32},
        Aead, KeyInit, Payload,
    },
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use getrandom::getrandom;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_LEN: usize = 46;
pub const MAGIC: &[u8; 4] = b"BSV\x02";
pub const FORMAT_VERSION: u8 = 0x02;
pub const KDF_ARGON2ID: u8 = 0x01;

const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 7;
const KEY_LEN: usize = 32;
const BUCKET_SIZE: usize = 256;
const GCM_TAG_LEN: usize = 16;

// Legacy v1 constants (16B salt + 12B nonce + AES-256-GCM ciphertext, no BSV\x02 header)
const V1_SALT_LEN: usize = 16;
const V1_NONCE_LEN: usize = 12;
const V1_MIN_LEN: usize = V1_SALT_LEN + V1_NONCE_LEN + GCM_TAG_LEN;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    Rng,
    Kdf,
    BadFormat(&'static str),
    AuthFailed,
    Padding(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub was_v1: bool,
}

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

    pub fn from_bytes(buf: &[u8]) -> Result<Self, VaultError> {
        if buf.len() < HEADER_LEN {
            return Err(VaultError::BadFormat("truncated header"));
        }
        if &buf[0..4] != MAGIC || buf[4] != FORMAT_VERSION {
            return Err(VaultError::BadFormat("invalid magic or format version"));
        }
        if buf[5] != KDF_ARGON2ID {
            return Err(VaultError::BadFormat("unsupported KDF identifier"));
        }

        let m_cost_kib = u32::from_be_bytes(buf[6..10].try_into().unwrap());
        let t_cost = u32::from_be_bytes(buf[10..14].try_into().unwrap());
        let p_cost = u32::from_be_bytes(buf[14..18].try_into().unwrap());
        let chunk_size = u32::from_be_bytes(buf[18..22].try_into().unwrap());

        if m_cost_kib == 0 || m_cost_kib > MAX_M_COST_KIB {
            return Err(VaultError::BadFormat("m_cost exceeds safety cap"));
        }
        if t_cost == 0 || t_cost > MAX_T_COST {
            return Err(VaultError::BadFormat("t_cost exceeds safety cap"));
        }
        if p_cost == 0 || p_cost > MAX_P_COST {
            return Err(VaultError::BadFormat("p_cost exceeds safety cap"));
        }
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(VaultError::BadFormat("chunk_size exceeds safety cap"));
        }
        if buf[45] != 0x00 {
            return Err(VaultError::BadFormat("non-zero reserved byte"));
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
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    let params = Params::new(
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Kdf)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, &header.salt, key.as_mut_slice())
        .map_err(|_| VaultError::Kdf)?;

    Ok(key)
}

fn derive_v1_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    let params = Params::new(
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Kdf)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|_| VaultError::Kdf)?;

    Ok(key)
}

fn decrypt_v1_legacy(payload_bytes: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
    if payload_bytes.len() < V1_MIN_LEN {
        return Err(VaultError::BadFormat("truncated v1 payload"));
    }

    let salt = &payload_bytes[..V1_SALT_LEN];
    let nonce_bytes = &payload_bytes[V1_SALT_LEN..V1_SALT_LEN + V1_NONCE_LEN];
    let ciphertext = &payload_bytes[V1_SALT_LEN + V1_NONCE_LEN..];

    let key = derive_v1_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    drop(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::AuthFailed)?;

    let out = plaintext.clone();
    plaintext.zeroize();
    Ok(out)
}

pub fn encrypt_with_params(
    data: &[u8],
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    chunk_size: u32,
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt).map_err(|_| VaultError::Rng)?;

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom(&mut nonce_prefix).map_err(|_| VaultError::Rng)?;

    let header = VaultHeader {
        m_cost_kib,
        t_cost,
        p_cost,
        chunk_size,
        salt,
        nonce_prefix,
    };
    let _ = VaultHeader::from_bytes(&header.to_bytes())?;
    let header_bytes = header.to_bytes();

    let padded_data: Zeroizing<Vec<u8>> = Zeroizing::new(pad_bytes(data, BUCKET_SIZE)?);

    let key = derive_key_argon2id(passphrase, &header)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    drop(key);

    let mut encryptor = Some(EncryptorBE32::from_aead(cipher, &header.nonce_prefix.into()));

    let chunk_usize = header.chunk_size as usize;
    let chunks: Vec<&[u8]> = if padded_data.is_empty() {
        vec![&[]]
    } else {
        padded_data.chunks(chunk_usize).collect()
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
                .ok_or(VaultError::AuthFailed)?
                .encrypt_last(payload)
                .map_err(|_| VaultError::AuthFailed)?
        } else {
            encryptor
                .as_mut()
                .ok_or(VaultError::AuthFailed)?
                .encrypt_next(payload)
                .map_err(|_| VaultError::AuthFailed)?
        };
        output.extend_from_slice(&ct);
    }

    Ok(output)
}

pub fn encrypt_core(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
    encrypt_with_params(
        data,
        passphrase,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
        DEFAULT_CHUNK_SIZE,
    )
}

pub fn decrypt_core_with_meta(
    payload_bytes: &[u8],
    passphrase: &[u8],
) -> Result<DecryptResult, VaultError> {
    if payload_bytes.len() >= MAGIC.len() && &payload_bytes[..MAGIC.len()] == MAGIC {
        if payload_bytes.len() < HEADER_LEN + GCM_TAG_LEN {
            return Err(VaultError::BadFormat("truncated header or stream"));
        }

        let header_bytes = &payload_bytes[..HEADER_LEN];
        let header = VaultHeader::from_bytes(header_bytes)?;
        let stream_body = &payload_bytes[HEADER_LEN..];

        let key = derive_key_argon2id(passphrase, &header)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        drop(key);

        let mut decryptor = Some(DecryptorBE32::from_aead(cipher, &header.nonce_prefix.into()));

        let block_len = (header.chunk_size as usize) + GCM_TAG_LEN;
        let blocks: Vec<&[u8]> = stream_body.chunks(block_len).collect();

        let mut decrypted_padded: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(stream_body.len()));

        for (idx, block) in blocks.iter().enumerate() {
            let is_last = idx == blocks.len() - 1;
            let payload = Payload {
                msg: block,
                aad: header_bytes,
            };

            let mut pt = if is_last {
                decryptor
                    .take()
                    .ok_or(VaultError::AuthFailed)?
                    .decrypt_last(payload)
                    .map_err(|_| VaultError::AuthFailed)?
            } else {
                decryptor
                    .as_mut()
                    .ok_or(VaultError::AuthFailed)?
                    .decrypt_next(payload)
                    .map_err(|_| VaultError::AuthFailed)?
            };
            decrypted_padded.extend_from_slice(&pt);
            pt.zeroize();
        }

        let plaintext = unpad_bytes(&decrypted_padded)?;
        Ok(DecryptResult {
            plaintext,
            was_v1: false,
        })
    } else {
        let plaintext = decrypt_v1_legacy(payload_bytes, passphrase)?;
        Ok(DecryptResult {
            plaintext,
            was_v1: true,
        })
    }
}

pub fn decrypt_core(payload_bytes: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
    decrypt_core_with_meta(payload_bytes, passphrase).map(|r| r.plaintext)
}

pub fn migrate_v1_to_v2(
    legacy_payload: &[u8],
    current_passphrase: &[u8],
    new_passphrase: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
    let mut plaintext = decrypt_v1_legacy(legacy_payload, current_passphrase)?;
    let target_pass = new_passphrase.unwrap_or(current_passphrase);
    let upgraded = encrypt_core(&plaintext, target_pass);
    plaintext.zeroize();
    upgraded
}

#[wasm_bindgen]
pub fn decrypt_and_migrate_bytes(
    payload_bytes: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut res = decrypt_core_with_meta(payload_bytes, passphrase)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let upgraded = if res.was_v1 {
        encrypt_core(&res.plaintext, passphrase)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))
    } else {
        Ok(payload_bytes.to_vec())
    };
    res.plaintext.zeroize();
    upgraded
}

#[wasm_bindgen]
pub fn encrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    encrypt_core(data, passphrase).map_err(|e| JsValue::from_str(&format!("{e:?}")))
}

#[wasm_bindgen]
pub fn decrypt_bytes(payload_bytes: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsValue> {
    decrypt_core(payload_bytes, passphrase).map_err(|e| JsValue::from_str(&format!("{e:?}")))
}

// ==========================================
// CIPHERTEXT PADDING / BUCKETING (v0.1.1)
// ==========================================

pub fn pad_bytes(plaintext: &[u8], target_bucket_size: usize) -> Result<Vec<u8>, VaultError> {
    if target_bucket_size == 0 {
        return Err(VaultError::Padding("bucket size must be non-zero"));
    }

    let orig_len_u32 =
        u32::try_from(plaintext.len()).map_err(|_| VaultError::Padding("input exceeds u32 max"))?;
    let current_len = plaintext.len();

    let remainder = current_len % target_bucket_size;
    let pad_len = if remainder == 0 {
        target_bucket_size
    } else {
        target_bucket_size - remainder
    };

    let mut padded = Vec::with_capacity(4 + current_len + pad_len);
    padded.extend_from_slice(&orig_len_u32.to_be_bytes());
    padded.extend_from_slice(plaintext);

    let mut rng_bytes = Zeroizing::new(vec![0u8; pad_len]);
    getrandom(rng_bytes.as_mut_slice()).map_err(|_| VaultError::Rng)?;
    padded.extend_from_slice(rng_bytes.as_slice());

    Ok(padded)
}

pub fn unpad_bytes(decrypted_padded: &[u8]) -> Result<Vec<u8>, VaultError> {
    if decrypted_padded.len() < 4 {
        return Err(VaultError::Padding("missing 4-byte length header"));
    }

    let orig_len = u32::from_be_bytes([
        decrypted_padded[0],
        decrypted_padded[1],
        decrypted_padded[2],
        decrypted_padded[3],
    ]) as usize;

    let payload_start: usize = 4;
    let payload_end = payload_start
        .checked_add(orig_len)
        .ok_or(VaultError::Padding("length overflow"))?;

    if payload_end > decrypted_padded.len() {
        return Err(VaultError::Padding("payload bounds overflow"));
    }

    Ok(decrypted_padded[payload_start..payload_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sizes_with_small_chunk() {
        let sizes = [0, 1, 255, 256, 15, 16, 17, 64];
        for sz in sizes {
            let data = vec![0x5A_u8; sz];
            let ct = encrypt_with_params(&data, b"secret-pass", 64, 1, 1, 16).unwrap();
            let pt = decrypt_core(&ct, b"secret-pass").unwrap();
            assert_eq!(pt, data, "failed round-trip at size {sz}");
        }
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let ct = encrypt_with_params(b"top secret", b"right-pass", 64, 1, 1, 16).unwrap();
        let err = decrypt_core(&ct, b"wrong-pass").unwrap_err();
        assert_eq!(err, VaultError::AuthFailed);
    }

    #[test]
    fn flipping_header_byte_fails() {
        let mut ct = encrypt_with_params(b"hello vault", b"pass", 64, 1, 1, 16).unwrap();
        ct[10] ^= 0x01;
        assert!(decrypt_core(&ct, b"pass").is_err());
    }

    #[test]
    fn oversized_m_cost_rejected_without_allocation() {
        let mut hdr = VaultHeader {
            m_cost_kib: u32::MAX,
            t_cost: 2,
            p_cost: 1,
            chunk_size: 1024,
            salt: [1u8; 16],
            nonce_prefix: [2u8; 7],
        }
        .to_bytes()
        .to_vec();
        hdr.extend_from_slice(&[0u8; 32]);
        let err = decrypt_core(&hdr, b"pass").unwrap_err();
        assert_eq!(err, VaultError::BadFormat("m_cost exceeds safety cap"));
    }
}
