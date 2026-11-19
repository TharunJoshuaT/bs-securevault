# BS SecureVault Binary Format Specification (v2)

All multi-byte integers are **Big-Endian (BE)**.

## 1. File Header (46 Bytes Total — Authenticated as AAD)
Every `.bsv` file starts with a fixed 46-byte header. This entire 46-byte slice is passed as Associated Data (AAD) into the STREAM cipher so any single-bit modification to the header aborts decryption immediately.

| Offset | Size | Field | Value / Description |
| :--- | :--- | :--- | :--- |
| `0` | 4 B | `magic` | ASCII `BSV\x02` (`0x42 0x53 0x56 0x02`) |
| `4` | 1 B | `version` | `0x02` (Format v2) |
| `5` | 1 B | `kdf_id` | `0x01` = Argon2id |
| `6` | 4 B | `m_cost_kib` | Memory cost in KiB (u32 BE). **Hard cap: 262,144 KiB (256 MiB)** |
| `10` | 4 B | `t_cost` | Time cost / iterations (u32 BE). **Hard cap: 10** |
| `14` | 4 B | `p_cost` | Parallelism / lanes (u32 BE). **Hard cap: 4** |
| `18` | 4 B | `chunk_size` | Plaintext chunk size in bytes (u32 BE, default `65536` = 64 KiB). **Hard cap: 16,777,216 (16 MiB)** |
| `22` | 16 B | `salt` | 128-bit CSPRNG random salt |
| `38` | 7 B | `nonce_prefix` | 56-bit (7-byte) CSPRNG nonce prefix for `EncryptorBE32` |
| `45` | 1 B | `reserved` | `0x00` (Reserved for future flags) |

## 2. Ciphertext Stream (AEAD STREAM `EncryptorBE32` / `DecryptorBE32`)
* **Cipher:** AES-256-GCM
* **Key Derivation:** Single Argon2id run (`output_len = 32` bytes) using `salt`, `m_cost_kib`, `t_cost`, `p_cost`.
* **Chunking:** Plaintext is split into `chunk_size` blocks (64 KiB default).
* **Authentication:** Each block is encrypted via `EncryptorBE32` with the 46-byte header passed as AAD on every `encrypt_next` / `encrypt_last` call. `EncryptorBE32` internally appends a 32-bit big-endian counter and a 1-byte last-block flag (`0x00` vs `0x01`) to the 7-byte `nonce_prefix` to form the 12-byte GCM nonce—preventing chunk reordering, duplication, or truncation.