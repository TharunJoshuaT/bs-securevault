# BS SecureVault — WebAssembly Browser Manual

> **Module:** `bs_securevault` WASM Engine  
> **Target:** Modern Web Browsers (Chrome, Edge, Safari, Firefox)  
> **Security:** Client-Side Zero-Knowledge Encryption  
> **Developer:** BS Operating Systems and Software Engines (BS OS SE)  

---

## Overview
The WebAssembly (WASM) engine brings defense-grade cryptography directly into client browsers. All key derivation (Argon2id) and encryption/decryption operations (AES-256-GCM) execute strictly inside client memory—no unencrypted bytes or passphrases ever leave the local machine.

---

## Web Integration Guide

### 1. Module Initialization
Import and initialize the WebAssembly binding in your application:

```javascript
import init, { encrypt_bytes, decrypt_bytes } from './pkg/bs_securevault.js';

// Initialize WebAssembly memory space
await init();
⚙️ Core API Functions
encrypt_bytes(data, passphrase)
Encrypts an in-memory byte array into a .bsv container buffer.
Parameters:
data (Uint8Array): Unencrypted target file or message bytes.
passphrase (Uint8Array): UTF-8 encoded passphrase array.
Returns: Uint8Array — Complete .bsv binary array containing attached salt, nonce, ciphertext, and authentication tag.
decrypt_bytes(payload, passphrase)
Decrypts a .bsv binary array back to raw plaintext.
Parameters:
payload (Uint8Array): Complete .bsv file buffer.
passphrase (Uint8Array): UTF-8 encoded passphrase array.
Returns: Uint8Array — Decrypted file bytes.
Error Handling: Throws an exception if authentication fails or if payload framing is invalid.
🌐 Cross-Browser Streaming Strategy
To maintain stability when processing large files (100 MB+):
Chromium (Chrome, Edge, Opera): Uses FileSystemAccessAPI direct disk streaming, keeping browser RAM utilization under 70 MB regardless of file size.
Safari & Firefox: Uses memory-buffered streaming with a 64 MB chunking window and auto-zeroizing stack buffers.
