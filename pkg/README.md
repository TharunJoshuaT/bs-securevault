# BS SecureVault

> **Core Engine:** Rust + WebAssembly (WASM)  
> **Security Model:** Zero-Knowledge Client-Side Cryptography  
> **Container Extension:** `.bsv`  
> **Developer:** BS Operating Systems and Software Engines (BS OS SE)  

---

## Overview

**BS SecureVault** is an enterprise-grade, client-side encryption system built by **BS Operating Systems and Software Engines**. It connects high-performance native terminal execution with browser-based web applications using a shared Rust cryptographic core.

### Key Specifications
*  **Argon2id + AES-256-GCM:** Memory-hard password key derivation combined with authenticated payload encryption.
*  **Cross-Platform Parity:** Files encrypted via the terminal CLI can be decrypted directly inside modern web browsers and vice versa[cite: 3].
*  **Auto-Zeroizing Memory:** Memory allocations holding sensitive key materials are automatically scrubbed upon execution using Rust `zeroize`.
*  **High Entropy:** Output container headers and ciphertexts are mathematically indistinguishable from random noise.

---

## Technical Manuals & Benchmarks

*  **[Terminal CLI Manual](./BSVTerminalManual.md)** — CLI installation and usage guide.
*  **[Browser WASM Manual](./BSVBrowserManual.md)** — JavaScript and WASM integration reference.
*  **[Benchmarks & Test Benches](./BENCHMARKS.md)** — Interactive WASM test bench (`wasm-test.html`) and stress test suite (`stress-test.html`)[cite: 5, 6].

---

## Build Instructions

### 1. Build Native Terminal CLI
```bash
cargo build --release --bin bsv
The compiled binary executable will be created at ./target/release/bsv.

2. Build WebAssembly Web Package
Bash
wasm-pack build --target web --out-dir pkg

💻 Terminal CLI Commands
Encrypt a File
Bash
./target/release/bsv encrypt -i <INPUT_FILE> -o <OUTPUT_CONTAINER.bsv>
Decrypt a File
Bash
./target/release/bsv decrypt -i <CONTAINER.bsv> -o <RESTORED_FILE>
© 2026 BS Operating Systems and Software Engines. All Rights Reserved.
