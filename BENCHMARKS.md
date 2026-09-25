# BS OS SE Verification & Benchmark Suite

> **Modules:** WASM Test Bench & Engine Stress Test Suite  
> **Target Runtimes:** WebAssembly (Browser V8 / JSC) & Native Rust CLI  
> **Developer:** BS Operating Systems and Software Engines (BS OS SE)  

---

## Overview

**BS SecureVault** includes two built-in verification suites designed for security researchers, performance analysts, and core developers[cite: 3, 4]:
1. **WASM Test Bench (`wasm-test.html`):** Verifies live in-memory cryptographic key derivation and cross-compatibility decryption of terminal-generated `.bsv` files[cite: 3, 6].
2. **Engine Stress Test Suite (`stress-test.html`):** Executes automated high-throughput stress tests and verifies GCM tag validation under memory loads[cite: 4, 5].

---

## 1. WASM Test Bench (`wasm-test.html`)

The Test Bench provides interactive verification across three operational phases[cite: 3, 6]:

### Test Phase 1: Engine Initialization
* Verifies that the WebAssembly linear memory layout is instantiated correctly and that CSPRNG entropy bindings are accessible.

### Test Phase 2: In-Browser WASM Engine Self-Test
* **Operation:** Encrypts and decrypts a test string using Argon2id + AES-256-GCM entirely inside WASM memory[cite: 3].
* **Verification:** Confirms that encrypted payload sizes match binary framing specifications and that restored text matches input byte-for-byte[cite: 3].

### Test Phase 3: Cross-Compatibility Decryption
* **Operation:** Accepts a `.bsv` container file created via the native `bsv` terminal CLI[cite: 3].
* **Verification:** Validates that the browser WASM engine can parse the terminal-generated 16-byte salt and 12-byte nonce to decrypt the file with zero loss[cite: 3].

---

## 2. Engine Stress Test Suite (`stress-test.html`)

The Stress Test Suite measures browser execution performance and hardware throughput ($MB/s$)[cite: 4, 5].

### Execution Parameters
* **Memory Allocation:** Stress tests allocation windows up to 64 MB per chunk.
* **Key Derivation Iterations:** Logs real-time timing metrics for Argon2id memory-hard execution times.
* **Cipher Integrity:** Validates that corrupted payloads fail instantly with authentication exceptions.

---

## Running Tests Locally

To run the test benches on your local machine:

1. **Build the WASM Package:**
   ```bash
   wasm-pack build --target web --out-dir pkg
Launch a Local Web Server:
Bash
python3 -m http.server 8000
Access via Browser:
WASM Test Bench: http://localhost:8000/wasm-test.html
   
Engine Stress Test: http://localhost:8000/stress-test.html
   
© 2026 BS Operating Systems and Software Engines. All Rights Reserved.
