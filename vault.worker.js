// vault.worker.js
import init, { encrypt_bytes, decrypt_bytes } from './pkg/bs_securevault.js';

let isWasmInitialized = false;

async function initWasm() {
    try {
        await init();
        isWasmInitialized = true;
        self.postMessage({ type: 'READY' });
    } catch (err) {
        self.postMessage({ type: 'ERROR', error: `WASM Init Failed: ${err}` });
    }
}

initWasm();

self.onmessage = async (e) => {
    const { id, type, payload } = e.data;

    if (!isWasmInitialized) {
        return self.postMessage({ id, type: 'ERROR', error: 'WASM engine is still loading.' });
    }

    if (type === 'ENCRYPT') {
        const { dataBytes, passBytes } = payload;
        const startTime = performance.now();
        let encrypted = null;

        try {
            // Rust WASM Encryption
            encrypted = encrypt_bytes(dataBytes, passBytes);
            const duration = (performance.now() - startTime).toFixed(2);

            self.postMessage({
                id,
                type: 'ENCRYPT_SUCCESS',
                result: encrypted,
                duration: duration
            }, [encrypted.buffer]);
        } catch (err) {
            self.postMessage({ id, type: 'ERROR', error: String(err) });
        } finally {
            // Guaranteed zeroization even if encrypt_bytes throws
            if (passBytes && passBytes.fill) passBytes.fill(0);
        }

    } else if (type === 'DECRYPT') {
        const { dataBytes, passBytes } = payload;
        const startTime = performance.now();
        let decrypted = null;

        try {
            // Rust WASM Decryption
            decrypted = decrypt_bytes(dataBytes, passBytes);
            const duration = (performance.now() - startTime).toFixed(2);

            self.postMessage({
                id,
                type: 'DECRYPT_SUCCESS',
                result: decrypted,
                duration: duration
            }, [decrypted.buffer]);
        } catch (err) {
            self.postMessage({ id, type: 'ERROR', error: String(err) });
        } finally {
            // Guaranteed zeroization even if decrypt_bytes throws
            if (passBytes && passBytes.fill) passBytes.fill(0);
        }
    }
};
