import init, { encrypt_bytes, decrypt_bytes } from './pkg/bs_securevault.js';

let isWasmInitialized = false;

// Initialize WASM core upon worker spawning
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

    try {
        if (type === 'ENCRYPT') {
            const { dataBytes, passBytes } = payload;
            const startTime = performance.now();
            const encrypted = encrypt_bytes(dataBytes, passBytes);
            const duration = performance.now() - startTime;

            // Transfer ArrayBuffer back to avoid structured clone overhead
            self.postMessage({
                id,
                type: 'ENCRYPT_SUCCESS',
                result: encrypted,
                duration: duration.toFixed(2)
            }, [encrypted.buffer]);

        } else if (type === 'DECRYPT') {
            const { dataBytes, passBytes } = payload;
            const startTime = performance.now();
            const decrypted = decrypt_bytes(dataBytes, passBytes);
            const duration = performance.now() - startTime;

            self.postMessage({
                id,
                type: 'DECRYPT_SUCCESS',
                result: decrypted,
                duration: duration.toFixed(2)
            }, [decrypted.buffer]);
        }
    } catch (err) {
        self.postMessage({ id, type: 'ERROR', error: String(err) });
    }
};