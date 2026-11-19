// stream-engine.js

/**
 * Triggers a standard browser download for non-Chromium browsers (Safari, Firefox).
 */
function triggerBlobDownload(chunks, fileName) {
    const blob = new Blob(chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 1000);
}

/**
 * Encrypts a file into a single BSV v2 STREAM container via the WASM worker.
 * Direct Disk Stream on Chromium | Memory-Buffered Download on Safari & Firefox.
 */
export async function encryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const hasFileSystemAccess = 'showSaveFilePicker' in window;

    const outputFileName = `${file.name}.bsv`;
    let fileHandle, writableStream;

    if (hasFileSystemAccess) {
        try {
            fileHandle = await window.showSaveFilePicker({
                suggestedName: outputFileName,
                types: [{ description: 'BS SecureVault File', accept: { 'application/octet-stream': ['.bsv'] } }]
            });
            writableStream = await fileHandle.createWritable();
        } catch (e) {
            throw new Error("File save cancelled or file system permission denied.");
        }
    }

    const startTime = performance.now();

    try {
        if (onProgress) {
            onProgress({
                percent: 5,
                processedBytes: 0,
                totalBytes: totalSize,
                speedMBps: "0.00",
                chunkCurrent: 1,
                chunkTotal: 1
            });
        }

        const dataBytes = new Uint8Array(await file.arrayBuffer());
        const passBytes = new TextEncoder().encode(password);

        // Only transfer dataBytes.buffer; never transfer passBytes.buffer.
        const { result } = await runWorkerIPC(worker, 'ENCRYPT', {
            dataBytes,
            passBytes
        }, [dataBytes.buffer]);

        if (hasFileSystemAccess) {
            await writableStream.write(result);
            await writableStream.close();
        } else {
            triggerBlobDownload([result], outputFileName);
        }

        const elapsedSec = Math.max((performance.now() - startTime) / 1000, 0.001);
        const speedMBps = ((totalSize / (1024 * 1024)) / elapsedSec).toFixed(2);

        if (onProgress) {
            onProgress({
                percent: 100,
                processedBytes: totalSize,
                totalBytes: totalSize,
                speedMBps,
                chunkCurrent: 1,
                chunkTotal: 1
            });
        }

        return hasFileSystemAccess ? fileHandle.name : outputFileName;
    } catch (err) {
        if (writableStream) {
            try { await writableStream.close(); } catch (_) {}
        }
        throw err;
    }
}

/**
 * Decrypts a .bsv container via the WASM worker as a single authenticated stream.
 * Direct Disk Stream on Chromium | Memory-Buffered Download on Safari & Firefox.
 */
export async function decryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const hasFileSystemAccess = 'showSaveFilePicker' in window;

    let defaultRestoredName = file.name.replace(/\.bsv$/, '');
    if (defaultRestoredName === file.name) defaultRestoredName = `restored_${file.name}`;

    let fileHandle, writableStream;

    if (hasFileSystemAccess) {
        try {
            fileHandle = await window.showSaveFilePicker({
                suggestedName: defaultRestoredName,
                types: [{ description: 'Restored File', accept: { 'application/octet-stream': ['*'] } }]
            });
            writableStream = await fileHandle.createWritable();
        } catch (e) {
            throw new Error("File save cancelled or file system permission denied.");
        }
    }

    const startTime = performance.now();

    try {
        if (onProgress) {
            onProgress({
                percent: 5,
                processedBytes: 0,
                totalBytes: totalSize,
                speedMBps: "0.00",
                chunkCurrent: 1,
                chunkTotal: 1
            });
        }

        const dataBytes = new Uint8Array(await file.arrayBuffer());
        const passBytes = new TextEncoder().encode(password);

        // Only transfer dataBytes.buffer; never transfer passBytes.buffer.
        const { result } = await runWorkerIPC(worker, 'DECRYPT', {
            dataBytes,
            passBytes
        }, [dataBytes.buffer]);

        if (hasFileSystemAccess) {
            await writableStream.write(result);
            await writableStream.close();
        } else {
            triggerBlobDownload([result], defaultRestoredName);
        }

        const elapsedSec = Math.max((performance.now() - startTime) / 1000, 0.001);
        const speedMBps = ((totalSize / (1024 * 1024)) / elapsedSec).toFixed(2);

        if (onProgress) {
            onProgress({
                percent: 100,
                processedBytes: totalSize,
                totalBytes: totalSize,
                speedMBps,
                chunkCurrent: 1,
                chunkTotal: 1
            });
        }

        return hasFileSystemAccess ? fileHandle.name : defaultRestoredName;
    } catch (err) {
        if (writableStream) {
            try { await writableStream.close(); } catch (_) {}
        }
        throw err;
    }
}

/**
 * Decrypts in-memory ArrayBuffer bundles (e.g. .bsv-bundle for IndexedDB restore)
 */
export async function decryptVaultBundle(bundleArrayBuffer, password, worker) {
    const dataBytes = new Uint8Array(bundleArrayBuffer);
    const passBytes = new TextEncoder().encode(password);

    // Only transfer dataBytes.buffer, leaving passBytes usable for future iterations
    const { result } = await runWorkerIPC(worker, 'DECRYPT', {
        dataBytes,
        passBytes
    }, [dataBytes.buffer]);

    return result;
}

// Leak-proof IPC helper with timeout protection
let streamCallbackCounter = 900000;
function runWorkerIPC(worker, type, payload, transferables = []) {
    return new Promise((resolve, reject) => {
        const id = ++streamCallbackCounter;
        let timer = null;

        const cleanup = () => {
            worker.removeEventListener('message', handler);
            if (timer) clearTimeout(timer);
        };

        const handler = (e) => {
            if (e.data && e.data.id === id) {
                cleanup();
                if (e.data.type === 'ERROR') {
                    reject(new Error(e.data.error));
                } else {
                    resolve({ result: e.data.result, duration: e.data.duration });
                }
            }
        };

        timer = setTimeout(() => {
            cleanup();
            reject(new Error("Worker request timed out. Module may have crashed."));
        }, 60000);

        worker.addEventListener('message', handler);
        worker.postMessage({ id, type, payload }, transferables);
    });
}
