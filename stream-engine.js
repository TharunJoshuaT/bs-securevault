// stream-engine.js
const CHUNK_SIZE = 64 * 1024 * 1024; // 64 MB raw chunk size
const CHUNK_OVERHEAD_BYTES = 44;     // 16 (Salt) + 12 (Nonce) + 16 (GCM Tag)
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + CHUNK_OVERHEAD_BYTES;

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
 * Encrypts large files by slicing into chunks.
 * Direct Disk Stream on Chromium | Memory-Buffered Download on Safari & Firefox.
 */
export async function encryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);
    const hasFileSystemAccess = 'showSaveFilePicker' in window;
    
    const outputFileName = `${file.name}.bsv`;
    let fileHandle, writableStream;
    const memoryBuffer = [];

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
    let processedBytes = 0;

    try {
        for (let i = 0; i < totalChunks; i++) {
            const start = i * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, totalSize);

            const fileSlice = file.slice(start, end);
            const chunkBuffer = new Uint8Array(await fileSlice.arrayBuffer());
            const passBytes = new TextEncoder().encode(password);

            // FIX: Only transfer chunkBuffer.buffer in transferables.
            // DO NOT transfer passBytes.buffer so password bytes aren't detached!
            const { result } = await runWorkerIPC(worker, 'ENCRYPT', {
                dataBytes: chunkBuffer,
                passBytes: passBytes
            }, [chunkBuffer.buffer]);

            if (hasFileSystemAccess) {
                await writableStream.write(result);
            } else {
                memoryBuffer.push(result);
            }

            processedBytes += (end - start);

            const elapsedSec = (performance.now() - startTime) / 1000;
            const speedMBps = ((processedBytes / (1024 * 1024)) / (elapsedSec || 0.001)).toFixed(2);
            const percent = Math.round((processedBytes / totalSize) * 100);

            if (onProgress) {
                onProgress({
                    percent,
                    processedBytes,
                    totalBytes: totalSize,
                    speedMBps,
                    chunkCurrent: i + 1,
                    chunkTotal: totalChunks
                });
            }
        }

        if (hasFileSystemAccess) {
            await writableStream.close();
            return fileHandle.name;
        } else {
            triggerBlobDownload(memoryBuffer, outputFileName);
            return outputFileName;
        }
    } catch (err) {
        if (writableStream) await writableStream.close();
        throw err;
    }
}

/**
 * Decrypts large .bsv files by slicing chunks.
 * Direct Disk Stream on Chromium | Memory-Buffered Download on Safari & Firefox.
 */
export async function decryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const inputChunkSize = CHUNK_OVERHEAD_BYTES > 0 ? ENCRYPTED_CHUNK_SIZE : CHUNK_SIZE;
    const totalChunks = Math.ceil(totalSize / inputChunkSize);
    const hasFileSystemAccess = 'showSaveFilePicker' in window;

    let defaultRestoredName = file.name.replace(/\.bsv$/, '');
    if (defaultRestoredName === file.name) defaultRestoredName = `restored_${file.name}`;

    let fileHandle, writableStream;
    const memoryBuffer = [];

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
    let processedBytes = 0;

    try {
        for (let i = 0; i < totalChunks; i++) {
            const start = i * inputChunkSize;
            const end = Math.min(start + inputChunkSize, totalSize);

            const fileSlice = file.slice(start, end);
            const encryptedBuffer = new Uint8Array(await fileSlice.arrayBuffer());
            const passBytes = new TextEncoder().encode(password);

            // FIX: Only transfer encryptedBuffer.buffer in transferables.
            const { result } = await runWorkerIPC(worker, 'DECRYPT', {
                dataBytes: encryptedBuffer,
                passBytes: passBytes
            }, [encryptedBuffer.buffer]);

            if (hasFileSystemAccess) {
                await writableStream.write(result);
            } else {
                memoryBuffer.push(result);
            }

            processedBytes += (end - start);

            const elapsedSec = (performance.now() - startTime) / 1000;
            const speedMBps = ((processedBytes / (1024 * 1024)) / (elapsedSec || 0.001)).toFixed(2);
            const percent = Math.round((processedBytes / totalSize) * 100);

            if (onProgress) {
                onProgress({
                    percent,
                    processedBytes,
                    totalBytes: totalSize,
                    speedMBps,
                    chunkCurrent: i + 1,
                    chunkTotal: totalChunks
                });
            }
        }

        if (hasFileSystemAccess) {
            await writableStream.close();
            return fileHandle.name;
        } else {
            triggerBlobDownload(memoryBuffer, defaultRestoredName);
            return defaultRestoredName;
        }
    } catch (err) {
        if (writableStream) await writableStream.close();
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
        dataBytes: dataBytes,
        passBytes: passBytes
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
