const CHUNK_SIZE = 64 * 1024 * 1024; // 64 MB raw chunk size
// Set to 16/28 if your Rust WASM appends nonces/tags per chunk, or 0 if pure stream mode
const CHUNK_OVERHEAD_BYTES = 0;
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + CHUNK_OVERHEAD_BYTES;

/**
 * Encrypts large files by slicing into 64MB chunks and streaming to disk.
 */
export async function encryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);

    let fileHandle, writableStream;
    try {
        fileHandle = await window.showSaveFilePicker({
            suggestedName: `${file.name}.bsv`,
            types: [{ description: 'BS SecureVault File', accept: { 'application/octet-stream': ['.bsv'] } }]
        });
        writableStream = await fileHandle.createWritable();
    } catch (e) {
        throw new Error("File save cancelled or File System API not supported.");
    }

    const startTime = performance.now();
    let processedBytes = 0;

    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, totalSize);
        
        const fileSlice = file.slice(start, end);
        const chunkBuffer = new Uint8Array(await fileSlice.arrayBuffer());
        const passBytes = new TextEncoder().encode(password);

        const { result } = await runWorkerIPC(worker, 'ENCRYPT', {
            dataBytes: chunkBuffer,
            passBytes: passBytes
        }, [chunkBuffer.buffer, passBytes.buffer]);

        await writableStream.write(result);
        processedBytes += (end - start);

        const elapsedSec = (performance.now() - startTime) / 1000;
        const speedMBps = ((processedBytes / (1024 * 1024)) / elapsedSec).toFixed(2);
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

    await writableStream.close();
    return fileHandle.name;
}

/**
 * Decrypts large .bsv files by slicing chunks and streaming restored data directly to disk.
 */
export async function decryptLargeFileWithWasm({ file, password, worker, onProgress }) {
    const totalSize = file.size;
    const inputChunkSize = CHUNK_OVERHEAD_BYTES > 0 ? ENCRYPTED_CHUNK_SIZE : CHUNK_SIZE;
    const totalChunks = Math.ceil(totalSize / inputChunkSize);

    let defaultRestoredName = file.name.replace(/\.bsv$/, '');
    if (defaultRestoredName === file.name) defaultRestoredName = `restored_${file.name}`;

    let fileHandle, writableStream;
    try {
        fileHandle = await window.showSaveFilePicker({
            suggestedName: defaultRestoredName,
            types: [{ description: 'Restored File', accept: { 'application/octet-stream': ['*'] } }]
        });
        writableStream = await fileHandle.createWritable();
    } catch (e) {
        throw new Error("File save cancelled or File System API not supported.");
    }

    const startTime = performance.now();
    let processedBytes = 0;

    for (let i = 0; i < totalChunks; i++) {
        const start = i * inputChunkSize;
        const end = Math.min(start + inputChunkSize, totalSize);

        const fileSlice = file.slice(start, end);
        const encryptedBuffer = new Uint8Array(await fileSlice.arrayBuffer());
        const passBytes = new TextEncoder().encode(password);

        const { result } = await runWorkerIPC(worker, 'DECRYPT', {
            dataBytes: encryptedBuffer,
            passBytes: passBytes
        }, [encryptedBuffer.buffer, passBytes.buffer]);

        await writableStream.write(result);
        processedBytes += (end - start);

        const elapsedSec = (performance.now() - startTime) / 1000;
        const speedMBps = ((processedBytes / (1024 * 1024)) / elapsedSec).toFixed(2);
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

    await writableStream.close();
    return fileHandle.name;
}

// Internal IPC helper matching the main window callback map protocol
let streamCallbackCounter = 900000;
function runWorkerIPC(worker, type, payload, transferables = []) {
    return new Promise((resolve, reject) => {
        const id = ++streamCallbackCounter;
        const handler = (e) => {
            if (e.data && e.data.id === id) {
                worker.removeEventListener('message', handler);
                if (e.data.type === 'ERROR') {
                    reject(new Error(e.data.error));
                } else {
                    resolve({ result: e.data.result, duration: e.data.duration });
                }
            }
        };
        worker.addEventListener('message', handler);
        worker.postMessage({ id, type, payload }, transferables);
    });
}
