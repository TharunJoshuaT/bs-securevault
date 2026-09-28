const CACHE_NAME = 'bs-securevault-v1';

// List all core static assets required to run the vault offline
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/vault.worker.js',
  '/stream-engine.js',
  '/sw.js',
  '/pkg/bs_securevault_bg.wasm', // compiled Rust WASM binary
  '/pkg/bs_securevault.js'        // wasm-pack JS glue code
];

// 1. Install Event: Cache essential assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[BS SecureVault SW] Pre-caching offline assets...');
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

// 2. Activate Event: Clean up legacy caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[BS SecureVault SW] Removing old cache:', key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// 3. Fetch Event: Serve from Cache first, fall back to Network
self.addEventListener('fetch', (event) => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Return cached version immediately (works 100% offline)
        return cachedResponse;
      }
      // If not in cache, attempt network fetch
      return fetch(event.request);
    })
  );
});
