# syntax=docker/dockerfile:1.7

# ==========================================
# Stage 1: Build Rust CLI + WASM (pkg/)
# ==========================================
FROM rust:1-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown && \
    cargo install wasm-pack --locked

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release CLI binary and WASM web package
RUN cargo build --release --bin bsv && \
    wasm-pack build --target web --release --out-dir /app/pkg

# ==========================================
# Stage 2: Minimal Runtime for Cloud Run
# ==========================================
FROM node:22-alpine AS runtime

ENV NODE_ENV=production
ENV PORT=8080
ENV HOST=0.0.0.0

WORKDIR /app

# Copy compiled WASM package and static frontend files
COPY --from=rust-builder /app/pkg ./pkg
COPY . .

# Lightweight static + WASM HTTP server with security headers
RUN cat <<'EOF' > /app/server.mjs
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || '0.0.0.0';
const rootDir = process.cwd();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  let relPath = decodeURIComponent(reqUrl.pathname);
  if (relPath === '/') relPath = '/index.html';

  const safePath = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
  const fullPath = path.join(rootDir, safePath);

  if (!fullPath.startsWith(rootDir)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  fs.stat(fullPath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(fullPath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    });

    fs.createReadStream(fullPath).pipe(res);
  });
});

server.listen(port, host, () => {
  console.log(`BS SecureVault server listening on http://${host}:${port}`);
});
EOF

EXPOSE 8080
CMD ["node", "/app/server.mjs"]
