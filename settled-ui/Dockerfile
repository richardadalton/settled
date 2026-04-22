# Build context must be the repo root (set in compose.yml).
# This lets us reach both settled-ui/ and proto/.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:20-slim AS builder
WORKDIR /app

COPY settled-ui/package*.json ./
RUN npm ci

COPY settled-ui/ .
# Proto file lives outside the UI directory; copy it so the gRPC client can
# load it at the same relative path used in development.
COPY proto/ /proto

RUN npm run build

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM node:20-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production

COPY settled-ui/package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist       ./dist
COPY --from=builder /proto          /proto

EXPOSE 3000

CMD ["node", "dist/server/index.js"]
