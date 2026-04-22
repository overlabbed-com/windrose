# Windrose Next.js application
FROM node:20-bookworm AS base

# Install build dependencies
FROM base AS deps
RUN apt-get update && \
    apt-get install -y python3 make g++ build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Clean install
RUN npm ci

# Build the application
FROM base AS builder
WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build
RUN npm run build

# Production image - copy everything needed
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy all necessary files
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json

# Create entrypoint script
RUN printf '%s\n' \
'#!/bin/sh' \
'mkdir -p /app/data' \
'chown -R nextjs:nodejs /app/data 2>/dev/null || true' \
'if [ ! -f /app/data/config.json ]; then' \
'  echo "{\"version\":1,\"setupComplete\":false,\"preferences\":{},\"personalization\":{},\"modelProviders\":[],\"search\":{\"searxngURL\":\"http://searxng:8080\"}}" > /app/data/config.json' \
'fi' \
'exec node server.js' > /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown nextjs:nodejs /app/entrypoint.sh

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOST_NAME=0.0.0.0

ENTRYPOINT ["/app/entrypoint.sh"]
