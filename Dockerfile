# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage: full toolchain, never shipped.
# ---------------------------------------------------------------------------
FROM node:26-bookworm-slim AS build

WORKDIR /app

# Dependencies first, so a change to the source does not invalidate this layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# Reinstall with production dependencies only. `npm ci` from the same lockfile,
# so the versions are exactly those the build and the tests used.
RUN npm ci --omit=dev && npm cache clean --force

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
FROM node:26-bookworm-slim AS runtime

# dumb-init reaps zombies and forwards signals, so SIGTERM reaches Node and the
# shutdown handler runs instead of the container being killed.
RUN apt-get update \
    && apt-get install --no-install-recommends -y dumb-init \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000

WORKDIR /app

# The image runs as the unprivileged `node` user that the base image provides.
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node public ./public
COPY --chown=node:node package.json ./

USER node

EXPOSE 3000

# The filesystem can be mounted read-only: the application writes nothing to disk.
# See compose.yaml, which sets `read_only: true` and a tmpfs for /tmp.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
