# syntax=docker/dockerfile:1
# Hardened image: multi-stage, non-root, PINNED base tag (NEVER :latest).
# CIS Docker Benchmark 4.x · CWE-1104 (use of unmaintained/unpinned components).
#
# Production hardening: pin by immutable digest instead of the version tag:
#   docker pull node:20.18.1-bookworm-slim
#   docker inspect --format='{{index .RepoDigests 0}}' node:20.18.1-bookworm-slim
# then replace the FROM with  node:20.18.1-bookworm-slim@sha256:<digest>
FROM node:20.18.1-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:20.18.1-bookworm-slim AS runtime
ENV NODE_ENV=production \
    LAB_MODE=false \
    PORT=3000
WORKDIR /app
# Drop privileges — the node image ships a non-root 'node' user (CIS 4.1).
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node . .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
