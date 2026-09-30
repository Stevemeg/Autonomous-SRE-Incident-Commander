# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG NODE_IMAGE=node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
ARG NODE_RUNTIME=gcr.io/distroless/nodejs24-debian13@sha256:bb6b03d81066993293a10feda7250e8e1cc034035fe9b61cfceededa7c8bf04d

# Debian's CVE-2026-84782 backport until the distroless base ships this update.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS runtime-security
ARG LIBSSL_VERSION=3.5.7-1~deb13u3
WORKDIR /packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64=${LIBSSL_VERSION} \
    && apt-get download libssl3t64=${LIBSSL_VERSION} \
    && dpkg-deb --extract libssl3t64_*.deb /patched \
    && mkdir -p /patched/var/lib/dpkg/status.d \
    && dpkg-query --status libssl3t64 > /patched/var/lib/dpkg/status.d/libssl3t64 \
    && cp /var/lib/dpkg/info/libssl3t64:$(dpkg --print-architecture).md5sums \
        /patched/var/lib/dpkg/status.d/libssl3t64.md5sums

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts

FROM dependencies AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY . .
RUN npm run build

FROM ${NODE_RUNTIME} AS runtime
COPY --from=runtime-security /patched/ /
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Autonomous SRE Incident Commander Dashboard" \
      org.opencontainers.image.description="Server-rendered incident-command dashboard" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/Stevemeg/Autonomous-SRE-Incident-Commander"

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

WORKDIR /app
COPY --from=build --chown=10001:10001 /app/.next/standalone ./
COPY --from=build --chown=10001:10001 /app/.next/static ./.next/static

USER 10001:10001
EXPOSE 3000
CMD ["server.js"]
