# debian-host-audit — one image, one command, one report.
#
# Every third-party component is pinned by version AND sha256. Bumping a
# version means updating both values in the same commit.

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG LYNIS_VERSION=3.1.7
ARG LYNIS_SHA256=48d829d0dc2c583a3e838cc09a7190b69a3af844bcb913c7cf9c0226b04b95c5
ARG DOCKER_BENCH_VERSION=1.6.1
ARG DOCKER_BENCH_SHA256=736111db91d5c11808e015d3980c8cb199dce4d03bf35d897e23b7d87cc25844
# Release tarball signature verified with cosign (sigstore bundle) before pinning.
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_SHA256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
# Set to 1 to bake the Trivy vulnerability DB into the image (offline hosts, ~+100 MB).
ARG EMBED_TRIVY_DB=0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq python3 \
 && rm -rf /var/lib/apt/lists/*

COPY build/patch-lynis.sh /tmp/patch-lynis.sh

RUN set -eu; cd /tmp; \
    curl -fsSL -o lynis.tgz "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VERSION}.tar.gz"; \
    echo "${LYNIS_SHA256}  lynis.tgz" | sha256sum -c -; \
    mkdir -p /opt/lynis && tar xzf lynis.tgz -C /opt/lynis --strip-components=1; \
    # GPL-3.0 modification notice: temp/PID files honour LYNIS_TMPDIR (see build/patch-lynis.sh)
    sh /tmp/patch-lynis.sh /opt/lynis; rm /tmp/patch-lynis.sh; \
    curl -fsSL -o bench.tgz "https://github.com/docker/docker-bench-security/archive/refs/tags/v${DOCKER_BENCH_VERSION}.tar.gz"; \
    echo "${DOCKER_BENCH_SHA256}  bench.tgz" | sha256sum -c -; \
    mkdir -p /opt/docker-bench && tar xzf bench.tgz -C /opt/docker-bench --strip-components=1; \
    curl -fsSL -o trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  trivy.tgz" | sha256sum -c -; \
    tar xzf trivy.tgz -C /usr/local/bin trivy; \
    mkdir -p /usr/share/doc/third-party; \
    cp /opt/lynis/LICENSE /usr/share/doc/third-party/lynis.LICENSE; \
    cp /opt/docker-bench/LICENSE.md /usr/share/doc/third-party/docker-bench-security.LICENSE; \
    tar xzf trivy.tgz -C /usr/share/doc/third-party LICENSE && mv /usr/share/doc/third-party/LICENSE /usr/share/doc/third-party/trivy.LICENSE; \
    rm -f /tmp/*.tgz; \
    # Lynis refuses to load include files writable by group/other.
    chown -R root:root /opt/lynis /opt/docker-bench; chmod -R go-w /opt/lynis /opt/docker-bench

ENV TRIVY_CACHE_DIR=/var/cache/trivy
RUN if [ "${EMBED_TRIVY_DB}" = "1" ]; then trivy image --download-db-only --cache-dir "${TRIVY_CACHE_DIR}"; fi

COPY bin/ /opt/dha/bin/
COPY lib/ /opt/dha/lib/
COPY VERSION /opt/dha/VERSION
RUN chmod 0755 /opt/dha/bin/audit /opt/dha/lib/collect-host.sh

LABEL org.opencontainers.image.title="debian-host-audit" \
      org.opencontainers.image.description="Read-only security audit of a Debian 13 host: Lynis, docker-bench-security, Trivy, one normalized report." \
      org.opencontainers.image.licenses="MIT"

ENV LYNIS_VERSION=${LYNIS_VERSION} DOCKER_BENCH_VERSION=${DOCKER_BENCH_VERSION} TRIVY_VERSION=${TRIVY_VERSION}
ENTRYPOINT ["/opt/dha/bin/audit"]
CMD ["all"]
