# debian-host-audit

*[Version française](README.fr.md)*

One container image, one command, one normalized report: a **read-only security audit of a Debian 13 host**, built so that a human *or an AI agent* gets the whole picture in a single file.

It bundles three established open-source tools and a set of custom checks, runs them against the **host** (not the container), and merges everything into `summary.json` + `summary.md` with one finding shape and one severity scale.

| Layer | Tool | What it covers |
|---|---|---|
| Host hardening | [Lynis](https://github.com/CISOfy/lynis) 3.1.7 | ~260 tests: kernel, boot, auth, PAM, file permissions, services, logging… |
| Host essentials | custom checks | SSH effective config, uid-0 accounts, root-equivalent groups (`docker`), default-deny firewall, exposed listeners, Docker ports published on all interfaces, pending security updates, unattended-upgrades, pending reboot, failed units, `/tmp` mount options |
| Docker | [docker-bench-security](https://github.com/docker/docker-bench-security) 1.6.1 | CIS Docker Benchmark: daemon config, files, images, running containers |
| Vulnerabilities | [Trivy](https://github.com/aquasecurity/trivy) 0.76.2 | CVEs in the host's Debian packages and in container images |

## Why

The tools above are good, but each has its own output format, its own notion of severity, and none of them tells you when it silently audited the wrong thing. A heavy platform (Wazuh, OpenVAS) is overkill for an occasional audit of a handful of VMs. This project is the thin layer in between.

## Quick start

```bash
git clone <this repo> && cd debian-host-audit
docker build -t debian-host-audit:0.1.0 .

mkdir -p reports
docker run --rm --privileged --pid=host \
  -v /:/host:ro -v "$PWD/reports:/reports" \
  debian-host-audit:0.1.0
```

`summary.md` is printed on stdout. Everything lands in `reports/<hostname>_<UTC timestamp>/`, owned by whoever owns `reports/`, with owner-only permissions.

**For an agent**, ask for JSON on stdout (logs go to stderr):

```bash
docker run --rm --privileged --pid=host -v /:/host:ro debian-host-audit:0.1.0 --json > audit.json
jq '.coverage_complete, .counts, [.findings[] | select(.severity=="critical" or .severity=="high")]' audit.json
```

A full run on a busy host takes 3–5 minutes plus about 3 s to 2 min per scanned image.

## Usage

```
debian-host-audit [STEP...] [OPTIONS]

Steps (default: all)
  host      Lynis + custom host checks
  docker    docker-bench-security (skipped if Docker is absent)
  vulns     Trivy scan of the host's Debian packages
  images    Trivy scan of container images

Options
  --images running|all|none   which images to scan (default: those of running containers)
  --max-images N              scan at most N images (coverage then reads "partial")
  --docker-socket PATH        default: /host/run/docker.sock
  --json                      summary.json on stdout instead of summary.md
  --fail-on SEVERITY          exit 2 if a finding is at or above SEVERITY
  --offline                   never download the Trivy DB (build with EMBED_TRIVY_DB=1)
  --version
```

Exit codes: `0` report produced · `1` preflight error (missing flag or mount) · `2` `--fail-on` threshold reached.

## The report

`summary.json` (`schema_version: 1`):

| Field | Content |
|---|---|
| `run` | hostname, OS, timestamp, duration, tool versions, steps |
| `coverage[]` | one entry per check: `ok` / `partial` / `failed` / `skipped`, with the reason and duration |
| `coverage_complete` | `false` as soon as one check is not `ok`. **Read this first.** |
| `witness` | proof that Lynis audited the host and not the container (see below) |
| `host` | Lynis hardening index, docker-bench tallies, collected facts (listeners, groups, sshd settings, kernels…) |
| `counts` | findings per severity |
| `findings[]` | `{id, source, severity, category, title, evidence, remediation, references}`, sorted by severity |
| `vulnerabilities[]` | per target (host packages, each image): counts per severity, fixable counts, unfixed critical/high counts, and the full list of fixable critical/high CVEs |

Severity is `critical > high > medium > low > info`. Mapping:

- **Lynis**: warning → `medium`, suggestion → `low`.
- **docker-bench**: `WARN` → `medium`. Raised to `high` when the check breaks isolation outright: privileged containers, the Docker socket mounted in a container, a shared host namespace, sensitive host directories mounted, insecure registries, an unauthenticated TCP daemon.
- **Trivy**: one finding per target that carries *fixable* critical/high CVEs, at the worst severity found. CVEs with no fix available (`affected`, `fix_deferred`, `will_not_fix`) give one `info` finding, because nothing can be upgraded yet.
- **Custom checks**: each check sets its own level (uid 0 besides root → `critical`; docker group members, `PermitRootLogin yes`, pending security updates → `high`; …).

`raw/` keeps the untouched output of every tool, so any finding can be verified.

## How it works

The container only **delivers** the tools. It does not audit itself.

1. **Lynis, docker-bench and the custom collector run inside the host's namespaces** (`nsenter -t 1 -m -u -i -n -p`), with the host's own binaries. A Lynis started in a plain container audits the container, and its report looks clean.
2. They run from the image's filesystem and write their reports back into it through `/proc/<container pid>/root`. **Nothing is written to the audited host's disk.** The one exception: Lynis creates short-lived temp files in the host's `/tmp` and deletes them.
3. **Trivy** never walks the host filesystem: it scans a minimal copy of the host's `os-release` and dpkg `status`, which takes seconds even on a host with terabytes of data. Images are read through the Docker socket.
4. **Witness check.** The image is Debian 13 too, so "the OS is Debian 13" proves nothing. The summary compares the hostname Lynis saw with the host's hostname, and Lynis's installed-package count with a floor that the image cannot reach. If either fails, Lynis's findings are discarded and its coverage is marked `failed`.

Preflight refuses to run without `-v /:/host:ro`, `--pid=host` or `--privileged`, rather than produce a report about the wrong system.

## Auditing several VMs

```bash
# copies the image over SSH (no registry), runs it, collects <host>.json locally
scripts/audit-remote.sh --ship-image vm1 vm2 admin@vm3 -- all --max-images 20
```

Raw files stay on each host under `~/host-audit-reports/`. Use `--sudo` if the SSH user is not in the `docker` group.

## Security considerations

- **`--privileged --pid=host` with `/` mounted means root on the host.** That is inherent to auditing a host from a container. Run the image on demand with `--rm`; never as a long-running service.
- **The image is a supply-chain trust point.** Every component is pinned by version and SHA-256 in the `Dockerfile`, and the base image by digest. The Trivy release tarball's Sigstore signature was verified before pinning: Trivy's published binaries were compromised in 2026. Re-verify on every bump:
  ```bash
  cosign verify-blob --bundle trivy_<v>_Linux-64bit.tar.gz.sigstore.json \
    --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com trivy_<v>_Linux-64bit.tar.gz
  ```
- **Reports are sensitive.** They describe exactly how to attack the host. They are written owner-only (`0700`/`0600`); keep them out of public places.
- **Read-only by construction.** No `apt update`, no package install, no configuration change. Pending updates are read from the local apt cache, and a finding warns when that cache is older than 7 days.

## Limitations

- **Built for Debian 13 (trixie).** Other Debian releases will mostly work, with a warning. Other distributions are not supported.
- **docker-bench-security 1.6.1 is its latest release (2023)** and implements CIS Docker Benchmark 1.6. Some checks lag behind recent Docker Engine versions.
- **Only one Docker daemon**, the one on the default socket. Rootless Docker and `userns-remap` hosts are untested.
- **Trivy downloads its vulnerability DB** (~80 MB) on each run. Build with `--build-arg EMBED_TRIVY_DB=1` and pass `--offline` for air-gapped hosts. The embedded DB goes stale, so rebuild regularly.
- **Firewall detection** looks for a default-deny inbound policy (nftables `hook input … policy drop`, `iptables -P INPUT DROP`, or ufw `deny (incoming)`). It does not evaluate individual rules. Ports published by Docker bypass the INPUT chain: they are reported separately.

## Development

```bash
python3 -m unittest discover -s tests          # stdlib only
shellcheck -S warning bin/audit lib/collect-host.sh scripts/audit-remote.sh
```

To bump a component, change both `*_VERSION` and `*_SHA256` in the `Dockerfile` in the same commit.

## License

MIT, see [LICENSE](LICENSE). The image redistributes, unmodified:
- Lynis, under **GPL-3.0**: its source is the shell scripts themselves, under `/opt/lynis`;
- docker-bench-security and Trivy, under **Apache-2.0**.

Their license texts are in `/usr/share/doc/third-party/` inside the image.
