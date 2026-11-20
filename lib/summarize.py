#!/usr/bin/env python3
"""Normalize raw tool output into summary.json + summary.md.

Usage:
    summarize.py <report-dir>
    summarize.py --check-threshold <severity> <summary.json>

Stdlib only. Every finding has the same shape:
    {id, source, severity, category, title, evidence, remediation, references}
Severity scale: critical > high > medium > low > info.

A tool that failed must never look like a clean host: every check reports its
status in `coverage`, and a failed or skipped check is listed in the summary.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA_VERSION = 1
SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


def finding(id, source, severity, category, title, evidence="", remediation="", references=None):
    return {
        "id": id,
        "source": source,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
        "references": references or [],
    }


def read(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


# ------------------------------------------------------------------ Lynis

def parse_lynis_report(text: str) -> dict:
    """report.dat: `key=value`, arrays as `key[]=value`."""
    scalars: dict[str, str] = {}
    arrays: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.endswith("[]"):
            arrays[key[:-2]].append(value)
        else:
            scalars[key] = value
    return {"scalars": scalars, "arrays": dict(arrays)}


def _lynis_item(raw: str):
    # ID|text|details|solution|  — '-' means empty
    parts = [p if p != "-" else "" for p in raw.split("|")]
    parts += [""] * (4 - len(parts))
    return parts[0], parts[1], parts[2], parts[3]


def lynis_findings(report: dict) -> list[dict]:
    out = []
    for kind, severity in (("warning", "medium"), ("suggestion", "low")):
        for raw in report["arrays"].get(kind, []):
            tid, text, details, solution = _lynis_item(raw)
            out.append(finding(
                id=f"lynis:{tid}",
                source="lynis",
                severity=severity,
                category=f"lynis-{kind}",
                title=text,
                evidence=details,
                remediation=solution,
                references=[f"https://cisofy.com/lynis/controls/{tid}/"] if tid else [],
            ))
    return out


# ------------------------------------------------------------------ docker-bench

# docker-bench has no severity. These checks give root on the host or break
# isolation outright, so they are raised to high; every other WARN is medium.
DOCKER_BENCH_HIGH = re.compile(
    r"privileged containers|docker socket is not mounted|"
    r"host's (network|process|ipc|user) namespace|sensitive host system directories|"
    r"insecure registries|TLS authentication",
    re.IGNORECASE,
)
LOG_LINE = re.compile(r"^\[(WARN|NOTE|PASS|INFO)\]\s+(\d+(?:\.\d+)+)\s+-\s+(.*)$")
LOG_DETAIL = re.compile(r"^\[(?:WARN|NOTE|INFO)\]\s+\*\s+(.*)$")


def parse_docker_bench(json_text: str | None, log_text: str | None) -> tuple[list[dict], str]:
    """Return (results, parser). docker-bench prints its JSON with printf and
    does not escape quotes, so a description with a quote breaks the file:
    fall back to the text log, which carries the same verdicts."""
    if json_text:
        try:
            data = json.loads(json_text, strict=False)
            results = []
            for section in data.get("tests", []):
                for r in section.get("results", []):
                    results.append(r)
            return results, "json"
        except (ValueError, AttributeError):
            pass
    results = []
    if log_text:
        for line in log_text.splitlines():
            m = LOG_LINE.match(line.strip())
            if m:
                results.append({"id": m.group(2), "desc": m.group(3), "result": m.group(1)})
            elif results and results[-1]["result"] == "WARN" and (d := LOG_DETAIL.match(line.strip())):
                results[-1]["details"] = "; ".join(filter(None, [results[-1].get("details"), d.group(1)]))
    return results, "log"


def docker_bench_findings(results: list[dict]) -> list[dict]:
    out = []
    for r in results:
        if r.get("result") != "WARN":
            continue
        desc = r.get("desc", "")
        items = r.get("items")
        evidence = r.get("details", "")
        if isinstance(items, list) and items:
            evidence = ", ".join(map(str, items[:20])) + (" …" if len(items) > 20 else "")
        out.append(finding(
            id=f"docker-bench:{r.get('id')}",
            source="docker-bench",
            severity="high" if DOCKER_BENCH_HIGH.search(desc) else "medium",
            category="docker-cis",
            title=desc,
            evidence=evidence,
            remediation=r.get("remediation", ""),
            references=["https://www.cisecurity.org/benchmark/docker"],
        ))
    return out


# ------------------------------------------------------------------ custom checks

def sshd_settings(text: str) -> dict[str, str]:
    s = {}
    for line in text.splitlines():
        k, _, v = line.strip().partition(" ")
        if k:
            s.setdefault(k.lower(), v.strip().lower())
    return s


def custom_findings(host: Path) -> tuple[list[dict], dict]:
    out: list[dict] = []
    facts: dict = {}

    def txt(name):
        if read(host / f"{name}.rc") is None:
            return None
        return read(host / f"{name}.txt") or ""

    # Accounts with uid 0
    uid0 = [u for u in (txt("uid0") or "").split() if u != "root"]
    if uid0:
        out.append(finding("custom:uid0", "custom", "critical", "accounts",
                           "Accounts other than root have uid 0", ", ".join(uid0),
                           "Remove or renumber these accounts; uid 0 is root."))

    # Privileged groups — docker membership is root-equivalent
    groups = {}
    for line in (txt("groups-priv") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            groups[parts[0]] = [m for m in parts[3].split(",") if m]
    facts["privileged_groups"] = groups
    if groups.get("docker"):
        out.append(finding("custom:docker-group", "custom", "high", "accounts",
                           "Users in the docker group are root-equivalent",
                           "docker: " + ", ".join(groups["docker"]),
                           "Anyone in `docker` can mount / into a privileged container. Keep the group "
                           "empty, use rootless Docker, or accept it knowingly (sudo with logging is auditable, docker is not).",
                           ["https://docs.docker.com/engine/security/#docker-daemon-attack-surface"]))

    # SSH
    sshd = txt("sshd-effective")
    if sshd is not None:
        s = sshd_settings(sshd)
        facts["sshd"] = {k: s.get(k) for k in ("permitrootlogin", "passwordauthentication",
                                               "kbdinteractiveauthentication", "x11forwarding",
                                               "maxauthtries", "allowusers", "allowgroups", "port")}
        if s.get("permitrootlogin") == "yes":
            out.append(finding("custom:ssh-root-login", "custom", "high", "ssh",
                               "SSH allows root login with a password", "PermitRootLogin yes",
                               "Set `PermitRootLogin no` (or `prohibit-password`) in /etc/ssh/sshd_config.d/."))
        if s.get("passwordauthentication") == "yes":
            out.append(finding("custom:ssh-password-auth", "custom", "medium", "ssh",
                               "SSH accepts password authentication", "PasswordAuthentication yes",
                               "Use keys only: `PasswordAuthentication no` and `KbdInteractiveAuthentication no`."))
        if s.get("x11forwarding") == "yes":
            out.append(finding("custom:ssh-x11", "custom", "low", "ssh",
                               "SSH X11 forwarding enabled", "X11Forwarding yes", "Set `X11Forwarding no`."))
        try:
            if int(s.get("maxauthtries", "6")) > 4:
                out.append(finding("custom:ssh-maxauthtries", "custom", "low", "ssh",
                                   "SSH MaxAuthTries above 4", f"MaxAuthTries {s.get('maxauthtries')}",
                                   "Set `MaxAuthTries 3`."))
        except ValueError:
            pass

    # Listening sockets
    listeners = []
    for line in (txt("listening") or "").splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        addr, _, port = local.rpartition(":")
        proc = re.search(r'users:\(\("([^"]+)"', line)
        listeners.append({"proto": proto, "address": addr, "port": port,
                          "process": proc.group(1) if proc else ""})
    loopback = re.compile(r"^(127\.|::1$|fe80:)")
    exposed = [l for l in listeners
               if not loopback.match(l["address"].strip("[]").split("%")[0])]
    facts["listening"] = listeners
    facts["exposed_listeners"] = exposed

    # Firewall: a default-deny inbound policy anywhere (nftables or iptables)
    nft = txt("nft-ruleset") or ""
    ipt = txt("iptables-input") or ""
    ufw = txt("ufw") or ""
    deny_inbound = bool(
        re.search(r"hook input[^\n]*policy drop", nft)
        or re.search(r"^-P INPUT (DROP|REJECT)", ipt, re.M)
        or re.search(r"Status: active", ufw) and re.search(r"deny \(incoming\)", ufw)
    )
    facts["firewall_default_deny_inbound"] = deny_inbound
    if not deny_inbound:
        sev = "medium" if exposed else "low"
        ports = sorted({f"{l['proto']}/{l['port']} ({l['process'] or '?'})" for l in exposed})
        out.append(finding("custom:no-firewall", "custom", sev, "network",
                           "No default-deny inbound firewall policy",
                           ("Exposed listeners: " + ", ".join(ports)) if ports else "No non-loopback listener found",
                           "Add an nftables `input` chain with `policy drop` allowing only needed ports. "
                           "Note: ports published by Docker bypass INPUT (they go through FORWARD/DOCKER-USER).",
                           ["https://wiki.debian.org/nftables"]))
    for l in exposed:
        out.append(finding(f"custom:listen:{l['proto']}:{l['port']}", "custom", "info", "network",
                           f"Listening on {l['address']}:{l['port']} ({l['proto']})",
                           l["process"], "Confirm this service must be reachable from the network."))

    # Docker published ports on all interfaces
    for line in (txt("docker-published") or "").splitlines():
        name, _, ports = line.partition("\t")
        public = re.findall(r"(?:0\.0\.0\.0|\[::\]|:::):(\d+)->", ports)
        if public:
            out.append(finding(f"custom:docker-published:{name}", "custom", "medium", "docker",
                               f"Container {name} publishes ports on all interfaces",
                               ports.strip(),
                               "Bind to 127.0.0.1 (`127.0.0.1:PORT:PORT`) unless the port must be public. "
                               "Docker-published ports are NOT filtered by the INPUT chain."))

    # Updates
    upg = [l for l in (txt("apt-upgradable") or "").splitlines() if "/" in l and "[upgradable" in l]
    security = [l.split("/")[0] for l in upg if "-security" in l]
    facts["upgradable_packages"] = len(upg)
    facts["upgradable_security_packages"] = len(security)
    if security:
        out.append(finding("custom:security-updates", "custom", "high", "updates",
                           f"{len(security)} security updates pending",
                           ", ".join(security[:30]) + (" …" if len(security) > 30 else ""),
                           "apt-get update && apt-get upgrade"))
    elif upg:
        out.append(finding("custom:updates", "custom", "low", "updates",
                           f"{len(upg)} package updates pending", "",
                           "apt-get update && apt-get upgrade"))
    age = (txt("apt-lists-age") or "").split()
    if len(age) == 2:
        try:
            days = (int(age[1]) - int(age[0])) / 86400
            facts["apt_lists_age_days"] = round(days, 1)
            if days > 7:
                out.append(finding("custom:apt-lists-stale", "custom", "low", "updates",
                                   f"Package lists are {days:.0f} days old — pending updates are underestimated",
                                   "", "Run `apt-get update` (or enable apt-daily.timer)."))
        except ValueError:
            pass
    unattended = txt("unattended") or ""
    facts["unattended_upgrades"] = "install ok installed" in unattended
    if "install ok installed" not in unattended:
        out.append(finding("custom:no-unattended-upgrades", "custom", "medium", "updates",
                           "unattended-upgrades is not installed",
                           "", "apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
                           ["https://wiki.debian.org/UnattendedUpgrades"]))

    # Reboot
    running = (txt("kernel-running") or "").strip()
    installed = (txt("kernels-installed") or "").split()
    facts["kernel_running"] = running
    facts["kernels_installed"] = installed
    reboot = "REBOOT_REQUIRED" in (txt("reboot-required") or "")
    newest = sorted(installed, key=_version_key)[-1] if installed else ""
    if reboot or (newest and running and newest != running):
        out.append(finding("custom:reboot-required", "custom", "medium", "updates",
                           "A reboot is needed to run the newest installed kernel/libraries",
                           f"running {running}, newest installed {newest or '?'}",
                           "Schedule a reboot."))

    # Failed units
    failed = [l.split()[0] for l in (txt("failed-units") or "").splitlines() if l.strip()]
    if failed:
        out.append(finding("custom:failed-units", "custom", "info", "system",
                           f"{len(failed)} failed systemd units", ", ".join(failed),
                           "Check `systemctl --failed`: a failed security unit (e.g. a firewall loader) is silent."))

    # Mount options
    for line in (txt("mounts") or "").splitlines():
        target, _, opts = line.partition(" ")
        if target in ("/tmp", "/dev/shm", "/var/tmp"):
            missing = [o for o in ("nodev", "nosuid", "noexec") if o not in opts.split(",")]
            if missing:
                out.append(finding(f"custom:mount:{target}", "custom", "low", "filesystem",
                                   f"{target} mounted without {', '.join(missing)}", opts,
                                   f"Add {','.join(missing)} to the {target} mount options."))
    return out, facts


def _version_key(v: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+~]", v)]


# ------------------------------------------------------------------ Trivy

def trivy_summary(path: Path, target_label: str, kind: str) -> tuple[dict | None, list[dict]]:
    text = read(path)
    if not text:
        return None, []
    try:
        data = json.loads(text)
    except ValueError:
        return None, []
    counts = Counter()
    fixable_counts = Counter()
    fixable = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "UNKNOWN").lower()
            counts[sev] += 1
            fixed = v.get("FixedVersion") or ""
            if fixed and v.get("Status", "fixed") in ("fixed", ""):
                fixable_counts[sev] += 1
                if sev in ("critical", "high"):
                    fixable.append({
                        "id": v.get("VulnerabilityID"), "severity": sev, "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"), "fixed": fixed,
                        "title": (v.get("Title") or "")[:200], "url": v.get("PrimaryURL", ""),
                        "target": res.get("Target", ""),
                    })
    unfixed = {sev: counts[sev] - fixable_counts[sev] for sev in ("critical", "high")}
    summary = {
        "target": target_label, "kind": kind, "unfixed_critical_high": unfixed,
        "counts": dict(counts), "fixable_counts": dict(fixable_counts),
        "fixable_critical_high": sorted(fixable, key=lambda x: (RANK.get(x["severity"], 9), x["package"] or "")),
    }
    findings = []
    if fixable:
        by_pkg = defaultdict(list)
        for f in fixable:
            by_pkg[(f["package"], f["fixed"])].append(f["id"])
        worst = min((f["severity"] for f in fixable), key=lambda s: RANK[s])
        evidence = "; ".join(f"{p} → {fx} ({len(ids)} CVE)" for (p, fx), ids in sorted(by_pkg.items())[:25])
        remediation = ("apt-get update && apt-get upgrade" if kind == "host"
                       else "Rebuild the image on an updated base and bump the listed dependencies.")
        findings.append(finding(
            id=f"trivy:{kind}:{target_label}", source="trivy", severity=worst, category="vulnerabilities",
            title=f"{len(fixable)} fixable critical/high CVEs in {target_label}",
            evidence=evidence + (" …" if len(by_pkg) > 25 else ""), remediation=remediation,
        ))
    if unfixed["critical"] or unfixed["high"]:
        findings.append(finding(
            id=f"trivy:{kind}-unfixed:{target_label}", source="trivy", severity="info",
            category="vulnerabilities",
            title=f"{unfixed['critical']} critical / {unfixed['high']} high CVEs in {target_label} have no fix available",
            evidence="Status affected / fix_deferred / will_not_fix upstream",
            remediation="Nothing to upgrade yet. Reduce exposure (remove unused packages, minimal base image) "
                        "and re-audit; see raw Trivy output for the list.",
        ))
    return summary, findings


# ------------------------------------------------------------------ witness

def witness(report: dict | None, run: dict, host_dir: Path) -> dict:
    """Prove Lynis audited the HOST, not the container. Both are Debian 13,
    so the OS name proves nothing: compare hostname and package count."""
    if report is None:
        return {"status": "not-applicable"}
    sc = report["scalars"]
    lynis_host = sc.get("hostname", "")
    lynis_pkgs = sc.get("installed_packages", "")
    checks = {
        "hostname": {"lynis": lynis_host, "host": run.get("hostname"),
                     "ok": bool(lynis_host) and lynis_host == run.get("hostname")},
    }
    try:
        n = int(lynis_pkgs)
        # The audit image carries ~100 packages; a real host carries far more.
        checks["installed_packages"] = {"lynis": n, "ok": n > 150}
    except ValueError:
        checks["installed_packages"] = {"lynis": lynis_pkgs, "ok": None}
    ok = all(c["ok"] is not False for c in checks.values())
    return {"status": "ok" if ok else "failed", "checks": checks}


# ------------------------------------------------------------------ assemble

def build(out_dir: Path) -> dict:
    raw = out_dir / "raw"
    run = json.loads(read(raw / "run.json") or "{}")
    coverage = []
    for p in sorted((raw / "coverage").glob("*.json")):
        coverage.append(json.loads(p.read_text()))
    cov = {c["check"]: c for c in coverage}

    findings: list[dict] = []
    host_info: dict = {}

    report = None
    if cov.get("lynis", {}).get("status") == "ok":
        report = parse_lynis_report(read(raw / "lynis-report.dat") or "")
        host_info["lynis_hardening_index"] = _int(report["scalars"].get("hardening_index"))
        host_info["lynis_tests_performed"] = _int(report["scalars"].get("lynis_tests_done"))
    wit = witness(report, run, raw / "host")
    if wit["status"] == "failed":
        cov["lynis"].update(status="failed",
                            reason="witness check failed: Lynis audited the container, not the host — findings discarded")
    elif report is not None:
        findings += lynis_findings(report)

    if cov.get("custom", {}).get("status") == "ok":
        f, facts = custom_findings(raw / "host")
        findings += f
        host_info["facts"] = facts

    if cov.get("docker-bench", {}).get("status") == "ok":
        results, parser = parse_docker_bench(read(raw / "docker-bench.log.json"), read(raw / "docker-bench.log"))
        if results:
            findings += docker_bench_findings(results)
            cov["docker-bench"]["reason"] = f"{len(results)} checks parsed from {parser}"
            c = Counter(r.get("result") for r in results)
            host_info["docker_bench"] = {"warn": c.get("WARN", 0), "pass": c.get("PASS", 0),
                                         "note": c.get("NOTE", 0), "info": c.get("INFO", 0)}
        else:
            cov["docker-bench"].update(status="failed", reason="docker-bench ran but no result could be parsed")

    vulns = []
    if cov.get("trivy-host", {}).get("status") == "ok":
        s, f = trivy_summary(raw / "trivy-host.json", "host packages", "host")
        if s is None:
            cov["trivy-host"].update(status="failed", reason="unreadable trivy-host.json")
        else:
            vulns.append(s); findings += f
    index = raw / "images" / "index.tsv"
    if index.exists():
        for line in index.read_text().splitlines():
            safe, ref, containers = (line.split("\t") + ["", ""])[:3]
            s, f = trivy_summary(raw / "images" / f"{safe}.json", ref, "image")
            if s:
                s["containers"] = [c for c in containers.split(",") if c]
                vulns.append(s); findings += f

    findings.sort(key=lambda f: (RANK.get(f["severity"], 9), f["source"], f["id"]))
    # Lynis reuses a control ID for several suggestions: keep ids unique.
    seen = Counter()
    for f in findings:
        seen[f["id"]] += 1
        if seen[f["id"]] > 1:
            f["id"] = f"{f['id']}#{seen[f['id']]}"
    counts = Counter(f["severity"] for f in findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run": run,
        "coverage": list(cov.values()),
        "coverage_complete": all(c["status"] == "ok" for c in cov.values()),
        "witness": wit,
        "host": host_info,
        "counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "findings": findings,
        "vulnerabilities": vulns,
    }


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _cell(s: str, n: int = 160) -> str:
    s = (s or "").replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def render_md(s: dict) -> str:
    run = s["run"]
    L = [f"# Security audit — {run.get('hostname', '?')}", ""]
    L.append(f"- **OS**: {run.get('os', '?')} · **audited**: {run.get('audited_at', '?')} UTC "
             f"· **duration**: {run.get('duration_s', '?')} s")
    comps = run.get("components", {})
    L.append(f"- **Tools**: debian-host-audit {run.get('tool_version')} · " +
             " · ".join(f"{k} {v}" for k, v in comps.items()))
    hi = s["host"].get("lynis_hardening_index")
    if hi is not None:
        L.append(f"- **Lynis hardening index**: {hi}/100")
    c = s["counts"]
    L.append("- **Findings**: " + " · ".join(f"{c[k]} {k}" for k in SEVERITIES))
    L += ["", "## Coverage", ""]
    if not s["coverage_complete"]:
        L.append("> ⚠️ **Coverage is incomplete. A check that did not run says nothing about the host.**")
        L.append("")
    L += ["| Check | Status | Duration | Note |", "|---|---|---|---|"]
    for cv in s["coverage"]:
        icon = {"ok": "✅", "partial": "◐", "failed": "❌", "skipped": "⏭️"}.get(cv["status"], "?")
        L.append(f"| {cv['check']} | {icon} {cv['status']} | {cv['duration_s']} s | {_cell(cv['reason'])} |")
    w = s["witness"]
    if w.get("status") in ("ok", "failed"):
        L.append("")
        L.append(f"Witness (Lynis audited the host, not the container): **{w['status']}** — " +
                 ", ".join(f"{k}={v.get('lynis')}" for k, v in w["checks"].items()))

    L += ["", "## Findings", ""]
    for sev in SEVERITIES:
        rows = [f for f in s["findings"] if f["severity"] == sev]
        if not rows:
            continue
        L += [f"### {sev.capitalize()} ({len(rows)})", "",
              "| ID | Title | Evidence | Remediation |", "|---|---|---|---|"]
        for f in rows:
            L.append(f"| `{f['id']}` | {_cell(f['title'], 120)} | {_cell(f['evidence'])} | {_cell(f['remediation'])} |")
        L.append("")

    if s["vulnerabilities"]:
        L += ["## Vulnerabilities (Trivy)", "",
              "| Target | Critical | High | Medium | Low | Fixable crit+high |", "|---|---|---|---|---|---|"]
        for v in s["vulnerabilities"]:
            cc = v["counts"]
            L.append(f"| {_cell(v['target'], 80)} | {cc.get('critical', 0)} | {cc.get('high', 0)} | "
                     f"{cc.get('medium', 0)} | {cc.get('low', 0)} | {len(v['fixable_critical_high'])} |")
        L.append("")
    L += ["## Files", "",
          "- `summary.json` — same content, machine-readable (schema_version "
          f"{SCHEMA_VERSION}); full CVE lists under `vulnerabilities[].fixable_critical_high`.",
          "- `raw/` — untouched output of every tool, to verify any finding.", ""]
    return "\n".join(L)


def check_threshold(severity: str, summary_path: Path) -> int:
    if severity not in RANK:
        print(f"unknown severity {severity}", file=sys.stderr)
        return 1
    s = json.loads(summary_path.read_text())
    hit = sum(n for k, n in s["counts"].items() if RANK[k] <= RANK[severity])
    if hit:
        print(f"[audit] {hit} findings at or above {severity}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--check-threshold":
        return check_threshold(argv[2], Path(argv[3]))
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    out = Path(argv[1])
    summary = build(out)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    (out / "summary.md").write_text(render_md(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
