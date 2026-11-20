"""Unit tests for lib/summarize.py — stdlib unittest, no dependency.

Run:  python3 -m unittest discover -s tests
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import summarize as S  # noqa: E402

LYNIS_REPORT = """\
hostname=web-01
installed_packages=612
hardening_index=71
lynis_tests_done=260
warning[]=SSH-7408|Root can login via SSH|-|-|
suggestion[]=AUTH-9286|Configure minimum password age in /etc/login.defs|-|-|
suggestion[]=AUTH-9286|Configure maximum password age in /etc/login.defs|-|-|
"""

# docker-bench prints JSON with printf: an unescaped quote breaks the file.
BENCH_BROKEN_JSON = '{"tests": [{"id": "1", "results": [{"id": "5.5", "desc": "say "hi"", "result": "WARN"}]}]}'
BENCH_LOG = """\
[WARN] 5.5 - Ensure that privileged containers are not used (Automated)
[WARN]      * Privileged: traefik
[WARN] 5.8 - Ensure privileged ports are not mapped within containers (Automated)
[PASS] 5.9 - Ensure that only needed ports are open on the container (Manual)
"""

TRIVY = {
    "Results": [{
        "Target": "debian 13",
        "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "3.0",
             "FixedVersion": "3.1", "Status": "fixed", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-2", "PkgName": "linux", "InstalledVersion": "6.12",
             "Status": "affected", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-3", "PkgName": "zlib", "InstalledVersion": "1",
             "FixedVersion": "2", "Status": "fixed", "Severity": "LOW"},
        ],
    }]
}


def make_report(tmp: Path, *, hostname="web-01", lynis=LYNIS_REPORT, host_files=None,
                coverage=None, bench=None, trivy=None, hostname_mount=None) -> Path:
    raw = tmp / "raw"
    (raw / "coverage").mkdir(parents=True)
    (raw / "host").mkdir()
    (raw / "images").mkdir()
    (raw / "run.json").write_text(json.dumps({"hostname": hostname, "os": "Debian 13",
                                              "hostname_mount": hostname_mount or hostname}))
    cov = coverage or {"lynis": "ok", "custom": "ok"}
    for check, status in cov.items():
        (raw / "coverage" / f"{check}.json").write_text(json.dumps(
            {"check": check, "status": status, "reason": "", "duration_s": 1}))
    (raw / "lynis-report.dat").write_text(lynis)
    files = {"hostname": hostname + "\n", **(host_files or {})}
    for name, content in files.items():
        (raw / "host" / f"{name}.txt").write_text(content)
        (raw / "host" / f"{name}.rc").write_text("0\n")
    if bench is not None:
        json_text, log_text = bench
        (raw / "docker-bench.log.json").write_text(json_text)
        (raw / "docker-bench.log").write_text(log_text)
    if trivy is not None:
        (raw / "trivy-host.json").write_text(json.dumps(trivy))
    return tmp


class LynisTests(unittest.TestCase):
    def test_warnings_are_medium_suggestions_low_and_ids_unique(self):
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d)))
        lynis = [f for f in s["findings"] if f["source"] == "lynis"]
        self.assertEqual({f["severity"] for f in lynis if f["id"].startswith("lynis:SSH")}, {"medium"})
        ids = [f["id"] for f in s["findings"]]
        self.assertEqual(len(ids), len(set(ids)), "finding ids must be unique")
        self.assertIn("lynis:AUTH-9286#2", ids)
        self.assertEqual(s["host"]["lynis_hardening_index"], 71)

    def test_witness_failure_discards_lynis_findings(self):
        # Lynis audited the container: few packages, container hostname.
        container_report = LYNIS_REPORT.replace("installed_packages=612", "installed_packages=98") \
                                       .replace("hostname=web-01", "hostname=3f2a1b")
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d), lynis=container_report))
        self.assertEqual(s["witness"]["status"], "failed")
        self.assertFalse([f for f in s["findings"] if f["source"] == "lynis"])
        lynis_cov = next(c for c in s["coverage"] if c["check"] == "lynis")
        self.assertEqual(lynis_cov["status"], "failed")
        self.assertFalse(s["coverage_complete"])


    def test_witness_compares_short_hostnames(self):
        # Lynis records `hostname -s`; /etc/hostname may hold an FQDN.
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d), hostname_mount="web-01.example.org"))
        self.assertEqual(s["witness"]["status"], "ok")
        self.assertTrue([f for f in s["findings"] if f["source"] == "lynis"])

    def test_collector_witness_failure_discards_custom_findings(self):
        # e.g. --init without --pid=host: nsenter -t 1 entered the container.
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d), host_files={"hostname": "3f2a1b\n",
                                                         "groups-priv": "docker:x:999:alice\n"}))
        custom = next(c for c in s["coverage"] if c["check"] == "custom")
        self.assertEqual(custom["status"], "failed")
        self.assertFalse([f for f in s["findings"] if f["source"] == "custom"])


class DockerBenchTests(unittest.TestCase):
    def test_broken_json_falls_back_to_log(self):
        results, parser = S.parse_docker_bench(BENCH_BROKEN_JSON, BENCH_LOG)
        self.assertEqual(parser, "log")
        self.assertEqual([r["id"] for r in results], ["5.5", "5.8", "5.9"])
        self.assertIn("traefik", results[0]["details"])

    def test_privileged_containers_high_but_privileged_ports_medium(self):
        results, _ = S.parse_docker_bench(None, BENCH_LOG)
        sev = {f["id"]: f["severity"] for f in S.docker_bench_findings(results)}
        self.assertEqual(sev, {"docker-bench:5.5": "high", "docker-bench:5.8": "medium"})


class CustomCheckTests(unittest.TestCase):
    def findings(self, files):
        with tempfile.TemporaryDirectory() as d:
            make_report(Path(d), host_files=files)
            return S.custom_findings(Path(d) / "raw" / "host")

    def test_docker_group_and_ssh(self):
        f, facts = self.findings({
            "groups-priv": "docker:x:999:alice,bob\nsudo:x:27:alice\n",
            "sshd-effective": "permitrootlogin yes\npasswordauthentication no\nmaxauthtries 3\n",
            "unattended": "install ok installed\n",
        })
        sev = {x["id"]: x["severity"] for x in f}
        self.assertEqual(sev["custom:docker-group"], "high")
        self.assertEqual(sev["custom:ssh-root-login"], "high")
        self.assertNotIn("custom:ssh-password-auth", sev)
        self.assertEqual(facts["privileged_groups"]["docker"], ["alice", "bob"])

    def test_firewall_detected_through_ufw(self):
        f, facts = self.findings({
            "ufw": "Status: active\nDefault: deny (incoming), allow (outgoing)\n",
            "unattended": "install ok installed\n",
        })
        self.assertTrue(facts["firewall_default_deny_inbound"])
        self.assertNotIn("custom:no-firewall", {x["id"] for x in f})

    def test_no_firewall_with_exposed_listener_is_medium(self):
        f, facts = self.findings({
            "listening": 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                         'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))\n'
                         'tcp LISTEN 0 128 [::1]:6379 [::]:* users:(("redis",pid=3,fd=3))\n',
            "nft-ruleset": "table inet filter {\n chain input {\n type filter hook input priority 0; policy accept;\n }\n}\n",
            "unattended": "install ok installed\n",
        })
        self.assertEqual([l["port"] for l in facts["exposed_listeners"]], ["22"])
        self.assertEqual({x["id"]: x["severity"] for x in f}["custom:no-firewall"], "medium")

    def test_security_updates_are_high(self):
        f, _ = self.findings({
            "apt-upgradable": "Listing...\nopenssl/trixie-security 3.5.1 amd64 [upgradable from: 3.5.0]\n",
            "unattended": "",
        })
        sev = {x["id"]: x["severity"] for x in f}
        self.assertEqual(sev["custom:security-updates"], "high")
        self.assertEqual(sev["custom:no-unattended-upgrades"], "medium")

    def test_missing_collector_output_is_not_a_finding(self):
        # A command that did not run (no sshd, no apt: non-Debian host) must not
        # be read as "empty = clean" or "empty = bad".
        f, facts = self.findings({})
        ids = {x["id"] for x in f}
        self.assertNotIn("custom:ssh-password-auth", ids)
        self.assertNotIn("custom:no-unattended-upgrades", ids)
        self.assertIsNone(facts["unattended_upgrades"])

    def test_ipv6_any_published_port(self):
        f, _ = self.findings({"docker-published": "web\t:::8080->80/tcp\n"})
        self.assertIn("custom:docker-published:web", {x["id"] for x in f})

    def test_mixed_kernel_names_do_not_crash(self):
        f, _ = self.findings({"kernel-running": "6.12.48-1-amd64\n",
                              "kernels-installed": "6.12.48+deb13-amd64\n6.12.48-1-amd64\n"})
        self.assertIsInstance(f, list)


class TrivyTests(unittest.TestCase):
    def test_only_fixed_status_counts_as_fixable(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.json"
            p.write_text(json.dumps(TRIVY))
            summary, findings = S.trivy_summary(p, "host packages", "host")
        self.assertEqual([v["id"] for v in summary["fixable_critical_high"]], ["CVE-1"])
        self.assertEqual(summary["unfixed_critical_high"], {"critical": 0, "high": 1})
        self.assertEqual({f["severity"] for f in findings}, {"critical", "info"})


    def test_trivy_host_without_os_or_packages_is_a_failure(self):
        base = {"os": "debian 13.7", "packages": 700}
        self.assertIsNone(S.trivy_host_problem(base, "766\n"))
        self.assertIn("did not detect", S.trivy_host_problem({**base, "os": None}, "766"))
        self.assertIn("0 packages", S.trivy_host_problem({**base, "packages": 0}, "766"))
        self.assertIn("dpkg lists", S.trivy_host_problem({**base, "packages": 100}, "766"))

    def test_trivy_host_coverage_downgraded_when_os_missing(self):
        no_os = {"Results": [{"Target": "x", "Packages": [{"Name": "a"}]}]}
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d), coverage={"trivy-host": "ok"}, trivy=no_os))
        cov = next(c for c in s["coverage"] if c["check"] == "trivy-host")
        self.assertEqual(cov["status"], "failed")


class CoverageAndThresholdTests(unittest.TestCase):
    def test_partial_coverage_is_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            s = S.build(make_report(Path(d), coverage={"lynis": "ok", "custom": "ok", "trivy-images": "partial"}))
        self.assertFalse(s["coverage_complete"])

    def test_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            out = make_report(Path(d), host_files={"groups-priv": "docker:x:999:alice\n",
                                                   "unattended": "install ok installed\n"})
            S.main(["summarize.py", str(out)])
            self.assertTrue((out / "summary.md").read_text().startswith("# Security audit — web-01"))
            self.assertEqual(S.check_threshold("high", out / "summary.json"), 2)
            self.assertEqual(S.check_threshold("critical", out / "summary.json"), 0)
            self.assertEqual(S.check_threshold("HIGH", out / "summary.json"), 2)
            self.assertEqual(S.check_threshold("crit", out / "summary.json"), 1)


if __name__ == "__main__":
    unittest.main()
