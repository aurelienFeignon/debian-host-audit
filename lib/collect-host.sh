#!/bin/sh
# Runs INSIDE the host namespaces (via nsenter), with the host's own binaries.
# Read-only: every command below only reads state. Raw output only — all
# interpretation happens in summarize.py, inside the container.
#
# Usage: collect-host.sh <output-dir>   (a container-private directory reached
#        through /proc/<container-pid>/root: nothing is written to the host disk)

out=${1:?output directory required}
mkdir -p "$out" || exit 1

# run <name> <command...> : stdout+stderr to <name>.txt, exit code to <name>.rc
run() {
    name=$1; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout 60 "$@" >"$out/$name.txt" 2>&1
    else
        "$@" >"$out/$name.txt" 2>&1
    fi
    echo $? >"$out/$name.rc"
}

has() { command -v "$1" >/dev/null 2>&1; }

run hostname        hostname
run os-release      cat /etc/os-release
run uname           uname -a
run kernel-running  uname -r
run kernels-installed sh -c 'ls -1 /boot/vmlinuz-* 2>/dev/null | sed "s|/boot/vmlinuz-||"'
run reboot-required sh -c 'if [ -e /run/reboot-required ]; then cat /run/reboot-required.pkgs 2>/dev/null; echo REBOOT_REQUIRED; fi'
run uid0            awk -F: '$3 == 0 { print $1 }' /etc/passwd
run groups-priv     sh -c 'for g in docker sudo adm lxd libvirt disk; do getent group "$g"; done'
run listening       ss -H -tulpn
run failed-units    systemctl --failed --no-legend --plain
run timers          systemctl list-timers --all --no-legend --plain

if has sshd; then
    run sshd-effective sshd -T
fi

# Package state, from the local apt cache only (no `apt update`: read-only).
# Debian family only: on other hosts these files are simply absent, and
# summarize.py treats an absent check as "not evaluated", never as a finding.
if has apt && has dpkg-query; then
    run apt-upgradable  sh -c 'apt list --upgradable 2>/dev/null'
    run apt-lists-age   sh -c 'stat -c %Y /var/lib/apt/lists/* 2>/dev/null | sort -n | tail -1; date +%s'
    run unattended      sh -c 'dpkg-query -W -f="\${Status}\n" unattended-upgrades 2>/dev/null; systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null; cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null'
fi

# Firewall
if has nft; then run nft-ruleset nft list ruleset; fi
if has iptables; then run iptables-input iptables -S INPUT; fi
if has ufw; then run ufw ufw status verbose; fi

# Docker (daemon config + published ports)
if has docker; then
    run docker-version docker version --format '{{.Server.Version}}'
    run docker-published sh -c "docker ps --format '{{.Names}}\t{{.Ports}}'"
    run docker-daemon-json cat /etc/docker/daemon.json
fi

# Mount options of sensitive mount points
run mounts sh -c 'findmnt -rno TARGET,OPTIONS /tmp /dev/shm /var/tmp /home 2>/dev/null'

exit 0
