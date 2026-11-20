#!/usr/bin/env bash
# Audit one or more remote Debian 13 hosts over SSH and collect summary.json locally.
#
#   scripts/audit-remote.sh [--ship-image] [--sudo] [--out DIR] HOST... [-- AUDIT-ARGS...]
#
#   --ship-image   copy the local image to each host (docker save | ssh docker load) — no registry needed
#   --sudo         run docker through sudo on the remote host
#   --out DIR      where to write <host>.json locally (default: ./reports)
#   -- ARGS        passed to the audit command (default: all --images running)
#
# Raw files stay on each host under ~/host-audit-reports/ (owner-only).

set -euo pipefail

IMAGE=${IMAGE:-debian-host-audit:$(cat "$(dirname "$0")/../VERSION")}
SHIP=0
SUDO=
OUT=./reports
AUDIT_ARGS=(all)
HOSTS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --ship-image) SHIP=1 ;;
        --sudo) SUDO=sudo ;;
        --out) OUT=${2:?}; shift ;;
        --) shift; AUDIT_ARGS=("$@"); break ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) HOSTS+=("$1") ;;
    esac
    shift
done
[ ${#HOSTS[@]} -gt 0 ] || { echo "no host given" >&2; exit 1; }
mkdir -p "$OUT"

rc_all=0
for h in "${HOSTS[@]}"; do
    echo "== $h" >&2
    if [ "$SHIP" = 1 ]; then
        docker save "$IMAGE" | ssh "$h" "$SUDO docker load" >&2
    fi
    # shellcheck disable=SC2029  # AUDIT_ARGS are expanded locally on purpose
    if ssh "$h" "mkdir -p ~/host-audit-reports && chmod 700 ~/host-audit-reports && \
        $SUDO docker run --rm --privileged --pid=host -v /:/host:ro \
        -v ~/host-audit-reports:/reports $IMAGE ${AUDIT_ARGS[*]} --json" >"$OUT/$h.json"; then
        python3 -c "
import json,sys; s=json.load(open(sys.argv[1]))
print(f\"{s['run']['hostname']}: \" + ', '.join(f'{n} {k}' for k,n in s['counts'].items()) +
      ('' if s['coverage_complete'] else '  ⚠ coverage incomplete'))" "$OUT/$h.json" >&2
    else
        echo "!! $h: audit failed (see stderr above)" >&2
        rc_all=1
    fi
done
exit $rc_all
