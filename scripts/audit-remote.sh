#!/usr/bin/env bash
# Audit one or more remote Debian 13 hosts over SSH and collect summary.json locally.
#
#   scripts/audit-remote.sh [--ship-image] [--sudo] [--out DIR] HOST... [-- AUDIT-ARGS...]
#
#   --ship-image   copy the local image to each host (docker save | ssh docker load) — no registry needed
#   --sudo         run docker through sudo on the remote host
#   --out DIR      where to write <host>.json locally (default: ./reports)
#   -- ARGS        passed to the audit command (default: all)
#   IMAGE=...      env: image to run (default: ghcr.io/aurelienfeignon/debian-host-audit:<major.minor>,
#                  or the local debian-host-audit:<VERSION> with --ship-image)
#
# Raw files stay on each host under ~/host-audit-reports/ (owner-only).
# One host failing never stops the others. Exit status: 0 all reports produced,
# 2 all produced and at least one reached --fail-on, 1 at least one host failed.

set -uo pipefail
umask 077  # reports describe how to attack the host: owner-only

VERSION=$(cat "$(dirname "$0")/../VERSION")
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
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) HOSTS+=("$1") ;;
    esac
    shift
done
[ ${#HOSTS[@]} -gt 0 ] || { echo "no host given" >&2; exit 1; }
# Default image: the published one, or the local build when shipping it.
if [ "$SHIP" = 1 ]; then IMAGE=${IMAGE:-debian-host-audit:$VERSION}
else IMAGE=${IMAGE:-ghcr.io/aurelienfeignon/debian-host-audit:${VERSION%.*}}; fi
# umask does not reach a directory or report left by an earlier run.
mkdir -p "$OUT" && chmod 700 "$OUT"

failed=0
threshold=0
for h in "${HOSTS[@]}"; do
    echo "== $h" >&2
    if [ "$SHIP" = 1 ] && ! docker save "$IMAGE" | ssh "$h" "$SUDO docker load" >&2; then
        echo "!! $h: could not ship the image, skipped" >&2
        failed=$((failed + 1)); continue
    fi
    install -m 600 /dev/null "$OUT/$h.json"
    # shellcheck disable=SC2029  # AUDIT_ARGS are expanded locally on purpose
    ssh "$h" "mkdir -p ~/host-audit-reports && chmod 700 ~/host-audit-reports && \
        $SUDO docker run --rm --privileged --pid=host -v /:/host:ro \
        -v ~/host-audit-reports:/reports $IMAGE ${AUDIT_ARGS[*]} --json" >"$OUT/$h.json"
    rc=$?
    # 0 = report, 2 = report + --fail-on threshold reached; anything else = no usable report
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
        echo "!! $h: audit failed (exit $rc, see stderr above)" >&2
        failed=$((failed + 1)); continue
    fi
    [ "$rc" -eq 2 ] && threshold=$((threshold + 1))
    python3 -c "
import json,sys; s=json.load(open(sys.argv[1]))
print(f\"{s['run']['hostname']}: \" + ', '.join(f'{n} {k}' for k,n in s['counts'].items()) +
      ('' if s['coverage_complete'] else '  ⚠ coverage incomplete') +
      ('  ⛔ --fail-on threshold reached' if sys.argv[2] == '2' else ''))" "$OUT/$h.json" "$rc" >&2 \
        || { echo "!! $h: unreadable report $OUT/$h.json" >&2; failed=$((failed + 1)); }
done
echo "== ${#HOSTS[@]} hosts: $failed failed, $threshold over threshold" >&2
[ "$failed" -gt 0 ] && exit 1
[ "$threshold" -gt 0 ] && exit 2
exit 0
