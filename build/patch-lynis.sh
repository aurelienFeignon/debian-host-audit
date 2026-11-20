#!/bin/sh
# Patch Lynis so that, when LYNIS_TMPDIR is set, its temp files and PID file go
# there instead of the audited host's /tmp and /var/run.
#
# Lynis runs inside the host mount namespace; without this patch it writes
# /tmp/lynis.XXXXXXXXXX and /var/run/lynis.pid on the audited host. With
# LYNIS_TMPDIR unset, behaviour is unchanged (upstream defaults).
#
# Each substitution is checked: if upstream changes these lines, the build
# fails here instead of silently writing to the host again.

set -eu
cd "${1:?lynis directory}"

subst() {  # subst <file> <sed expression> <pattern that must exist afterwards>
    sed -i "$2" "$1"
    grep -qF -- "$3" "$1" || { echo "patch-lynis: substitution failed in $1: $3" >&2; exit 1; }
}

# 1. temp files
subst include/functions \
    's|TEMP_FILE=$(mktemp /tmp/lynis.XXXXXXXXXX)|TEMP_FILE=$(mktemp "${LYNIS_TMPDIR:-/tmp}/lynis.XXXXXXXXXX")|' \
    'mktemp "${LYNIS_TMPDIR:-/tmp}/lynis.XXXXXXXXXX"'

# 2. temp file cleanup only accepts paths under the temp dir
#    (LYNIS_TMPDIR is set by bin/audit to a path without regex metacharacters)
subst include/functions \
    's#grep -E "^/tmp/lynis" | grep -v "\\.\\."#grep -E "^${LYNIS_TMPDIR:-/tmp}/lynis" | grep -v "\\.\\."#' \
    'grep -E "^${LYNIS_TMPDIR:-/tmp}/lynis"'

# 3. PID file
subst lynis \
    's|    elif \[ -d /var/run \]; then|    elif [ -n "${LYNIS_TMPDIR:-}" ]; then\n        PIDFILE="${LYNIS_TMPDIR}/lynis.pid"\n    elif [ -d /var/run ]; then|' \
    'PIDFILE="${LYNIS_TMPDIR}/lynis.pid"'

echo "patch-lynis: 3 substitutions applied"
