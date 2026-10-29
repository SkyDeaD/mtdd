#!/usr/bin/env bash
# Hard gate: reject a static mtdd binary whose libcrypto was built without
# thread support.
#
# OpenSSL's Configure silently disables threads when it sees "-static" in
# LDFLAGS (Configure: disable('static', 'pic', 'threads')). A no-threads
# libcrypto compiles crypto/threads_none.c, where CRYPTO_THREAD_lock_new only
# stores an integer and CRYPTO_THREAD_write_lock only compares it. Concurrent
# handshakes then mutate shared provider/namemap state without locking and
# abort in free(). This gate inspects the final executable, so it catches a
# stale or misconfigured OpenSSL even when configdata.pm is not around.
#
# Usage:
#   tools/verify-static-locks.sh BINARY [OPENSSL_CONFIGDATA]
#   tools/verify-static-locks.sh --configdata-only OPENSSL_CONFIGDATA
set -Eeuo pipefail

die() { printf 'LOCK GATE FAILED: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

check_configdata() { # check_configdata <configdata.pm>
    local configdata=$1 options
    [[ -r $configdata ]] || die "OpenSSL configdata is not readable: $configdata"
    options=$(perl -ne 'if (/^\s*"options"\s*=>\s*"([^"]*)"/) { print $1; exit }' "$configdata")
    [[ -n $options ]] || die "cannot read the options list from $configdata"
    if grep -qw 'no-threads' <<<"$options"; then
        die "OpenSSL was configured with no-threads: $configdata"
    fi
    log "OpenSSL configdata has no no-threads option"
}

check_calls() { # check_calls <description> <disassembly> <callee>...
    local where=$1 body=$2 callee
    shift 2
    for callee in "$@"; do
        # musl exposes both pthread_* and __pthread_* entry points; static
        # links resolve to either spelling.
        if grep -Eq "call.*<(__)?$callee(@[^>]*)?>" <<<"$body"; then
            printf '    %s -> %s\n' "$where" "$callee"
            return 0
        fi
    done
    die "$where does not call any of: $* (OpenSSL built without thread support)"
}

check_symbol() { # check_symbol <nm-dump> <symbol>
    local symbols=$1 symbol=$2
    grep -qE "[[:space:]]$symbol\$" <<<"$symbols" \
        || die "symbol $symbol is missing (stripped or lto?); cannot verify thread locks"
}

disassemble() { # disassemble <binary> <symbol>
    local binary=$1 symbol=$2 body
    body=$(objdump -d --no-show-raw-insn --disassemble="$symbol" "$binary" 2>/dev/null) \
        || die "objdump failed to disassemble $symbol in $binary"
    [[ $body == *"<$symbol>:"* ]] || die "objdump did not emit $symbol for $binary"
    printf '%s\n' "$body"
}

if [[ ${1:-} == --configdata-only ]]; then
    (($# == 2)) || die "usage: $0 --configdata-only <configdata.pm>"
    check_configdata "$2"
    exit 0
fi

BIN=${1:-}
CONFIGDATA=${2:-}
[[ -n $BIN ]] || die "usage: $0 <binary> [configdata.pm]"
[[ -f $BIN ]] || die "binary not found: $BIN"
for tool in nm objdump perl; do
    command -v "$tool" >/dev/null 2>&1 || die "missing host tool: $tool"
done

if [[ -n $CONFIGDATA ]]; then
    check_configdata "$CONFIGDATA"
fi

log "inspecting OpenSSL thread primitives in $BIN"
SYMBOLS=$(nm "$BIN" 2>/dev/null) || die "nm cannot read symbols from $BIN"
check_symbol "$SYMBOLS" CRYPTO_THREAD_lock_new
check_symbol "$SYMBOLS" CRYPTO_THREAD_write_lock
check_symbol "$SYMBOLS" CRYPTO_THREAD_unlock

LOCK_NEW=$(disassemble "$BIN" CRYPTO_THREAD_lock_new)
WRITE_LOCK=$(disassemble "$BIN" CRYPTO_THREAD_write_lock)
UNLOCK=$(disassemble "$BIN" CRYPTO_THREAD_unlock)

# Linux builds of OpenSSL prefer rwlocks when PTHREAD_RWLOCK_INITIALIZER is
# available (musl provides it); mutexes are the fallback. Either is a real lock.
check_calls "CRYPTO_THREAD_lock_new" "$LOCK_NEW" \
    pthread_rwlock_init pthread_mutex_init
check_calls "CRYPTO_THREAD_write_lock" "$WRITE_LOCK" \
    pthread_rwlock_wrlock pthread_mutex_lock pthread_mutex_trylock
check_calls "CRYPTO_THREAD_unlock" "$UNLOCK" \
    pthread_rwlock_unlock pthread_mutex_unlock

printf '\n%s\n' "$LOCK_NEW"
printf '\n%s\n' "$WRITE_LOCK"
log "thread locks verified in $BIN"
