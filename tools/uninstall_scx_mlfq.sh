#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# scx_mlfq beta uninstaller for CachyOS (sched_ext).
#
# Manifest-driven removal. This script does NOTHING unless the installer's
# manifest exists at /usr/lib/scx/scx_mlfq-beta.manifest; it never touches
# files that the installer did not create or record. It restores a
# package-owned binary from the recorded backup when the installed beta
# binary is still in place, and otherwise leaves the binary alone. It
# removes only the installer's own drop-in, backup, and manifest, then
# reloads systemd. scx_loader.service, /etc/default/scx and scx.service
# itself are never modified, disabled, or removed.
#
# The manifest is parsed strictly: duplicate keys, unknown keys, and values
# containing control characters abort the run. Every path read from the
# manifest is canonicalized and confined to its expected directory before
# use, and the drop-in is removed only if its content byte-matches what the
# installer writes.
#
# When the scheduler detaches (either because scx.service is stopped or
# because the binary is replaced), the kernel reverts to CFS automatically.
#
# Usage: sudo bash uninstall_scx_mlfq.sh [options]
#
# Options:
#   --force      Skip confirmation prompts
#   --dry-run    Read the manifest and print every action without changing
#                the system
#   --help, -h   Print this help text and exit

set -euo pipefail

BIN_NAME="scx_mlfq"
BIN_PATH="/usr/bin/scx_mlfq"
LIB_DIR="/usr/lib/scx"
MANIFEST="$LIB_DIR/scx_mlfq-beta.manifest"
BACKUP_PATH="$LIB_DIR/scx_mlfq.scx_mlfq-beta.bak"
DROPIN_DIR="/etc/systemd/system/scx.service.d"
DROPIN="$DROPIN_DIR/scx_mlfq-beta.conf"

FORCE=""
DRY_RUN=""
BINARY_STATE=""
DROPIN_STATE=""
BACKUP_STATE=""
DROPIN_BACKUP_STATE=""
QKK_RESULT=""

info()  { printf '[INFO]  %s\n' "$1"; }
ok()    { printf '[ OK ]  %s\n' "$1"; }
warn()  { printf '[WARN]  %s\n' "$1"; }
err()   { printf '[ERR ]  %s\n' "$1" >&2; }
step()  { printf '\n---- %s ----\n' "$1"; }
dry()   { printf '[DRY ]  %s\n' "$1"; }

# sanitize: replace control characters with '?' so untrusted values cannot
# inject terminal escapes or break line-oriented output.
sanitize() {
    printf '%s' "$1" | tr '[:cntrl:]' '?'
}

# our_dropin: the exact bytes this installer owns for the scx.service drop-in.
our_dropin() {
    printf '[Service]\nExecStart=\nExecStart=/usr/bin/scx_mlfq\n'
}

usage() {
    cat <<'EOF'
scx_mlfq beta uninstaller for CachyOS

Usage: sudo bash uninstall_scx_mlfq.sh [options]

Options:
  --force      Skip confirmation prompts
  --dry-run    Read the manifest and print every action without changing
               the system
  --help, -h   Print this help text and exit.
EOF
}

# run(): execute a command, or print it under --dry-run. Never uses eval.
run() {
    if [ -n "$DRY_RUN" ]; then
        dry "$*"
        return 0
    fi
    "$@"
}

sha256_of() {
    local f="$1"
    if [ -f "$f" ]; then
        sha256sum "$f" 2>/dev/null | awk '{print $1}'
    fi
}

# parse_manifest: strict key=value parser. Duplicate keys, unknown keys,
# and values with control characters are rejected. Populates the globals
# used by the rest of the script. Returns non-zero on any malformed line.
parse_manifest() {
    local line key value seen=""

    MANIFEST_VERSION=""
    NAME=""
    VERSION=""
    INSTALLED_SHA256=""
    ORIG_OWNER=""
    ORIG_SHA256=""
    BACKUP=""
    DROPINS=""
    DROPIN_BACKUP=""
    INSTALL_TIME=""
    SOURCE=""
    BRANCH=""

    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        case "$line" in
            *=*) ;;
            *)
                err "manifest line is missing '=': $(sanitize "$line")"
                return 1
                ;;
        esac
        key=${line%%=*}
        value=${line#*=}
        case "$key" in
            *[!A-Za-z0-9_]*)
                err "manifest contains an invalid key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case "$value" in
            *[$'\t\n\r\v\f']*)
                err "manifest value for '$key' contains control characters"
                return 1
                ;;
        esac
        case "$key" in
            manifest_version|name|version|installed_sha256|orig_owner|orig_sha256|backup_path|dropins|dropin_backup|install_time|source|branch) ;;
            *)
                err "manifest contains an unknown key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case " $seen " in
            *" $key "*)
                err "manifest contains duplicate key: $key"
                return 1
                ;;
        esac
        seen="$seen $key"
        case "$key" in
            manifest_version) MANIFEST_VERSION="$value" ;;
            name) NAME="$value" ;;
            version) VERSION="$value" ;;
            installed_sha256) INSTALLED_SHA256="$value" ;;
            orig_owner) ORIG_OWNER="$value" ;;
            orig_sha256) ORIG_SHA256="$value" ;;
            backup_path) BACKUP="$value" ;;
            dropins) DROPINS="$value" ;;
            dropin_backup) DROPIN_BACKUP="$value" ;;
            install_time) INSTALL_TIME="$value" ;;
            source) SOURCE="$value" ;;
            branch) BRANCH="$value" ;;
        esac
    done < "$MANIFEST"
}

confirm() {
    [ -n "$FORCE" ] && return 0
    printf '%s [y/N]: ' "$1" >&2
    if ! read -r _ans; then
        warn 'no input available; assuming "n"'
        return 1
    fi
    case "$_ans" in
        y|Y) return 0 ;;
        *)   return 1 ;;
    esac
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "must be run as root (EUID=$EUID)"
        printf '  try:  sudo bash %s\n' "$0"
        exit 1
    fi
}

stop_scx_service() {
    if systemctl is-active --quiet scx 2>/dev/null; then
        run systemctl stop scx.service || true
        ok 'scx.service stopped'
    else
        info 'scx.service is not active; nothing to stop'
    fi
    info 'scx.service is NOT disabled and NOT removed (only our drop-in is removed)'
}

restore_or_remove_binary() {
    local CURRENT_SHA RESTORED_SHA

    CURRENT_SHA=$(sha256_of "$BIN_PATH")

    if [ "$ORIG_OWNER" != "none" ]; then
        info "recorded owner: $ORIG_OWNER (original was package-owned)"
        if [ -n "$CURRENT_SHA" ] && [ "$CURRENT_SHA" = "$INSTALLED_SHA256" ]; then
            # Our beta binary is still in place; restore the package file.
            # BACKUP was verified regular (not a symlink) before we got here.
            run mv -f "$BACKUP" "$BIN_PATH"
            if [ ! -f "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
                err "$BIN_PATH is missing or a symlink after restore; refusing to chmod"
                exit 1
            fi
            run chmod 755 "$BIN_PATH"
            RESTORED_SHA=$(sha256_of "$BIN_PATH")
            if [ "$RESTORED_SHA" = "$ORIG_SHA256" ]; then
                ok "$BIN_PATH restored from backup (sha256 verified against the manifest)"
            else
                warn "$BIN_PATH restored, but its sha256 differs from the recorded original"
                warn "  restored: $RESTORED_SHA"
                warn "  recorded: $ORIG_SHA256"
                warn "  repair with:  sudo pacman -S --force $ORIG_OWNER"
            fi
            BINARY_STATE="restored"
        else
            # Current file differs (package already re-placed it, or it is gone).
            warn 'current binary differs from the beta this installer put in place; not touching it'
            if [ -n "$CURRENT_SHA" ]; then
                warn "  current:  $CURRENT_SHA"
                warn "  recorded: $INSTALLED_SHA256"
            else
                warn "  $BIN_PATH is absent"
            fi
            BINARY_STATE="left untouched"
        fi
        return 0
    fi

    # orig_owner == none
    info 'recorded owner: none (file was not package-owned)'
    if [ -f "$BIN_PATH" ] && [ "$CURRENT_SHA" = "$INSTALLED_SHA256" ]; then
        run rm -f "$BIN_PATH"
        ok "$BIN_PATH removed"
        BINARY_STATE="removed"
    elif [ -f "$BIN_PATH" ]; then
        warn 'current binary differs from the beta this installer put in place; leaving it'
        warn "  current:  $CURRENT_SHA"
        warn "  recorded: $INSTALLED_SHA256"
        BINARY_STATE="left untouched (sha mismatch)"
    else
        info "$BIN_PATH is already absent"
        BINARY_STATE="absent"
    fi
}

verify_package() {
    if [ "$ORIG_OWNER" = "none" ]; then
        QKK_RESULT="n/a"
        return 0
    fi
    if [ -n "$DRY_RUN" ]; then
        dry "pacman -Qkk $ORIG_OWNER"
        QKK_RESULT="skipped (dry-run)"
        return 0
    fi
    if pacman -Qkk "$ORIG_OWNER" 2>&1; then
        ok "pacman -Qkk $ORIG_OWNER: no problems reported"
        QKK_RESULT="OK"
    else
        warn "pacman -Qkk $ORIG_OWNER reported problems (see output above)"
        QKK_RESULT="problems reported"
    fi
}

remove_dropin() {
    local _leftover

    if [ -f "$DROPIN" ]; then
        if [ -r "$DROPIN" ] && cmp -s "$DROPIN" <(our_dropin); then
            run rm -f "$DROPIN"
            ok "removed drop-in $DROPIN"
            DROPIN_STATE="removed"
        else
            warn "drop-in $DROPIN does not byte-match the content this installer writes; leaving it"
            DROPIN_STATE="left (content mismatch)"
        fi
    else
        info "drop-in not present: $DROPIN"
        DROPIN_STATE="absent"
    fi
    # Remove the parent directory only if it is now empty; never force it.
    if [ -d "$DROPIN_DIR" ]; then
        _leftover=$(ls -A "$DROPIN_DIR" 2>/dev/null || true)
        if [ -z "$_leftover" ]; then
            run rmdir "$DROPIN_DIR" || true
        else
            info "leaving non-empty $DROPIN_DIR (other drop-ins present)"
        fi
    fi
}

remove_dropin_backup() {
    if [ -f "$DROPIN_BACKUP" ] && [ ! -L "$DROPIN_BACKUP" ]; then
        run rm -f "$DROPIN_BACKUP"
        ok "removed drop-in backup $DROPIN_BACKUP"
        DROPIN_BACKUP_STATE="removed"
    elif [ -e "$DROPIN_BACKUP" ]; then
        warn "drop-in backup at $DROPIN_BACKUP is a symlink or special file; not removing it"
        DROPIN_BACKUP_STATE="left (symlink or special file)"
    else
        info "drop-in backup not present: $DROPIN_BACKUP"
        DROPIN_BACKUP_STATE="absent"
    fi
}

remove_backup() {
    if [ -f "$BACKUP" ] && [ ! -L "$BACKUP" ]; then
        run rm -f "$BACKUP"
        ok "removed backup $BACKUP"
        BACKUP_STATE="removed"
    elif [ -e "$BACKUP" ]; then
        warn "backup at $BACKUP is a symlink or special file; not removing it"
        BACKUP_STATE="left (symlink or special file)"
    else
        info "backup not present: $BACKUP"
        BACKUP_STATE="absent"
    fi
}

remove_manifest() {
    if [ -f "$MANIFEST" ]; then
        run rm -f "$MANIFEST"
        ok "removed manifest $MANIFEST"
    else
        info "manifest not present: $MANIFEST"
    fi
}

summary() {
    printf '\n'
    printf '=== Uninstall summary ===\n'
    printf '  %-24s %s\n' 'Manifest:' 'removed'
    printf '  %-24s %s\n' "Binary $BIN_PATH:" "$BINARY_STATE"
    printf '  %-24s %s\n' 'Backup:' "$BACKUP_STATE"
    printf '  %-24s %s\n' 'Drop-in:' "$DROPIN_STATE"
    printf '  %-24s %s\n' 'scx.service:' 'left in place (not disabled)'
    if [ -n "$DROPIN_BACKUP" ]; then
        printf '  %-24s %s\n' 'Drop-in backup:' "$DROPIN_BACKUP_STATE"
    fi
    if [ "$ORIG_OWNER" != "none" ]; then
        printf '  %-24s %s\n' 'Package owner:' "$ORIG_OWNER"
        printf '  %-24s %s\n' 'pacman -Qkk:' "$QKK_RESULT"
    fi
    printf '\n'
    printf 'Note: the sched_ext scheduler is now detached; the kernel has\n'
    printf 'reverted to CFS automatically.\n'
    printf '\n'
}

main() {
    step 'scx_mlfq beta uninstaller for CachyOS'
    check_root

    if [ ! -f "$MANIFEST" ]; then
        printf '\nNothing to uninstall: no manifest at %s.\n' "$MANIFEST"
        printf 'This script only removes files recorded by the %s installer;\n' "$BIN_NAME"
        printf 'no files were touched.\n'
        exit 0
    fi

    if [ -n "$DRY_RUN" ]; then
        warn 'DRY-RUN: reading the manifest and printing actions only; no changes.'
    fi

    if ! parse_manifest; then
        err 'refusing to touch any file; inspect the manifest manually:'
        err "  cat $MANIFEST"
        exit 1
    fi

    if [ -n "$MANIFEST_VERSION" ] && [ "$MANIFEST_VERSION" != "1" ]; then
        warn "manifest_version=$MANIFEST_VERSION is not 1; proceeding conservatively"
    fi
    if [ -n "$NAME" ] && [ "$NAME" != "$BIN_NAME" ]; then
        warn "manifest name=$NAME does not match $BIN_NAME; proceeding conservatively"
    fi
    if [ -n "$VERSION" ] || [ -n "$INSTALL_TIME" ] || [ -n "$SOURCE" ] || [ -n "$BRANCH" ]; then
        info "manifest record: version=${VERSION:-unknown} install_time=${INSTALL_TIME:-unknown} source=${SOURCE:-unknown} branch=${BRANCH:-unknown}"
    fi

    if [ -z "$INSTALLED_SHA256" ] || [ -z "$ORIG_OWNER" ]; then
        err "manifest $MANIFEST is missing required fields (installed_sha256, orig_owner)"
        err 'refusing to touch any file; inspect the manifest manually:'
        err "  cat $MANIFEST"
        exit 1
    fi

    [ -n "$BACKUP" ] || BACKUP="$BACKUP_PATH"
    [ -n "$DROPINS" ] || DROPINS="$DROPIN"

    # HIGH-1: confine and canonicalize every path read from the manifest.
    # The lexical prefix check alone is bypassable with '..' components, so
    # the string guard plus realpath plus a re-check confine it for real.
    case "$BACKUP" in
        *'/../'*|*'/./'*|*$'\n'*|*$'\r'*)
            err 'refusing manifest backup path containing traversal or control characters'
            exit 1
            ;;
    esac
    BACKUP_REAL=$(realpath -m -- "$BACKUP") || exit 1
    case "$BACKUP_REAL" in
        /usr/lib/scx/*) ;;
        *)
            err "refusing unexpected backup path in manifest: $(sanitize "$BACKUP")"
            exit 1
            ;;
    esac

    case "$DROPINS" in
        *'/../'*|*'/./'*|*$'\n'*|*$'\r'*)
            err 'refusing manifest drop-in path containing traversal or control characters'
            exit 1
            ;;
    esac
    DROPINS_REAL=$(realpath -m -- "$DROPINS") || exit 1
    case "$DROPINS_REAL" in
        /etc/systemd/system/scx.service.d/scx_mlfq-beta.conf)
            DROPIN="$DROPINS"
            ;;
        *)
            err "refusing unexpected drop-in path in manifest: $(sanitize "$DROPINS")"
            exit 1
            ;;
    esac

    if [ -n "$DROPIN_BACKUP" ]; then
        case "$DROPIN_BACKUP" in
            *'/../'*|*'/./'*|*$'\n'*|*$'\r'*)
                err 'refusing manifest drop-in backup path containing traversal or control characters'
                exit 1
                ;;
        esac
        DROPIN_BACKUP_REAL=$(realpath -m -- "$DROPIN_BACKUP") || exit 1
        case "$DROPIN_BACKUP_REAL" in
            /usr/lib/scx/*) ;;
            *)
                err "refusing unexpected drop-in backup path in manifest: $(sanitize "$DROPIN_BACKUP")"
                exit 1
                ;;
        esac
    fi

    # The backup is used whenever the installer replaced a package-owned
    # file: it must then be a regular file, never a symlink. Unowned
    # installs record the path but never create the file.
    if [ "$ORIG_OWNER" != "none" ]; then
        if [ ! -f "$BACKUP" ] || [ -L "$BACKUP" ]; then
            err "backup is missing or is a symlink: $BACKUP"
            exit 1
        fi
    fi

    if ! confirm 'This stops scx.service (if active) and removes the beta files. Continue?'; then
        info 'uninstall cancelled'
        exit 0
    fi

    step 'Stopping scx.service'
    stop_scx_service

    step 'Restoring or removing the binary'
    restore_or_remove_binary

    step 'Verifying package integrity'
    verify_package

    step 'Removing our systemd drop-in'
    remove_dropin

    if [ -n "$DROPIN_BACKUP" ]; then
        step 'Removing our drop-in backup'
        remove_dropin_backup
    fi

    step 'Removing our backup'
    remove_backup

    step 'Removing our manifest'
    remove_manifest

    step 'Reloading systemd'
    run systemctl daemon-reload || warn 'systemctl daemon-reload failed'

    summary
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)
            FORCE="1"
            shift
            ;;
        --dry-run)
            DRY_RUN="1"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            err "unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

main
