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
# reloads systemd. The timestamped /etc/scx_loader.toml.bak.* files that
# the Kernel Manager leaves behind on every config rewrite are pruned
# down to the newest one, so repeated installs do not accumulate junk.
# scx_loader.service, /etc/default/scx and scx.service itself are never
# modified, disabled, or removed.
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
SCX_LOADER_CONFIG="/etc/scx_loader.toml"
LOADER_BIN="/usr/local/bin/scx_loader"
LOADER_DROPIN_DIR="/etc/systemd/system/scx_loader.service.d"
LOADER_DROPIN="$LOADER_DROPIN_DIR/mlfq-loader.conf"
LOADER_MANIFEST="$LIB_DIR/scx_mlfq-loader.manifest"
GUI_MANIFEST="$LIB_DIR/scx_mlfq-gui.manifest"
GUI_LIB="/usr/lib/libscxctl-ui.so.1.15.12"

FORCE=""
DRY_RUN=""
BINARY_STATE=""
DROPIN_STATE=""
BACKUP_STATE=""
DROPIN_BACKUP_STATE=""
QKK_RESULT=""
LOADER_BAK_STATE=""

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
    LOADER_ENTRY=""
    LOADER_BIN_MF=""
    LOADER_DROPIN_MF=""
    LOADER_SHA256=""
    LOADER_VERSION=""
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
            manifest_version|name|version|installed_sha256|orig_owner|orig_sha256|backup_path|dropins|dropin_backup|loader_entry|loader_bin|loader_dropin|loader_sha256|loader_version|install_time|source|branch) ;;
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
            loader_entry) LOADER_ENTRY="$value" ;;
            loader_bin) LOADER_BIN_MF="$value" ;;
            loader_dropin) LOADER_DROPIN_MF="$value" ;;
            loader_sha256) LOADER_SHA256="$value" ;;
            loader_version) LOADER_VERSION="$value" ;;
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

# remove_loader_entry: drop the [scheds.scx_mlfq] section the installer
# appended to the scx_loader config. Only a section recorded in the
# manifest is touched; the rest of the config is preserved byte for byte.
remove_loader_entry() {
    local _tmp

    if [ "$LOADER_ENTRY" != "1" ]; then
        info 'no scx_loader entry recorded in the manifest; nothing to remove'
        LOADER_ENTRY_STATE="none recorded"
        return 0
    fi
    if [ ! -f "$SCX_LOADER_CONFIG" ]; then
        warn "$SCX_LOADER_CONFIG is absent; nothing to remove"
        LOADER_ENTRY_STATE="config absent"
        return 0
    fi
    if ! grep -q '^\[scheds\.scx_mlfq\]$' "$SCX_LOADER_CONFIG" 2>/dev/null; then
        info "no [scheds.scx_mlfq] section in $SCX_LOADER_CONFIG"
        LOADER_ENTRY_STATE="absent"
        return 0
    fi

    if [ -n "$DRY_RUN" ]; then
        dry "remove the [scheds.scx_mlfq] section from $SCX_LOADER_CONFIG"
        LOADER_ENTRY_STATE="would remove"
        return 0
    fi

    _tmp=$(mktemp "${SCX_LOADER_CONFIG}.scx_mlfq.XXXXXX") || {
        err "cannot create a temp file next to $SCX_LOADER_CONFIG"
        exit 1
    }
    awk '
        $0 == "[scheds.scx_mlfq]" { skip = 1; next }
        skip && /^\[/ { skip = 0 }
        skip { next }
        { print }
    ' "$SCX_LOADER_CONFIG" > "$_tmp"
    chmod --reference="$SCX_LOADER_CONFIG" "$_tmp"
    mv -f -- "$_tmp" "$SCX_LOADER_CONFIG"
    ok "removed the [scheds.scx_mlfq] section from $SCX_LOADER_CONFIG"
    LOADER_ENTRY_STATE="removed"

    if systemctl is-active --quiet scx_loader 2>/dev/null; then
        run systemctl restart scx_loader             || warn 'scx_loader restart failed; the GUI updates after the next loader start'
    fi
}

# remove_mlfq_default: the Kernel Manager GUI writes
# default_sched = "scx_mlfq" into the loader config when scx_mlfq is
# applied as the default scheduler. The stock loader rejects the whole
# config file when the default scheduler is an unknown variant, so the
# line must be removed when scx_mlfq leaves the system.
remove_mlfq_default() {
    if [ ! -f "$SCX_LOADER_CONFIG" ]; then
        LOADER_DEFAULT_STATE="no config"
        return 0
    fi
    if ! grep -E '^default_sched[[:space:]]*=[[:space:]]*["'"'"']scx_mlfq["'"'"'][[:space:]]*$'          "$SCX_LOADER_CONFIG" >/dev/null 2>&1; then
        LOADER_DEFAULT_STATE="absent"
        return 0
    fi

    if [ -n "$DRY_RUN" ]; then
        dry "remove the default_sched = \"scx_mlfq\" line from $SCX_LOADER_CONFIG"
        LOADER_DEFAULT_STATE="would remove"
        return 0
    fi

    sed -i '/^default_sched[[:space:]]*=[[:space:]]*["'"'"']scx_mlfq["'"'"'][[:space:]]*$/d'         "$SCX_LOADER_CONFIG"
    ok "removed the default_sched = \"scx_mlfq\" line from $SCX_LOADER_CONFIG"
    LOADER_DEFAULT_STATE="removed"
}

# prune_loader_config_backups: the Kernel Manager rewrites
# /etc/scx_loader.toml with a timestamped backup on every apply and
# never prunes them.  Keep the newest file so the previous config can
# still be restored by hand, and remove the rest.
prune_loader_config_backups() {
    local bak keep="" removed=0

    for bak in /etc/scx_loader.toml.bak.*; do
        [ -f "$bak" ] && [ ! -L "$bak" ] || continue
        if [ -z "$keep" ] || [[ "$bak" > "$keep" ]]; then
            keep="$bak"
        fi
    done

    if [ -z "$keep" ]; then
        info 'no scx_loader config backups to prune'
        LOADER_BAK_STATE="none"
        return 0
    fi

    for bak in /etc/scx_loader.toml.bak.*; do
        [ -f "$bak" ] && [ ! -L "$bak" ] || continue
        if [ "$bak" != "$keep" ]; then
            run rm -f -- "$bak"
            removed=$((removed + 1))
        fi
    done

    if [ "$removed" -eq 0 ]; then
        info "the newest scx_loader config backup is already the only one: $keep"
        LOADER_BAK_STATE="newest only"
    else
        ok "pruned $removed stale scx_loader config backup(s), kept $keep"
        LOADER_BAK_STATE="pruned $removed, kept newest"
    fi
}

# our_loader_dropin: the exact bytes the loader installer owns for the
# scx_loader.service override.
our_loader_dropin() {
    printf '[Service]\nExecStart=\nExecStart=%s\n' "$LOADER_BIN"
}

# parse_loader_manifest: strict key=value parser for the loader manifest.
# Duplicate keys, unknown keys, and values with control characters are
# rejected. Populates the LOADER_* globals used by remove_loader_patch().
parse_loader_manifest() {
    local line key value seen=""

    LOADER_BIN_MF=""
    LOADER_DROPIN_MF=""
    LOADER_SHA256=""
    LOADER_VERSION=""

    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        case "$line" in
            *=*) ;;
            *)
                err "loader manifest line is missing '=': $(sanitize "$line")"
                return 1
                ;;
        esac
        key=${line%%=*}
        value=${line#*=}
        case "$key" in
            *[!A-Za-z0-9_]*)
                err "loader manifest contains an invalid key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case "$value" in
            *[$'\t\n\r\v\f']*)
                err "loader manifest value for '$key' contains control characters"
                return 1
                ;;
        esac
        case "$key" in
            name|version|loader_bin|loader_dropin|loader_sha256|loader_dropin_backup|install_time) ;;
            *)
                err "loader manifest contains an unknown key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case " $seen " in
            *" $key "*)
                err "loader manifest contains duplicate key: $key"
                return 1
                ;;
        esac
        seen="$seen $key"
        case "$key" in
            loader_bin) LOADER_BIN_MF="$value" ;;
            loader_dropin) LOADER_DROPIN_MF="$value" ;;
            loader_sha256) LOADER_SHA256="$value" ;;
            loader_version) LOADER_VERSION="$value" ;;
        esac
    done < "$LOADER_MANIFEST"
}

# remove_loader_patch: undo the patched-loader install. The drop-in is
# removed only when it byte-matches the content the loader installer
# writes; the binary only when its sha256 matches the manifest record.
# The stock loader then takes over at the next service start.
remove_loader_patch() {
    if [ -z "$LOADER_BIN_MF" ] && [ -z "$LOADER_DROPIN_MF" ]; then
        info 'no patched loader recorded in the manifest; nothing to remove'
        LOADER_BIN_STATE="none recorded"
        LOADER_DROPIN_STATE="none recorded"
        return 0
    fi

    if [ -n "$LOADER_BIN_MF" ]; then
        if [ -f "$LOADER_BIN" ] && [ -n "$LOADER_SHA256" ]            && [ "$(sha256_of "$LOADER_BIN")" = "$LOADER_SHA256" ]; then
            run rm -f "$LOADER_BIN"
            ok "removed patched loader $LOADER_BIN"
            LOADER_BIN_STATE="removed"
        elif [ -e "$LOADER_BIN" ]; then
            warn "$LOADER_BIN differs from the recorded patched loader; leaving it"
            LOADER_BIN_STATE="left (sha mismatch)"
        else
            info "$LOADER_BIN is already absent"
            LOADER_BIN_STATE="absent"
        fi
    fi

    if [ -n "$LOADER_DROPIN_MF" ]; then
        if [ -f "$LOADER_DROPIN" ] && cmp -s "$LOADER_DROPIN" <(our_loader_dropin); then
            run rm -f "$LOADER_DROPIN"
            ok "removed loader drop-in $LOADER_DROPIN"
            LOADER_DROPIN_STATE="removed"
        elif [ -e "$LOADER_DROPIN" ]; then
            warn "loader drop-in $LOADER_DROPIN does not byte-match the content the loader installer writes; leaving it"
            LOADER_DROPIN_STATE="left (content mismatch)"
        else
            info "loader drop-in not present: $LOADER_DROPIN"
            LOADER_DROPIN_STATE="absent"
        fi
        # Remove the parent directory only if it is now empty.
        if [ -d "$LOADER_DROPIN_DIR" ] && [ -z "$(ls -A "$LOADER_DROPIN_DIR" 2>/dev/null || true)" ]; then
            run rmdir "$LOADER_DROPIN_DIR" || true
        fi
    fi

    if [ -n "$LOADER_BIN_STATE" ] && [ -n "$LOADER_DROPIN_STATE" ]        && { [ "$LOADER_BIN_STATE" = "removed" ] || [ "$LOADER_BIN_STATE" = "absent" ]; }        && { [ "$LOADER_DROPIN_STATE" = "removed" ] || [ "$LOADER_DROPIN_STATE" = "absent" ]; }; then
        if systemctl is-active --quiet scx_loader 2>/dev/null; then
            # The drop-in that pointed at the patched loader is gone; reload
            # the unit first so the restart uses the stock ExecStart.
            run systemctl daemon-reload || true
            run systemctl restart scx_loader                 || warn 'scx_loader restart failed; the stock loader takes over at the next start'
        fi
    fi
}

# parse_gui_manifest: strict key=value parser for the GUI manifest.
# Same discipline as the beta and loader manifests.
parse_gui_manifest() {
    local line key value seen=""

    GUI_LIB_MF=""
    GUI_BACKUP_MF=""
    GUI_SHA256=""
    GUI_ORIG_SHA256=""

    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        case "$line" in
            *=*) ;;
            *)
                err "GUI manifest line is missing '=': $(sanitize "$line")"
                return 1
                ;;
        esac
        key=${line%%=*}
        value=${line#*=}
        case "$key" in
            *[!A-Za-z0-9_]*)
                err "GUI manifest contains an invalid key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case "$value" in
            *[$'\t\n\r\v\f']*)
                err "GUI manifest value for '$key' contains control characters"
                return 1
                ;;
        esac
        case "$key" in
            name|version|gui_lib|gui_backup|gui_sha256|orig_owner|orig_sha256|install_time) ;;
            *)
                err "GUI manifest contains an unknown key: $(sanitize "$key")"
                return 1
                ;;
        esac
        case " $seen " in
            *" $key "*)
                err "GUI manifest contains duplicate key: $key"
                return 1
                ;;
        esac
        seen="$seen $key"
        case "$key" in
            gui_lib) GUI_LIB_MF="$value" ;;
            gui_backup) GUI_BACKUP_MF="$value" ;;
            gui_sha256) GUI_SHA256="$value" ;;
            orig_sha256) GUI_ORIG_SHA256="$value" ;;
        esac
    done < "$GUI_MANIFEST"
}

# restore_gui_lib: undo the GUI library replacement. The library is
# restored only when the backup is a regular file and the current library
# still matches the patched build recorded in the manifest; otherwise the
# package has already taken the file back and only the backup/manifest are
# removed.
restore_gui_lib() {
    local CURRENT_SHA GUI_LIB_REAL GUI_BACKUP_REAL RESTORED_SHA

    if [ -z "$GUI_LIB_MF" ] && [ -z "$GUI_BACKUP_MF" ]; then
        info 'no GUI library recorded in the manifest; nothing to restore'
        GUI_LIB_STATE="none recorded"
        return 0
    fi

    # Confine the recorded paths.
    case "$GUI_LIB_MF" in
        *'/../'*|*'/./'*|*$'\n'*|*$'\r'*)
            err 'refusing GUI manifest library path containing traversal or control characters'
            exit 1
            ;;
    esac
    GUI_LIB_REAL=$(realpath -m -- "$GUI_LIB_MF") || exit 1
    case "$GUI_LIB_REAL" in
        /usr/lib/libscxctl-ui.so.1.15.12) GUI_LIB="$GUI_LIB_MF" ;;
        *)
            err "refusing unexpected GUI library path in manifest: $(sanitize "$GUI_LIB_MF")"
            exit 1
            ;;
    esac
    case "$GUI_BACKUP_MF" in
        *'/../'*|*'/./'*|*$'\n'*|*$'\r'*)
            err 'refusing GUI manifest backup path containing traversal or control characters'
            exit 1
            ;;
    esac
    GUI_BACKUP_REAL=$(realpath -m -- "$GUI_BACKUP_MF") || exit 1
    case "$GUI_BACKUP_REAL" in
        /usr/lib/scx/*) GUI_BACKUP="$GUI_BACKUP_MF" ;;
        *)
            err "refusing unexpected GUI backup path in manifest: $(sanitize "$GUI_BACKUP_MF")"
            exit 1
            ;;
    esac

    CURRENT_SHA=$(sha256_of "$GUI_LIB")
    if [ -n "$CURRENT_SHA" ] && [ "$CURRENT_SHA" = "$GUI_SHA256" ]; then
        # Our patched library is still in place; restore the original.
        if [ ! -f "$GUI_BACKUP" ] || [ -L "$GUI_BACKUP" ]; then
            err "GUI backup is missing or is a symlink: $GUI_BACKUP"
            exit 1
        fi
        run mv -f "$GUI_BACKUP" "$GUI_LIB"
        if [ ! -f "$GUI_LIB" ] || [ -L "$GUI_LIB" ]; then
            err "$GUI_LIB is missing or a symlink after restore; refusing to chmod"
            exit 1
        fi
        run chmod 755 "$GUI_LIB"
        RESTORED_SHA=$(sha256_of "$GUI_LIB")
        if [ -n "$GUI_ORIG_SHA256" ] && [ "$RESTORED_SHA" = "$GUI_ORIG_SHA256" ]; then
            ok "$GUI_LIB restored from backup (sha256 verified against the manifest)"
        else
            warn "$GUI_LIB restored, but its sha256 differs from the recorded original"
        fi
        GUI_LIB_STATE="restored"
    else
        warn 'current GUI library differs from the patched build this installer put in place; not touching it'
        if [ -n "$CURRENT_SHA" ]; then
            warn "  current:  $CURRENT_SHA"
            warn "  recorded: $GUI_SHA256"
        else
            warn "  $GUI_LIB is absent"
        fi
        if [ -f "$GUI_BACKUP" ] && [ ! -L "$GUI_BACKUP" ]; then
            run rm -f "$GUI_BACKUP"
            ok "removed GUI backup $GUI_BACKUP"
        fi
        GUI_LIB_STATE="left untouched"
    fi
    run rm -f "$GUI_MANIFEST"
    ok "removed GUI manifest $GUI_MANIFEST"
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
    printf '  %-24s %s\n' 'scx_loader entry:' "$LOADER_ENTRY_STATE"
    printf '  %-24s %s\n' 'mlfq default:' "$LOADER_DEFAULT_STATE"
    printf '  %-24s %s\n' 'Loader config backups:' "$LOADER_BAK_STATE"
    printf '  %-24s %s\n' 'Patched loader:' "$LOADER_BIN_STATE"
    printf '  %-24s %s\n' 'Loader drop-in:' "$LOADER_DROPIN_STATE"
    printf '  %-24s %s\n' 'GUI library:' "$GUI_LIB_STATE"
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

    if [ ! -f "$MANIFEST" ] && [ ! -f "$LOADER_MANIFEST" ] && [ ! -f "$GUI_MANIFEST" ]; then
        printf '\nNothing to uninstall: no beta, loader or GUI manifest found.\n'
        printf 'This script only removes files recorded by the %s installers;\n' "$BIN_NAME"
        printf 'no files were touched.\n'
        exit 0
    fi

    if [ -n "$DRY_RUN" ]; then
        warn 'DRY-RUN: reading the manifests and printing actions only; no changes.'
    fi

    if [ -f "$MANIFEST" ]; then
        if ! parse_manifest; then
            err 'refusing to touch any file; inspect the manifest manually:'
            err "  cat $MANIFEST"
            exit 1
        fi
    else
        info "no beta manifest at $MANIFEST; only the loader manifest will be processed"
    fi
    if [ -f "$LOADER_MANIFEST" ]; then
        if ! parse_loader_manifest; then
            err 'refusing to touch any file; inspect the loader manifest manually:'
            err "  cat $LOADER_MANIFEST"
            exit 1
        fi
    fi
    if [ -f "$GUI_MANIFEST" ]; then
        if ! parse_gui_manifest; then
            err 'refusing to touch any file; inspect the GUI manifest manually:'
            err "  cat $GUI_MANIFEST"
            exit 1
        fi
    fi

    if [ -n "$MANIFEST_VERSION" ] && [ "$MANIFEST_VERSION" != "1" ]; then
        warn "manifest_version=$MANIFEST_VERSION is not 1; proceeding conservatively"
    fi
    if [ -n "$NAME" ] && [ "$NAME" != "$BIN_NAME" ]; then
        warn "manifest name=$NAME does not match $BIN_NAME; proceeding conservatively"
    fi
    if [ -n "$VERSION" ] || [ -n "$INSTALL_TIME" ] || [ -n "$SOURCE" ] || [ -n "$BRANCH" ] || [ -n "$LOADER_VERSION" ]; then
        info "manifest record: version=${VERSION:-unknown} install_time=${INSTALL_TIME:-unknown} source=${SOURCE:-unknown} branch=${BRANCH:-unknown} loader_version=${LOADER_VERSION:-unknown}"
    fi

    if [ -f "$MANIFEST" ] && { [ -z "$INSTALLED_SHA256" ] || [ -z "$ORIG_OWNER" ]; }; then
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

    step 'Removing our scx_loader entry'
    remove_loader_entry
    remove_mlfq_default

    step 'Pruning stale scx_loader config backups'
    prune_loader_config_backups

    step 'Removing the patched scx_loader'
    remove_loader_patch

    step 'Restoring the GUI library'
    restore_gui_lib

    if [ -n "$DROPIN_BACKUP" ]; then
        step 'Removing our drop-in backup'
        remove_dropin_backup
    fi

    step 'Removing our backup'
    remove_backup

    step 'Removing our manifest'
    remove_manifest
    if [ -f "$LOADER_MANIFEST" ]; then
        run rm -f "$LOADER_MANIFEST"
        ok "removed loader manifest $LOADER_MANIFEST"
    fi

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
