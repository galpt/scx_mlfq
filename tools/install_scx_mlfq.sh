#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# scx_mlfq installer for CachyOS (sched_ext). This is the single entry
# point: it builds scx_mlfq from the galpt/scx fork (default branch
# "scx_mlfq"), installs it as /usr/bin/scx_mlfq, records the install in a
# manifest, installs a systemd drop-in so `systemctl restart scx.service`
# starts scx_mlfq instead of the packaged default scheduler, and then
# invokes the loader and GUI integration scripts so the CachyOS Kernel
# Manager GUI can select, apply and switch to scx_mlfq. Pass --beta-only
# to skip the GUI integration and install just the scheduler.
#
# Only ONE sched_ext scheduler can be attached at a time. This installer
# stops scx.service and, only if a scheduler is currently attached and
# scx_loader is active, also stops scx_loader.service. scx_mlfq is NOT
# auto-started. When /etc/scx_loader.toml exists, the installer appends a
# [scheds.scx_mlfq] section so the CachyOS Kernel Manager GUI can list,
# start and switch to scx_mlfq; the loader is left stopped rather than
# disabled.
#
# The install manifest is written BEFORE the binary is swapped into place,
# so an interrupted run never leaves a new binary without a manifest, and a
# leftover stage file is removed by the EXIT trap. If the drop-in
# /etc/systemd/system/scx.service.d/scx_mlfq-beta.conf already exists with
# different content, the installer refuses (or, with --force, backs it up
# under /usr/lib/scx and replaces it).
#
# This script never edits /etc/default/scx and never creates a
# scx_loader.service drop-in. It does append the [scheds.scx_mlfq] section
# to /etc/scx_loader.toml when that file exists, and records it in the
# manifest as loader_entry=1 so the uninstaller can remove exactly that
# section.
#
# Usage: sudo bash install_scx_mlfq.sh [options]
#
# The scheduler sources come from the standalone repository
# (https://github.com/galpt/scx_mlfq.git, branch main); the workspace
# repository provides the sched-ext build environment and the scheduler
# crate is copied into its scheds/experimental/scx_mlfq/ directory.
#
# Options:
#   --repo URL         Git repository to use as the build workspace
#                      (default: https://github.com/galpt/scx.git)
#   --branch NAME      Branch of the build workspace
#                      (default: scx_mlfq)
#   --source-dir DIR   Build from a local scx workspace instead of cloning.
#                      DIR must contain Cargo.toml with
#                      scheds/experimental/scx_mlfq listed as a member.
#                      --repo/--branch are ignored when this is set.
#   --beta-only        Install only the scheduler binary and its drop-in;
#                      skip the loader and GUI integration steps.
#   --force            Skip the interactive confirmation when overwriting a
#                      package-owned /usr/bin/scx_mlfq; also backs up and
#                      replaces a conflicting pre-existing drop-in.
#   --dry-run          Validate inputs and print every action without
#                      changing the system. Does NOT clone or build.
#   --help, -h         Print this help text and exit.

set -euo pipefail

BIN_NAME="scx_mlfq"
BIN_PATH="/usr/bin/scx_mlfq"
LIB_DIR="/usr/lib/scx"
MANIFEST="$LIB_DIR/scx_mlfq-beta.manifest"
BACKUP_PATH="$LIB_DIR/scx_mlfq.scx_mlfq-beta.bak"
DROPIN_BACKUP_PATH="$LIB_DIR/scx.service.d.scx_mlfq-beta.conf.bak"
DROPIN_DIR="/etc/systemd/system/scx.service.d"
DROPIN="$DROPIN_DIR/scx_mlfq-beta.conf"
SCX_STATE_FILE="/sys/kernel/sched_ext/state"
SCX_OPS_FILE="/sys/kernel/sched_ext/root/ops"
SCX_LOADER_CONFIG="/etc/scx_loader.toml"

DEFAULT_STANDALONE_REPO="https://github.com/galpt/scx_mlfq.git"
DEFAULT_STANDALONE_BRANCH="main"
DEFAULT_REPO="https://github.com/galpt/scx.git"
DEFAULT_BRANCH="scx_mlfq"

STANDALONE_REPO="$DEFAULT_STANDALONE_REPO"
STANDALONE_BRANCH="$DEFAULT_STANDALONE_BRANCH"
REPO="$DEFAULT_REPO"
BRANCH="$DEFAULT_BRANCH"
SOURCE_DIR=""
FORCE=""
DRY_RUN=""
BETA_ONLY=""
BUILD_DIR=""
SRC_DIR=""
BIN_BUILT=""
STAGE_FILE=""
MANIFEST_TMP=""
LOADER_STOPPED=""
dropin_backup_recorded=""
LOADER_ENTRY=""
orig_owner="none"
orig_sha256=""

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

# our_loader_section: the scx_loader config entry this installer owns.
# Empty mode arrays: scx_mlfq is knob-free, so no mode adds flags.
our_loader_section() {
    cat <<'EOF'

[scheds.scx_mlfq]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []
server_mode = []
EOF
}

# register_loader_entry: append the [scheds.scx_mlfq] section to the
# scx_loader config so the Kernel Manager GUI lists scx_mlfq. The section
# is appended atomically through a temp file; an existing section is left
# untouched. Without a loader config there is nothing to register.
register_loader_entry() {
    local _tmp

    if [ ! -f "$SCX_LOADER_CONFIG" ]; then
        warn "no $SCX_LOADER_CONFIG; skipping scx_loader registration"
        warn 'the CachyOS Kernel Manager GUI cannot list scx_mlfq without a loader config'
        return 0
    fi

    if grep -q '^\[scheds\.scx_mlfq\]$' "$SCX_LOADER_CONFIG" 2>/dev/null; then
        info "scx_mlfq is already registered in $SCX_LOADER_CONFIG"
        LOADER_ENTRY="1"
        return 0
    fi

    if [ -n "$DRY_RUN" ]; then
        dry "append the [scheds.scx_mlfq] section to $SCX_LOADER_CONFIG"
        return 0
    fi

    _tmp=$(mktemp "${SCX_LOADER_CONFIG}.scx_mlfq.XXXXXX") || {
        err "cannot create a temp file next to $SCX_LOADER_CONFIG"
        exit 1
    }
    cp -p -- "$SCX_LOADER_CONFIG" "$_tmp"
    our_loader_section >> "$_tmp"
    mv -f -- "$_tmp" "$SCX_LOADER_CONFIG"
    ok "registered scx_mlfq in $SCX_LOADER_CONFIG"
    LOADER_ENTRY="1"
}

# validate_flag_value: reject control characters and leading '-' in
# user-supplied flag values before they are used or logged.
validate_flag_value() {
    local flag="$1" value="$2"
    case "$value" in
        *[$'\t\n\r\v\f']*)
            err "$flag value contains control characters: $(sanitize "$value")"
            exit 1
            ;;
        -*)
            err "$flag value must not start with '-': $(sanitize "$value")"
            exit 1
            ;;
    esac
}

usage() {
    cat <<'EOF'
scx_mlfq beta installer for CachyOS

Usage: sudo bash install_scx_mlfq.sh [options]

Options:
  --repo URL         Git repository to use as the build workspace
                     (default: https://github.com/galpt/scx.git)
  --branch NAME      Branch of the build workspace
                     (default: scx_mlfq)
  --source-dir DIR   Build from a local scx workspace instead of cloning.
                     DIR must contain Cargo.toml with
                     scheds/experimental/scx_mlfq listed as a member.
                     --repo/--branch are ignored when this is set.
  --beta-only        Install only the scheduler binary and its drop-in;
                     skip the loader and GUI integration steps.
  --force            Skip the interactive confirmation when overwriting a
                     package-owned /usr/bin/scx_mlfq; also backs up and
                     replaces a conflicting pre-existing drop-in.
  --dry-run          Validate inputs and print every action without
                     changing the system. Does NOT clone or build.
  --help, -h         Print this help text and exit.

The scheduler sources are always taken from the standalone repository
(https://github.com/galpt/scx_mlfq.git, branch main); the workspace
repository only provides the sched-ext build environment. The scheduler
crate is copied into scheds/experimental/scx_mlfq/ of the workspace
before building.
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

version_of() {
    local v
    v=$("$BIN_PATH" --version 2>/dev/null | head -n 1) || true
    if [ -n "$v" ]; then
        printf '%s' "$v"
    else
        printf 'FAILED'
    fi
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

check_cachyos() {
    local OS_ID OS_LIKE

    if [ ! -r /etc/os-release ]; then
        warn '/etc/os-release is missing or unreadable'
        confirm 'Continue anyway? The installer expects a pacman/systemd system.' || exit 0
        return 0
    fi
    OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tail -n 1 | tr -d '"')
    OS_LIKE=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tail -n 1 | tr -d '"')
    case "$OS_ID" in
        cachyos)
            ok "CachyOS detected (ID=$OS_ID)"
            return 0
            ;;
    esac
    case "$OS_LIKE" in
        *arch*)
            ok "Arch-like system detected (ID=${OS_ID:-}, ID_LIKE=$OS_LIKE)"
            return 0
            ;;
    esac
    warn "this installer targets CachyOS/Arch (ID=$(sanitize "${OS_ID:-}"), ID_LIKE=$(sanitize "$OS_LIKE"))"
    confirm 'Continue anyway? pacman and systemd are required.' || exit 0
}

check_sched_ext() {
    local _sysfs="no" _cfg="no" _kcfg

    [ -d /sys/kernel/sched_ext ] && _sysfs="yes"
    _kcfg="/boot/config-$(uname -r)"
    # NOTE: grep -q cannot be used in a pipe here: it exits on the first
    # match, SIGPIPE-kills zcat, and pipefail then reports failure. grep -c
    # reads the whole stream, so it is pipefail-safe.
    if { command -v zcat >/dev/null 2>&1 \
             && [ "$(zcat /proc/config.gz 2>/dev/null | grep -c '^CONFIG_SCHED_CLASS_EXT=y')" -ge 1 ]; } \
       || { [ -f "$_kcfg" ] && grep -q '^CONFIG_SCHED_CLASS_EXT=y' "$_kcfg" 2>/dev/null; }; then
        _cfg="yes"
    fi

    if [ "$_sysfs" = "yes" ] && [ "$_cfg" = "yes" ]; then
        ok "kernel $(uname -r) confirms sched_ext (sysfs + CONFIG_SCHED_CLASS_EXT=y)"
    else
        warn "sched_ext support could not be fully confirmed for kernel $(uname -r)"
        warn "  /sys/kernel/sched_ext present: $_sysfs"
        warn "  CONFIG_SCHED_CLASS_EXT=y:      $_cfg"
        confirm 'Continue anyway? scx_mlfq needs a sched_ext kernel to run.' || exit 0
    fi
}

build_source() {
    if [ -n "$SOURCE_DIR" ]; then
        # Local-tree override: validate and build from it.
        if [ ! -d "$SOURCE_DIR" ]; then
            err "source directory not found: $SOURCE_DIR"
            exit 1
        fi
        if [ ! -f "$SOURCE_DIR/Cargo.toml" ]; then
            err "no Cargo.toml found in source directory: $SOURCE_DIR"
            exit 1
        fi
        if [ -n "$DRY_RUN" ]; then
            dry "build from local source directory: $SOURCE_DIR"
            dry "cargo build --release --manifest-path $SOURCE_DIR/Cargo.toml -p scx_mlfq"
            return 0
        fi
        info "building from local source directory: $SOURCE_DIR"
        SRC_DIR="$SOURCE_DIR"
        BRANCH=""
        BUILD_DIR=$(mktemp -d /tmp/scx_mlfq-build.XXXXXX)
    else
        if [ -z "$REPO" ]; then
            err "--repo must not be empty"
            exit 1
        fi
        if [ -z "$BRANCH" ]; then
            err "--branch must not be empty"
            exit 1
        fi
        if [ -n "$DRY_RUN" ]; then
            dry "git clone --branch $STANDALONE_BRANCH --depth 1 -- $STANDALONE_REPO (into a temporary build dir)"
            dry "git clone --branch $BRANCH --depth 1 -- $REPO (into a temporary build dir)"
            dry "rsync -a --delete --exclude target --exclude veristat <standalone>/scx/ <workspace>/scheds/experimental/scx_mlfq/"
            dry "cargo build --release -p scx_mlfq"
            return 0
        fi
        BUILD_DIR=$(mktemp -d /tmp/scx_mlfq-build.XXXXXX)
        info "cloning $STANDALONE_REPO (branch $STANDALONE_BRANCH) into $BUILD_DIR/mlfq"
        if ! git clone --branch "$STANDALONE_BRANCH" --depth 1 -- "$STANDALONE_REPO" \
                "$BUILD_DIR/mlfq" 2>/dev/null; then
            err "git clone failed for $(sanitize "$STANDALONE_REPO") (branch $STANDALONE_BRANCH)"
            err 'check the standalone repository URL and network access'
            exit 1
        fi
        info "cloning $REPO (branch $BRANCH) into $BUILD_DIR/src"
        if ! git clone --branch "$BRANCH" --depth 1 -- "$REPO" "$BUILD_DIR/src" 2>/dev/null; then
            err "git clone failed for $(sanitize "$REPO") (branch $BRANCH)"
            err 'check the --repo/--branch values and network access'
            exit 1
        fi
        SRC_DIR="$BUILD_DIR/src"
        CRATE_DIR="$SRC_DIR/scheds/experimental/scx_mlfq"
        if [ ! -d "$CRATE_DIR" ]; then
            err "the workspace $REPO (branch $BRANCH) has no scheds/experimental/scx_mlfq"
            err 'the workspace must list the scheduler as a member of its Cargo.toml'
            exit 1
        fi
        info "copying the scheduler sources from the standalone repository into the workspace"
        if ! rsync -a --delete --exclude target --exclude veristat \
                "$BUILD_DIR/mlfq/scx/" "$CRATE_DIR/"; then
            err "rsync of the scheduler sources failed"
            exit 1
        fi
    fi

    info "building package scx_mlfq (release profile)"
    export CARGO_TARGET_DIR="$BUILD_DIR/target"
    if ! cargo build --release --manifest-path "$SRC_DIR/Cargo.toml" -p scx_mlfq; then
        err "cargo build failed"
        err "$SRC_DIR must be a full scx workspace with"
        err "scheds/experimental/scx_mlfq listed in the members of Cargo.toml"
        exit 1
    fi

    BIN_BUILT="$CARGO_TARGET_DIR/release/scx_mlfq"
    if [ ! -f "$BIN_BUILT" ]; then
        err "built binary not found at $BIN_BUILT"
        exit 1
    fi
    ok "built binary: $BIN_BUILT"
}

stop_scheduler() {
    local _state

    if [ -n "$DRY_RUN" ]; then
        dry 'systemctl stop scx.service (ignore errors)'
        _state=$(cat "$SCX_STATE_FILE" 2>/dev/null || printf 'disabled')
        if systemctl is-active --quiet scx_loader 2>/dev/null && [ "$_state" != "disabled" ]; then
            dry 'systemctl stop scx_loader.service (a scheduler is attached)'
        fi
        return 0
    fi

    systemctl stop scx.service 2>/dev/null || true
    info 'scx.service stopped (errors ignored)'

    _state=$(cat "$SCX_STATE_FILE" 2>/dev/null || printf 'disabled')
    if [ "$_state" != "disabled" ]; then
        info "a sched_ext scheduler is attached (state=$_state); stopping scx_loader.service if active"
        if systemctl is-active --quiet scx_loader 2>/dev/null; then
            systemctl stop scx_loader.service 2>/dev/null || true
            LOADER_STOPPED="1"
            info 'stopped scx_loader.service'
        fi
    else
        info "no sched_ext scheduler attached (state=$_state); scx_loader left as-is"
    fi
}

ownership_gate() {
    local OWNER rc

    if [ ! -e "$BIN_PATH" ]; then
        orig_owner="none"
        orig_sha256=""
        info "$BIN_PATH is not present; installing fresh"
        return 0
    fi

    if [ -L "$BIN_PATH" ]; then
        warn "$BIN_PATH is a symlink; it will be replaced by a regular file"
    fi

    # pacman -Qo exit 0 means owned, exit 1 means unowned, any
    # other exit (database locked/corrupt) must abort, never silently
    # proceed as "unowned".
    if pacman -Qo "$BIN_PATH" >/dev/null 2>&1; then
        rc=0
    else
        rc=$?
    fi
    case "$rc" in
        0)
            OWNER=$(pacman -Qo "$BIN_PATH" 2>/dev/null | awk '{print $(NF-1)}')
            case "$OWNER" in
                *[$'\t\n\r\v\f']*)
                    err 'pacman reported an owner containing control characters; refusing'
                    exit 1
                    ;;
            esac
            [ -n "$OWNER" ] || OWNER="<unknown>"
            warn "/usr/bin/scx_mlfq is owned by package: $OWNER"
            if [ -z "$FORCE" ]; then
                if ! confirm 'Overwrite the package-owned file? The original is backed up first.'; then
                    err 'aborted: package-owned binary not overwritten (use --force to skip this prompt)'
                    exit 1
                fi
            fi
            orig_owner="$OWNER"
            orig_sha256=$(sha256_of "$BIN_PATH")
            if [ -f "$BACKUP_PATH" ]; then
                warn "an earlier backup already exists at $BACKUP_PATH; it will be replaced"
            fi
            if [ -n "$DRY_RUN" ]; then
                dry "mkdir -p $LIB_DIR"
                dry "cp -p $BIN_PATH $BACKUP_PATH"
                dry "record orig_owner=$orig_owner orig_sha256=$orig_sha256"
            else
                run mkdir -p "$LIB_DIR"
                run cp -p "$BIN_PATH" "$BACKUP_PATH"
                ok "backed up the original to $BACKUP_PATH"
            fi
            ;;
        1)
            orig_owner="none"
            orig_sha256=""
            info "$BIN_PATH exists but is not owned by any package; it will be replaced"
            ;;
        *)
            err "pacman -Qo exited $rc (database locked or corrupt?); refusing to continue"
            exit 1
            ;;
    esac
}

# check_dropin_conflict: read-only. Refuses before any system change when a
# pre-existing drop-in differs from the content this installer writes.
check_dropin_conflict() {
    if [ -e "$DROPIN" ] && ! cmp -s "$DROPIN" <(our_dropin); then
        warn "drop-in already exists at $DROPIN and DIFFERS from ours"
        if [ -z "$FORCE" ]; then
            err 'refusing to proceed: the existing drop-in differs from the content this installer writes'
            err "inspect it first:  $DROPIN"
            err 'use --force to back it up under /usr/lib/scx and replace it'
            exit 1
        fi
    fi
}

install_dropin() {
    if [ -e "$DROPIN" ]; then
        if cmp -s "$DROPIN" <(our_dropin); then
            info "drop-in already exists at $DROPIN and matches ours; it will be recorded"
        else
            # check_dropin_conflict already refused without --force.
            dropin_backup_recorded="$DROPIN_BACKUP_PATH"
            warn "backing up the conflicting drop-in to $DROPIN_BACKUP_PATH and replacing it"
            if [ -n "$DRY_RUN" ]; then
                dry "mkdir -p $LIB_DIR"
                dry "cp -p $DROPIN $DROPIN_BACKUP_PATH"
                dry "write $DROPIN with the installer's content"
            else
                run mkdir -p "$LIB_DIR"
                run cp -p "$DROPIN" "$DROPIN_BACKUP_PATH"
                write_dropin
            fi
        fi
    else
        if [ -n "$DRY_RUN" ]; then
            dry "mkdir -p $DROPIN_DIR"
            dry "write $DROPIN:"
            dry "  [Service]"
            dry "  ExecStart="
            dry "  ExecStart=/usr/bin/scx_mlfq"
        else
            run mkdir -p "$DROPIN_DIR"
            write_dropin
        fi
    fi
    run systemctl daemon-reload || warn 'systemctl daemon-reload failed; restart systemd or reboot'
}

write_dropin() {
    rm -f -- "$DROPIN"
    our_dropin > "$DROPIN"
    chmod 644 "$DROPIN"
    ok "drop-in written to $DROPIN"
}

install_binary() {
    local _stage INSTALLED_SHA256 VER_STR OUT _tmp

    if [ -n "$DRY_RUN" ]; then
        dry "rm -f $BIN_PATH.new.<pid>"
        dry "cp <built binary> $BIN_PATH.new.<pid>"
        dry "chmod 755 $BIN_PATH.new.<pid>"
        dry "write manifest $MANIFEST BEFORE the swap (installed_sha256 from the staged file)"
        dry "  (version, installed_sha256, orig_owner=$orig_owner, orig_sha256=$orig_sha256,"
        dry "   backup_path=$BACKUP_PATH, dropins=$DROPIN, dropin_backup=$dropin_backup_recorded,"
        dry "   source/branch)"
        dry "mv -f $BIN_PATH.new.<pid> $BIN_PATH (last step; the EXIT trap cleans a leftover stage)"
        return 0
    fi

    _stage="$BIN_PATH.new.$$"
    STAGE_FILE="$_stage"
    rm -f -- "$_stage"
    run cp "$BIN_BUILT" "$_stage"
    run chmod 755 "$_stage"

    INSTALLED_SHA256=$(sha256_of "$_stage")
    VER_STR="unknown"
    OUT=$("$_stage" --version 2>/dev/null | head -n 1) || true
    [ -n "$OUT" ] && VER_STR="$OUT"
    VER_STR=$(printf '%s' "$VER_STR" | tr -d '[:cntrl:]')
    [ -n "$VER_STR" ] || VER_STR="unknown"

    run mkdir -p "$LIB_DIR"
    _tmp=$(mktemp "$LIB_DIR/.scx_mlfq-beta.manifest.XXXXXX")
    MANIFEST_TMP="$_tmp"
    cat > "$_tmp" <<EOF
manifest_version=1
name=$BIN_NAME
version=$VER_STR
installed_sha256=$INSTALLED_SHA256
orig_owner=$orig_owner
orig_sha256=$orig_sha256
backup_path=$BACKUP_PATH
dropins=$DROPIN
dropin_backup=$dropin_backup_recorded
loader_entry=0
install_time=$(date +%Y-%m-%dT%H:%M:%S%z)
source=${SOURCE_DIR:-$REPO}
branch=${BRANCH:-}
EOF
    chmod 644 "$_tmp"
    run mv -f "$_tmp" "$MANIFEST"
    MANIFEST_TMP=""
    ok "manifest written to $MANIFEST"

    run mv -f "$_stage" "$BIN_PATH"
    STAGE_FILE=""
    ok "installed $BIN_PATH"
}

smoke_test() {
    local OUT

    if [ -n "$DRY_RUN" ]; then
        dry "smoke test: $BIN_PATH --version"
        return 0
    fi
    if OUT=$(timeout 15 "$BIN_PATH" --version 2>&1); then
        ok "smoke test passed: $BIN_PATH --version"
        printf '  %s\n' "$OUT"
    else
        warn "smoke test FAILED: $BIN_PATH --version did not succeed"
        printf '  output: %s\n' "${OUT:-<none>}"
        warn "the binary may be broken or missing runtime libraries; check: ldd $BIN_PATH"
    fi
}

status_summary() {
    printf '  %-22s %s\n' 'Binary:' "$(version_of)"
    printf '  %-22s %s\n' 'scx.service:' "$(systemctl is-active scx 2>/dev/null || printf 'stopped')"
    printf '  %-22s %s\n' 'scx_loader:' "$(systemctl is-active scx_loader 2>/dev/null || printf 'inactive')"
    printf '  %-22s %s\n' 'sched_ext state:' "$(cat "$SCX_STATE_FILE" 2>/dev/null || printf 'unknown')"
    printf '  %-22s %s\n' 'active ops:' "$(cat "$SCX_OPS_FILE" 2>/dev/null || printf 'none (CFS)')"
}

next_steps() {
    printf '\n'
    if [ -n "$DRY_RUN" ]; then
        printf '=== DRY-RUN complete - nothing was installed or changed ===\n'
        return 0
    fi
    printf '=== scx_mlfq (beta) installed ===\n'
    printf '\n'
    printf 'Start scx_mlfq now, one of:\n'
    printf '\n'
    printf '  1. Direct run (foreground, for a quick test):\n'
    printf '       sudo /usr/bin/scx_mlfq\n'
    printf '     Ctrl+C detaches; the kernel reverts to CFS automatically.\n'
    printf '\n'
    printf '  2. Via systemd (uses our drop-in %s):\n' "$DROPIN"
    printf '       sudo systemctl restart scx.service\n'
    printf '\n'
    printf 'Notes:\n'
    printf '  - The GUI lists schedulers through scx_loader, whose supported list\n'
    printf '    is compiled into the binary. Run install_scx_mlfq_loader.sh to add\n'
    printf '    scx_mlfq to it; until then the GUI cannot select scx_mlfq.\n'
    printf '    The loader may have been left stopped; it is NOT disabled.'
    if [ -n "$LOADER_STOPPED" ]; then
        printf ' (this installer stopped it)'
    fi
    printf '\n'
    printf '  - Only one sched_ext scheduler can run at a time.\n'
    printf '  - Remove with:  sudo bash uninstall_scx_mlfq.sh\n'
    printf '\n'
}

cleanup() {
    if [ -n "$STAGE_FILE" ]; then
        case "$STAGE_FILE" in
            "$BIN_PATH.new."*) rm -f -- "$STAGE_FILE" ;;
            *) warn "not removing unexpected stage path: $STAGE_FILE" ;;
        esac
    fi
    if [ -n "$MANIFEST_TMP" ]; then
        case "$MANIFEST_TMP" in
            "$LIB_DIR/.scx_mlfq-beta.manifest."*) rm -f -- "$MANIFEST_TMP" ;;
            *) warn "not removing unexpected manifest temp: $MANIFEST_TMP" ;;
        esac
    fi
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        case "$BUILD_DIR" in
            /tmp/scx_mlfq-build.*) rm -rf -- "$BUILD_DIR" ;;
            *) warn "not removing unexpected build dir: $BUILD_DIR" ;;
        esac
    fi
}

main() {
    step 'scx_mlfq beta installer for CachyOS'
    check_root

    if [ -n "$DRY_RUN" ]; then
        warn 'DRY-RUN: validating inputs and printing actions only; no clone, no build, no changes.'
    fi

    check_cachyos
    check_sched_ext

    step 'Source and build'
    build_source

    step 'Checking the systemd drop-in'
    check_dropin_conflict

    step 'Stopping the currently attached scheduler'
    stop_scheduler

    step "Ownership check for $BIN_PATH"
    ownership_gate

    step 'Installing binary and writing manifest'
    install_binary

    step 'Preparing the systemd drop-in'
    install_dropin

    # The manifest is written before the drop-in step so a crash between the
    # binary swap and the drop-in never leaves an unrecoverable state; if the
    # drop-in step backed up a conflicting file, record that in the manifest.
    if [ -n "$dropin_backup_recorded" ]; then
        run sed -i "s|^dropin_backup=.*|dropin_backup=$dropin_backup_recorded|" "$MANIFEST"
    fi

    step 'Registering scx_mlfq with scx_loader'
    register_loader_entry
    if [ -n "$LOADER_ENTRY" ]; then
        run sed -i "s|^loader_entry=.*|loader_entry=$LOADER_ENTRY|" "$MANIFEST"
        if [ -n "$DRY_RUN" ]; then
            dry 'systemctl restart scx_loader (if active) so the GUI sees the new entry'
        elif systemctl is-active --quiet scx_loader 2>/dev/null; then
            run systemctl restart scx_loader                 || warn 'scx_loader restart failed; the GUI picks the entry up after the next loader start'
        fi
    fi

    step 'Smoke test'
    smoke_test

    if [ -z "$BETA_ONLY" ]; then
        local _it_args=()
        [ -n "$FORCE" ] && _it_args+=(--force)
        [ -n "$DRY_RUN" ] && _it_args+=(--dry-run)

        step 'Loader integration (patched scx_loader for the GUI dropdown)'
        if ! bash "$(dirname "$0")/install_scx_mlfq_loader.sh" "${_it_args[@]}"; then
            err 'loader integration failed; the scheduler itself is installed'
            err "re-run the loader integration with:  sudo bash $(dirname "$0")/install_scx_mlfq_loader.sh"
            exit 1
        fi

        step 'GUI integration (patched libscxctl-ui for select and apply)'
        if ! bash "$(dirname "$0")/install_scx_mlfq_gui.sh" "${_it_args[@]}"; then
            err 'GUI integration failed; the scheduler and loader are installed'
            err "re-run the GUI integration with:  sudo bash $(dirname "$0")/install_scx_mlfq_gui.sh"
            exit 1
        fi
    else
        info '--beta-only: skipping the loader and GUI integration steps'
    fi

    step 'Status summary'
    status_summary

    next_steps
}

trap cleanup EXIT

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo)
            [ "$#" -ge 2 ] || { err '--repo needs a value'; exit 1; }
            validate_flag_value '--repo' "$2"
            REPO="$2"
            shift 2
            ;;
        --branch)
            [ "$#" -ge 2 ] || { err '--branch needs a value'; exit 1; }
            validate_flag_value '--branch' "$2"
            case "$2" in
                *[!A-Za-z0-9._/-]*)
                    err "--branch contains invalid characters (allowed: [A-Za-z0-9._/-]): $(sanitize "$2")"
                    exit 1
                    ;;
            esac
            BRANCH="$2"
            shift 2
            ;;
        --source-dir)
            [ "$#" -ge 2 ] || { err '--source-dir needs a value'; exit 1; }
            validate_flag_value '--source-dir' "$2"
            SOURCE_DIR="$2"
            shift 2
            ;;
        --beta-only)
            BETA_ONLY="1"
            shift
            ;;
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
