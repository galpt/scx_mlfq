#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# scx_mlfq loader patch installer for CachyOS (sched_ext).
#
# The CachyOS Kernel Manager GUI lists schedulers through scx_loader, and
# the loader's supported-scheduler list is compiled into the binary.
# scx_mlfq is not in the shipped list, so the GUI cannot select it; the
# [scheds.scx_mlfq] entry in /etc/scx_loader.toml only supplies mode flags.
#
# This script builds the published scx_loader crate with a patch that adds
# scx_mlfq to the supported set, installs the result as
# /usr/local/bin/scx_loader, and overrides scx_loader.service with a
# drop-in so package upgrades of the stock loader do not replace it. The
# GUI then lists scx_mlfq and can start, stop and switch to it like any
# other registered scheduler.
#
# The install is recorded in the scx_mlfq beta manifest
# (/usr/lib/scx/scx_mlfq-beta.manifest) under the loader_* keys, so
# uninstall_scx_mlfq.sh removes exactly the files this script created.
# scx_loader.service is enabled, so the patched loader (and with it the
# GUI entry for scx_mlfq) survives reboots.
#
# This script is normally invoked by install_scx_mlfq.sh; run it directly to rebuild the loader layer after a package upgrade has replaced it.
#
# Usage: sudo bash install_scx_mlfq_loader.sh [options]
#
# Options:
#   --force            Replace a conflicting pre-existing loader drop-in
#                      (backed up under /usr/lib/scx first).
#   --dry-run          Validate inputs and print every action without
#                      changing the system. Does NOT download or build.
#   --help, -h         Print this help text and exit.

set -euo pipefail

LIB_DIR="/usr/lib/scx"
LOADER_MANIFEST="$LIB_DIR/scx_mlfq-loader.manifest"
LOADER_BIN="/usr/local/bin/scx_loader"
LOADER_DROPIN_DIR="/etc/systemd/system/scx_loader.service.d"
LOADER_DROPIN="$LOADER_DROPIN_DIR/mlfq-loader.conf"
LOADER_DROPIN_BACKUP="$LIB_DIR/scx_loader.service.d.mlfq-loader.conf.bak"
LOADER_DROPIN_BACKUP_RECORDED=""
LOADER_CRATE_VERSION="1.1.2"
LOADER_CRATE_URL="https://static.crates.io/crates/scx_loader/scx_loader-${LOADER_CRATE_VERSION}.crate"

FORCE=""
DRY_RUN=""
BUILD_DIR=""
CRATE_DIR=""
LOADER_BIN_SHA=""
LOADER_DROPIN_BACKUP_RECORDED=""

info()  { printf '[INFO]  %s\n' "$1"; }
ok()    { printf '[ OK ]  %s\n' "$1"; }
warn()  { printf '[WARN]  %s\n' "$1"; }
err()   { printf '[ERR ]  %s\n' "$1" >&2; }
step()  { printf '\n---- %s ----\n' "$1"; }
dry()   { printf '[DRY ]  %s\n' "$1"; }

sanitize() {
    printf '%s' "$1" | tr '[:cntrl:]' '?'
}

# our_dropin: the exact bytes this installer owns for the loader override.
our_dropin() {
    printf '[Service]\nExecStart=\nExecStart=%s\n' "$LOADER_BIN"
}

# our_dropin_matches: 0 when the drop-in on disk is byte-identical to ours.
our_dropin_matches() {
    [ -f "$LOADER_DROPIN" ] && cmp -s "$LOADER_DROPIN" <(our_dropin)
}

usage() {
    cat <<'EOF'
scx_mlfq loader patch installer for CachyOS

Usage: sudo bash install_scx_mlfq_loader.sh [options]

Options:
  --force     Replace a conflicting pre-existing loader drop-in
              (backed up under /usr/lib/scx first).
  --dry-run   Validate inputs and print every action without
              changing the system. Does NOT download or build.
  --help, -h  Print this help text and exit.
EOF
}

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "must be run as root (EUID=$EUID)"
        printf '  try:  sudo bash %s\n' "$0"
        exit 1
    fi
}

# record_manifest: write the loader manifest. The loader install owns
# this file; the beta manifest records the scheduler binary install and
# is never touched here, so either script can be re-run independently.
record_manifest() {
    local _tmp

    if [ -n "$DRY_RUN" ]; then
        dry "write $LOADER_MANIFEST (name, version, loader_bin, loader_dropin, loader_sha256, install_time)"
        return 0
    fi

    mkdir -p "$LIB_DIR"
    _tmp=$(mktemp "$LIB_DIR/.scx_mlfq-loader.manifest.XXXXXX")
    cat > "$_tmp" <<EOF
name=scx_mlfq-loader
version=$LOADER_CRATE_VERSION
loader_bin=$LOADER_BIN
loader_dropin=$LOADER_DROPIN
loader_sha256=$LOADER_BIN_SHA
loader_dropin_backup=${LOADER_DROPIN_BACKUP_RECORDED:-}
install_time=$(date +%Y-%m-%dT%H:%M:%S%z)
EOF
    chmod 644 "$_tmp"
    mv -f "$_tmp" "$LOADER_MANIFEST"
    ok "loader install recorded in $LOADER_MANIFEST"
}

check_loader_service() {
    if [ "$(systemctl list-unit-files 'scx_loader*' --no-legend 2>/dev/null | grep -c .)" -eq 0 ]; then
        warn 'scx_loader.service is not installed; the GUI cannot manage schedulers without it'
        confirm_continue 'Continue anyway? The patched loader will be installed but unused.' || exit 0
    fi
}

confirm_continue() {
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

# check_dropin_conflict: read-only. Refuses before any system change when
# a pre-existing drop-in differs from the content this installer writes.
check_dropin_conflict() {
    if [ -e "$LOADER_DROPIN" ] && ! our_dropin_matches; then
        warn "drop-in already exists at $LOADER_DROPIN and DIFFERS from ours"
        if [ -z "$FORCE" ]; then
            err 'refusing to proceed: the existing drop-in differs from the content this installer writes'
            err "inspect it first:  $LOADER_DROPIN"
            err 'use --force to back it up under /usr/lib/scx and replace it'
            exit 1
        fi
    fi
}

fetch_and_patch_crate() {
    local _patch_dir _patch_file

    if [ -n "$DRY_RUN" ]; then
        dry "download $LOADER_CRATE_URL"
        dry 'extract and apply the scx_loader-mlfq.patch'
        dry "cargo build --release (in the extracted crate)"
        return 0
    fi

    BUILD_DIR=$(mktemp -d /tmp/scx_mlfq-loader-build.XXXXXX)
    CRATE_DIR="$BUILD_DIR/scx_loader-$LOADER_CRATE_VERSION"

    info "downloading $LOADER_CRATE_URL"
    curl --fail --silent --show-error --location "$LOADER_CRATE_URL" -o "$BUILD_DIR/crate.crate"
    tar xzf "$BUILD_DIR/crate.crate" -C "$BUILD_DIR"
    if [ ! -d "$CRATE_DIR" ]; then
        err "crate archive did not contain $CRATE_DIR"
        exit 1
    fi

    # The patch lives next to this script; resolve it without relying on
    # the working directory.
    _patch_dir=$(cd "$(dirname "$0")" && pwd)
    _patch_file="$_patch_dir/scx_loader-mlfq.patch"
    if [ ! -f "$_patch_file" ]; then
        err "patch file not found next to this script: $_patch_file"
        exit 1
    fi

    info "applying $_patch_file"
    if ! patch -p1 -d "$CRATE_DIR" < "$_patch_file"; then
        err 'patch application failed; the crate version may have changed'
        err "expected scx_loader $LOADER_CRATE_VERSION"
        exit 1
    fi
    ok 'patch applied'

    info 'building the patched loader (release profile)'
    # Own the target directory explicitly: the caller (install_scx_mlfq.sh)
    # may have exported CARGO_TARGET_DIR for its own build.
    if ! (cd "$CRATE_DIR" && CARGO_TARGET_DIR="$BUILD_DIR/target" cargo build --release); then
        err 'cargo build failed'
        exit 1
    fi
}

install_loader_binary() {
    local _built="$BUILD_DIR/target/release/scx_loader"

    if [ -n "$DRY_RUN" ]; then
        dry "install the built loader to $LOADER_BIN"
        return 0
    fi

    if [ ! -f "$_built" ]; then
        err "built loader not found at $_built"
        exit 1
    fi
    LOADER_BIN_SHA=$(sha256_of "$_built")
    install -m 755 "$_built" "$LOADER_BIN"
    ok "installed $LOADER_BIN"
}

install_dropin() {
    if [ -e "$LOADER_DROPIN" ]; then
        if our_dropin_matches; then
            info "drop-in already exists at $LOADER_DROPIN and matches ours"
            return 0
        fi
        # check_dropin_conflict already refused without --force.
        LOADER_DROPIN_BACKUP_RECORDED="$LOADER_DROPIN_BACKUP"
        warn "backing up the conflicting drop-in to $LOADER_DROPIN_BACKUP and replacing it"
        if [ -n "$DRY_RUN" ]; then
            dry "mkdir -p $LIB_DIR"
            dry "cp -p $LOADER_DROPIN $LOADER_DROPIN_BACKUP"
            dry "write $LOADER_DROPIN with the installer's content"
            return 0
        fi
        mkdir -p "$LIB_DIR"
        cp -p "$LOADER_DROPIN" "$LOADER_DROPIN_BACKUP"
        write_dropin
        return 0
    fi

    if [ -n "$DRY_RUN" ]; then
        dry "mkdir -p $LOADER_DROPIN_DIR"
        dry "write $LOADER_DROPIN:"
        dry "  [Service]"
        dry "  ExecStart="
        dry "  ExecStart=$LOADER_BIN"
        return 0
    fi

    mkdir -p "$LOADER_DROPIN_DIR"
    write_dropin
}

write_dropin() {
    rm -f -- "$LOADER_DROPIN"
    our_dropin > "$LOADER_DROPIN"
    chmod 644 "$LOADER_DROPIN"
    ok "drop-in written to $LOADER_DROPIN"
}

restart_loader() {
    if [ -n "$DRY_RUN" ]; then
        dry 'systemctl enable scx_loader (so the patched loader survives reboots)'
        dry 'systemctl daemon-reload'
        dry 'systemctl restart scx_loader (if active) so the GUI sees scx_mlfq'
        return 0
    fi

    run systemctl enable scx_loader 2>/dev/null \
        || warn 'scx_loader.service is not enabled; enable it for the patched loader to survive reboots'
    run systemctl daemon-reload || warn 'systemctl daemon-reload failed; restart systemd or reboot'
    if systemctl is-active --quiet scx_loader 2>/dev/null; then
        run systemctl restart scx_loader || warn 'scx_loader restart failed; the GUI picks scx_mlfq up after the next loader start'
    fi
}

verify_registration() {
    local OUT

    if [ -n "$DRY_RUN" ]; then
        dry "verify: SupportedSchedulers lists scx_mlfq (busctl)"
        return 0
    fi

    if ! systemctl is-active --quiet scx_loader 2>/dev/null; then
        info 'scx_loader is not running; start it (or open the Kernel Manager GUI) to see scx_mlfq'
        return 0
    fi

    if OUT=$(busctl --system get-property org.scx.Loader /org/scx/Loader \
            org.scx.Loader SupportedSchedulers 2>/dev/null) \
       && [ "$(printf '%s' "$OUT" | grep -c 'scx_mlfq')" -ge 1 ]; then
        ok 'scx_mlfq is registered with the running scx_loader; the GUI can select it'
    else
        warn 'could not confirm scx_mlfq in the loader SupportedSchedulers list'
        warn "  loader output: ${OUT:-<none>}"
    fi
}

cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        case "$BUILD_DIR" in
            /tmp/scx_mlfq-loader-build.*) rm -rf -- "$BUILD_DIR" ;;
            *) warn "not removing unexpected build dir: $BUILD_DIR" ;;
        esac
    fi
}

main() {
    step 'scx_mlfq loader patch installer for CachyOS'
    check_root

    if [ -n "$DRY_RUN" ]; then
        warn 'DRY-RUN: validating inputs and printing actions only; no download, no build, no changes.'
    fi

    check_loader_service

    step 'Checking the loader drop-in'
    check_dropin_conflict

    step 'Fetching and patching the scx_loader crate'
    fetch_and_patch_crate

    step 'Installing the patched loader'
    install_loader_binary

    step 'Overriding scx_loader.service'
    install_dropin

    step 'Recording the install'
    record_manifest

    step 'Restarting scx_loader'
    restart_loader

    step 'Verifying the registration'
    verify_registration

    if [ -n "$DRY_RUN" ]; then
        printf '\n=== DRY-RUN complete - nothing was installed or changed ===\n'
        return 0
    fi

    printf '\n=== patched scx_loader installed ===\n'
    printf 'The CachyOS Kernel Manager GUI now lists scx_mlfq and can start,\n'
    printf 'stop and switch to it like any other registered scheduler.\n'
    printf 'Remove with:  sudo bash uninstall_scx_mlfq.sh\n'
}

trap cleanup EXIT

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
