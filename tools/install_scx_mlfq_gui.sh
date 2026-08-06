#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# scx_mlfq GUI patch installer for CachyOS (sched_ext).
#
# The CachyOS Kernel Manager scheduler page and scx-manager link
# libscxctl-ui.so, which embeds a Rust client whose supported-scheduler
# list comes from the published scx_loader crate. Even with a patched
# scx_loader binary running, that embedded list does not know scx_mlfq,
# so the GUI cannot fetch flags for it or apply it.
#
# This script builds the CachyOS scx-manager project with the patched
# scx_loader crate vendored into its Rust library, and replaces
# /usr/lib/libscxctl-ui.so.1.15.12 (the soname both GUI front-ends link)
# with the result. The original file is backed up and recorded in the
# scx_mlfq GUI manifest, so uninstall_scx_mlfq.sh restores it.
#
# The build needs the GUI build dependencies: cmake, ninja, Qt 6 base and
# tools, and the Rust toolchain. No packages are installed by this script.
#
# Usage: sudo bash install_scx_mlfq_gui.sh [options]
#
# Options:
#   --force            Replace a conflicting pre-existing GUI library
#                      without prompting (still backed up first).
#   --dry-run          Validate inputs and print every action without
#                      cloning, building, or changing the system.
#   --help, -h         Print this help text and exit.

set -euo pipefail

LIB_DIR="/usr/lib/scx"
GUI_MANIFEST="$LIB_DIR/scx_mlfq-gui.manifest"
GUI_LIB="/usr/lib/libscxctl-ui.so.1.15.12"
GUI_BACKUP="$LIB_DIR/libscxctl-ui.so.1.15.12.orig"
GUI_REPO="https://github.com/CachyOS/scx-manager.git"
GUI_COMMIT="af37c3e7bbffa6b259c3d0aec88da33c6e0062b0"
GUI_VERSION="1.15.12"
CRATE_VERSION="1.1.2"
CRATE_URL="https://static.crates.io/crates/scx_loader/scx_loader-${CRATE_VERSION}.crate"

FORCE=""
DRY_RUN=""
BUILD_DIR=""
GUI_LIB_SHA=""
orig_owner="none"
orig_sha256=""

info()  { printf '[INFO]  %s\n' "$1"; }
ok()    { printf '[ OK ]  %s\n' "$1"; }
warn()  { printf '[WARN]  %s\n' "$1"; }
err()   { printf '[ERR ]  %s\n' "$1" >&2; }
step()  { printf '\n---- %s ----\n' "$1"; }
dry()   { printf '[DRY ]  %s\n' "$1"; }

sanitize() {
    printf '%s' "$1" | tr '[:cntrl:]' '?'
}

usage() {
    cat <<'EOF'
scx_mlfq GUI patch installer for CachyOS

Usage: sudo bash install_scx_mlfq_gui.sh [options]

Options:
  --force     Replace a conflicting pre-existing GUI library without
              prompting (still backed up first).
  --dry-run   Validate inputs and print every action without cloning,
              building, or changing the system.
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

check_build_deps() {
    local missing=""

    for c in cmake ninja rustc cargo; do
        command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
    done
    for p in qt6-base qt6-tools; do
        pacman -Q "$p" >/dev/null 2>&1 || missing="$missing $p"
    done
    if [ -n "$missing" ]; then
        warn "missing build dependencies:$missing"
        confirm_continue 'Continue anyway? The GUI build will fail without them.' || exit 0
    fi
}

# check_lib_conflict: read-only. Refuses before any system change when a
# pre-existing GUI library differs from the packaged one (it would be a
# foreign build, not the package's file we know how to restore).
check_lib_conflict() {
    local current

    if [ ! -f "$GUI_LIB" ]; then
        return 0
    fi
    if ! pacman -Qo "$GUI_LIB" >/dev/null 2>&1; then
        current=$(sha256_of "$GUI_LIB")
        warn "$GUI_LIB exists and is not owned by the scx-manager package"
        if [ -z "$FORCE" ]; then
            err 'refusing to proceed: the file is not the packaged library this installer knows how to restore'
            err 'use --force to back it up and replace it anyway'
            exit 1
        fi
        orig_owner="none"
        orig_sha256="$current"
    fi
}

clone_and_vendor() {
    local _patch_dir _patch_file _crate

    if [ -n "$DRY_RUN" ]; then
        dry "git clone $GUI_REPO (pinned commit $GUI_COMMIT)"
        dry "download $CRATE_URL and apply the scx_loader-mlfq.patch as a vendored path dependency"
        dry 'cmake configure and build (release)'
        return 0
    fi

    BUILD_DIR=$(mktemp -d /tmp/scx_mlfq-gui-build.XXXXXX)

    info "cloning $GUI_REPO"
    git clone --quiet "$GUI_REPO" "$BUILD_DIR/scx-manager"
    git -C "$BUILD_DIR/scx-manager" checkout --quiet "$GUI_COMMIT" \
        || { err "cannot check out pinned commit $GUI_COMMIT; the GUI project may have rewritten history"; exit 1; }

    _patch_dir=$(cd "$(dirname "$0")" && pwd)
    _patch_file="$_patch_dir/scx_loader-mlfq.patch"
    if [ ! -f "$_patch_file" ]; then
        err "patch file not found next to this script: $_patch_file"
        exit 1
    fi

    _crate="$BUILD_DIR/scx_loader.crate"
    info "downloading $CRATE_URL"
    curl --fail --silent --show-error --location "$CRATE_URL" -o "$_crate"
    tar xzf "$_crate" -C "$BUILD_DIR"
    mv "$BUILD_DIR/scx_loader-$CRATE_VERSION" \
       "$BUILD_DIR/scx-manager/scx-rustlib/vendor_scx_loader"

    info "applying $_patch_file to the vendored crate"
    if ! patch -p1 -d "$BUILD_DIR/scx-manager/scx-rustlib/vendor_scx_loader" < "$_patch_file"; then
        err 'patch application failed; the crate version may have changed'
        err "expected scx_loader $CRATE_VERSION"
        exit 1
    fi

    sed -i 's|^scx_loader = "1.1.2"|scx_loader = { version = "1.1.2", path = "vendor_scx_loader" }|' \
        "$BUILD_DIR/scx-manager/scx-rustlib/Cargo.toml"

    info 'building the GUI (release)'
    if ! (cd "$BUILD_DIR/scx-manager" \
          && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
          && cmake --build build -j"$(nproc)"); then
        err 'cmake build failed'
        err 'the build needs cmake, ninja, Qt 6 base and tools, and the Rust toolchain'
        exit 1
    fi
    ok 'build finished'
}

install_lib() {
    local _built="$BUILD_DIR/scx-manager/build/libscxctl-ui.so.1.15.12"

    if [ -n "$DRY_RUN" ]; then
        dry "backup $GUI_LIB to $GUI_BACKUP"
        dry "install the built libscxctl-ui.so.1.15.12 to $GUI_LIB"
        return 0
    fi

    if [ ! -f "$_built" ]; then
        err "built library not found at $_built"
        exit 1
    fi
    GUI_LIB_SHA=$(sha256_of "$_built")

    if [ -f "$GUI_LIB" ]; then
        if [ -f "$GUI_BACKUP" ]; then
            warn "an earlier backup already exists at $GUI_BACKUP; keeping it"
        else
            mkdir -p "$LIB_DIR"
            cp -p "$GUI_LIB" "$GUI_BACKUP"
            orig_sha256=$(sha256_of "$GUI_BACKUP")
            ok "backed up the original to $GUI_BACKUP"
        fi
    fi

    install -m 755 "$_built" "$GUI_LIB"
    ok "installed $GUI_LIB"
}

record_manifest() {
    local _tmp

    if [ -n "$DRY_RUN" ]; then
        dry "write $GUI_MANIFEST (name, version, gui_lib, gui_backup, gui_sha256, orig_owner, orig_sha256, install_time)"
        return 0
    fi

    mkdir -p "$LIB_DIR"
    _tmp=$(mktemp "$LIB_DIR/.scx_mlfq-gui.manifest.XXXXXX")
    cat > "$_tmp" <<EOF
name=scx_mlfq-gui
version=$GUI_VERSION
gui_lib=$GUI_LIB
gui_backup=$GUI_BACKUP
gui_sha256=$GUI_LIB_SHA
orig_owner=$orig_owner
orig_sha256=$orig_sha256
install_time=$(date +%Y-%m-%dT%H:%M:%S%z)
EOF
    chmod 644 "$_tmp"
    mv -f "$_tmp" "$GUI_MANIFEST"
    ok "GUI install recorded in $GUI_MANIFEST"
}

verify_install() {
    if [ -n "$DRY_RUN" ]; then
        dry "verify: the installed library resolves scx_mlfq (strings) and links cleanly (ldd)"
        return 0
    fi

    if [ "$(strings "$GUI_LIB" 2>/dev/null | grep -c 'scx_mlfq')" -ge 1 ]; then
        ok 'the installed library carries the patched scheduler list'
    else
        warn 'the installed library does not contain scx_mlfq; the GUI will still reject it'
    fi
    if [ "$(ldd /usr/bin/scx-manager 2>/dev/null | grep -c 'libscxctl-ui.so.1')" -ge 1 ] \
       && [ "$(ldd /usr/bin/scx-manager 2>/dev/null | grep -c 'not found')" -eq 0 ]; then
        ok 'scx-manager resolves the installed library'
    else
        warn 'scx-manager does not resolve libscxctl-ui.so.1'
    fi
}

cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        case "$BUILD_DIR" in
            /tmp/scx_mlfq-gui-build.*) rm -rf -- "$BUILD_DIR" ;;
            *) warn "not removing unexpected build dir: $BUILD_DIR" ;;
        esac
    fi
}

main() {
    step 'scx_mlfq GUI patch installer for CachyOS'
    check_root

    if [ -n "$DRY_RUN" ]; then
        warn 'DRY-RUN: validating inputs and printing actions only; no clone, no build, no changes.'
    fi

    step 'Checking build dependencies'
    check_build_deps

    step 'Checking the current GUI library'
    check_lib_conflict

    # Idempotency: a previous run whose library still matches the manifest
    # record needs no rebuild.
    if [ -f "$GUI_MANIFEST" ]; then
        recorded=$(sed -n 's/^gui_sha256=//p' "$GUI_MANIFEST")
        if [ -n "$recorded" ] && [ "$(sha256_of "$GUI_LIB")" = "$recorded" ]; then
            info 'the patched GUI library is already installed and matches the manifest'
            if [ -n "$DRY_RUN" ]; then
                printf '\n=== DRY-RUN complete - nothing to do ===\n'
            else
                printf '\n=== patched GUI library already installed ===\n'
            fi
            exit 0
        fi
        info 'the installed library differs from the manifest record; rebuilding'
    fi

    step 'Cloning and patching the GUI project'
    clone_and_vendor

    step 'Installing the patched library'
    install_lib

    step 'Recording the install'
    record_manifest

    step 'Verifying the install'
    verify_install

    if [ -n "$DRY_RUN" ]; then
        printf '\n=== DRY-RUN complete - nothing was installed or changed ===\n'
        return 0
    fi

    printf '\n=== patched GUI library installed ===\n'
    printf 'The Kernel Manager scheduler page and scx-manager now know\n'
    printf 'scx_mlfq: selecting it shows no flag error and Apply works.\n'
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
