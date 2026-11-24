#!/usr/bin/env bash
# sandfort node preparation: makes Docker on a fresh Ubuntu 24.04 sandbox node ready for the
# isolation tiers (container, gvisor, microvm) and for per-sandbox disk quotas.
#
#   sudo bash deploy/node-setup.sh --dry-run | [--with-kata] [--default-runtime-runsc]
#        [--userns-remap] [--live-restore] [--with-slice] | --rollback
#        bash deploy/node-setup.sh --check     # verify only; changes nothing
#   Kata needs KATA_SHA256=<sha256 of the tarball>; see --help for all flags.
#
# Steps (each guarded, so a re-run on a prepared node changes nothing):
#   1. /var/lib/docker (DOCKER_ROOT) must be on XFS with pquota; the script never formats or
#      mounts a disk, it prints instructions and exits 1. daemon.json gets "storage-driver":
#      "overlay2" and "features": {"containerd-snapshotter": false}, merged with jq; the
#      original is saved once as daemon.json.sandfort-orig.
#   2. gVisor: pinned release (GVISOR_RELEASE). Downloads <base>/<release>/<arch>/gvisor.tar.bz2
#      and gvisor.tar.bz2.sha512, verifies the file against the sha512 pinned in this script
#      (default release, x86_64) or GVISOR_SHA512, then against the downloaded sha512 file (a
#      secondary check); other releases die without GVISOR_SHA512 unless --unpinned.
#      Extracts into a temp dir and installs
#      runsc and containerd-shim-runsc-v1 (0755) into the directory of GVISOR_BIN, plus the
#      gvisor-bin helper directory next to them (gvisor_sentry and others; replaced by rename).
#      On HTTP 404 (older releases) it falls back to the bare <arch>/runsc + runsc.sha512 layout.
#      Runtime "runsc" with runtimeArgs ["--overlay2=none", "--file-access=shared"].
#   3. Kata (--with-kata): needs /dev/kvm and the operator's KATA_SHA256 (no hash, no install);
#      runtime "kata" (io.containerd.kata.v2) on the Rust runtime shim.
#   4. docker reload (restart with a warning when reload cannot apply it), then smoke tests.
#   5. Opt-in daemon settings (merged into daemon.json like the rest): --default-runtime-runsc
#      ("default-runtime": "runsc", so image builds stop running on plain runc), --userns-remap
#      ("userns-remap": "default"; moves the daemon data root), --live-restore ("live-restore":
#      true). --with-slice creates and enables sandfort.slice, the cgroup parent for sandboxes.
#   6. --rollback restores the daemon.json backup and reloads docker; binaries and the slice stay.
# Afterwards run deploy/host-setup.sh as root now and on every boot. No secrets are used.

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail

GVISOR_DEFAULT_RELEASE="20261102.0"
GVISOR_RELEASE="${GVISOR_RELEASE:-$GVISOR_DEFAULT_RELEASE}"
# Pinned sha512 of the default release's x86_64 gvisor.tar.bz2 (split to keep lines short).
GV_PIN_X86_64="2e6671bb2d033b871c5811ab57e16ac570988b0e"
GV_PIN_X86_64+="0054c525f911cfaf191bab3ca4efb08e0a98daa4b9e7"
GV_PIN_X86_64+="d248f9e5776ef2ef2f8a6b82d829646a42924c98bb05"
# Other releases or architectures need GVISOR_SHA512=<sha512 of the file> or --unpinned.
GVISOR_SHA512="${GVISOR_SHA512:-}"
GVISOR_PIN="" UNPINNED=0
GVISOR_BASE_URL="${GVISOR_BASE_URL:-https://storage.googleapis.com/gvisor/releases/release}"
GVISOR_BIN="${GVISOR_BIN:-/usr/local/bin/runsc}"
GVISOR_HELPER_DIR="gvisor-bin"  # helper binaries shipped in the tarball, installed beside runsc
GVISOR_ARGS_JSON='["--overlay2=none","--file-access=shared"]'
KATA_VERSION="${KATA_VERSION:-4.3.1}"
KATA_SHA256="${KATA_SHA256:-}"
KATA_URL_BASE="${KATA_URL_BASE:-https://github.com/kata-containers/kata-containers/releases/download}"
KATA_PREFIX="${KATA_PREFIX:-/opt/kata}"
KATA_SHIM="$KATA_PREFIX/runtime-rs/bin/containerd-shim-kata-v2"
KATA_CONFIG_SRC="${KATA_CONFIG_SRC:-$KATA_PREFIX/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml}"
KATA_CONFIG="${KATA_CONFIG:-/etc/kata-containers/configuration.toml}"
KATA_SHIM_LINK="${KATA_SHIM_LINK:-/usr/local/bin/containerd-shim-kata-v2}"
DAEMON_JSON="${DAEMON_JSON:-/etc/docker/daemon.json}"
DOCKER_ROOT="${DOCKER_ROOT:-/var/lib/docker}"
BACKUP="$DAEMON_JSON.sandfort-orig"
SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"
NODE_LABEL="sandfort.dev/sandbox-node"
SMOKE_IMAGE="alpine:3.20"

SLICE_NAME="sandfort.slice"
SLICE_UNIT="${SLICE_UNIT:-/etc/systemd/system/$SLICE_NAME}"

DRY_RUN=0 WITH_KATA=0 DEFAULT_RUNSC=0 USERNS_REMAP=0 LIVE_RESTORE=0 WITH_SLICE=0 MODE=apply DESIRED="{}" JSON_CHANGED=0 STORAGE_FAILED=0
TMP_DIR="" GV_ARCH="" KATA_ARCH=""

say() { printf 'node-setup: %s\n' "$*"; }
warn() { printf 'node-setup: WARNING: %s\n' "$*" >&2; }
die() { printf 'node-setup: ERROR: %s\n' "$*" >&2; exit 1; }
plan() { printf 'node-setup: [dry-run] would %s\n' "$*"; }
trap '[ -z "$TMP_DIR" ] || rm -rf "$TMP_DIR"' EXIT

usage() {
    cat <<'EOF'
usage: node-setup.sh [--dry-run] [--with-kata] [--default-runtime-runsc] [--userns-remap]
                     [--live-restore] [--with-slice] | --rollback | --check
  --dry-run    print every action and the daemon.json diff; change nothing
  --with-kata  also install Kata Containers (needs /dev/kvm and KATA_SHA256=<sha256 of the tarball>)
  --default-runtime-runsc
               set the daemon default runtime to runsc (gVisor), so tenant image builds no
               longer run on plain runc (applied with a docker restart)
  --userns-remap
               enable daemon-wide user-namespace remapping ("userns-remap": "default"); this
               MOVES the daemon data root: images must be pulled again and existing containers
               are no longer visible (applied with a docker restart)
  --live-restore
               enable live-restore, so running containers survive a daemon restart
  --with-slice create and enable the systemd slice sandfort.slice, the cgroup parent target
  --rollback   restore the daemon.json saved before the first change, then reload docker
  --check      verify storage and runtimes only; prints the Docker socket group id and
               the kubectl label/taint commands (changes nothing)
  --unpinned   allow a gVisor release/arch without a pinned sha512 (trusts the download origin)
environment: GVISOR_RELEASE, GVISOR_SHA512, KATA_VERSION, KATA_SHA256, NODE_NAME
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --with-kata) WITH_KATA=1 ;;
            --default-runtime-runsc) DEFAULT_RUNSC=1 ;;
            --userns-remap) USERNS_REMAP=1 ;;
            --live-restore) LIVE_RESTORE=1 ;;
            --with-slice) WITH_SLICE=1 ;;
            --unpinned) UNPINNED=1 ;;
            --rollback) MODE=rollback ;;
            --check) MODE=check ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; exit 2 ;;
        esac
        shift
    done
}

# Decide the expected gVisor sha512: GVISOR_SHA512 wins, else the pin for the default release
# on x86_64. With no pin the run dies unless --unpinned was given.
resolve_gvisor_pin() {
    GVISOR_PIN="${GVISOR_SHA512,,}"
    if [ -z "$GVISOR_PIN" ] && [ "$GVISOR_RELEASE" = "$GVISOR_DEFAULT_RELEASE" ] \
        && [ "$GV_ARCH" = "x86_64" ]; then
        GVISOR_PIN="$GV_PIN_X86_64"
    fi
    if [ -n "$GVISOR_PIN" ]; then
        [[ "$GVISOR_PIN" =~ ^[0-9a-f]{128}$ ]] || die "GVISOR_SHA512 is not a 128-digit hex sha512"
    elif [ "$UNPINNED" -eq 1 ]; then
        warn "no pinned sha512 for gVisor $GVISOR_RELEASE ($GV_ARCH); --unpinned trusts the origin"
    else
        die "no pinned sha512 for gVisor $GVISOR_RELEASE ($GV_ARCH); set GVISOR_SHA512 or --unpinned"
    fi
}

preflight() {
    [ "$(uname -s)" = "Linux" ] || die "Linux hosts only"
    command -v docker >/dev/null 2>&1 || die "docker CLI not found; install Docker Engine first"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    if [ "$MODE" != "check" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
        die "run as root (sudo), or add --dry-run"
    fi
    if ! (. /etc/os-release 2>/dev/null && [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_ID:-}" = "24.04" ]); then
        warn "this script is written for Ubuntu 24.04; continuing on another system"
    fi
    [ "$MODE" = "apply" ] || return 0
    case "$(uname -m)" in
        x86_64) GV_ARCH="x86_64"; KATA_ARCH="amd64" ;;
        aarch64) GV_ARCH="aarch64"; KATA_ARCH="arm64" ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
    resolve_gvisor_pin
    [ "$WITH_KATA" -eq 1 ] || return 0
    [ -c /dev/kvm ] || die "--with-kata needs /dev/kvm (enable virtualization or nested KVM)"
    [ -n "$KATA_SHA256" ] || die "refusing to install Kata without KATA_SHA256 (sha256 of kata-static-$KATA_VERSION-$KATA_ARCH.tar.xz)"
    [[ "$KATA_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die "KATA_SHA256 is not a 64-digit hex sha256"
}

ensure_tools() {
    local missing=""  # packages to install
    command -v jq >/dev/null 2>&1 || missing="$missing jq"
    command -v curl >/dev/null 2>&1 || missing="$missing curl"
    command -v bzip2 >/dev/null 2>&1 || missing="$missing bzip2"  # gvisor.tar.bz2
    if [ "$WITH_KATA" -eq 1 ] && ! command -v xz >/dev/null 2>&1; then missing="$missing xz-utils"; fi
    [ -n "$missing" ] || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        command -v jq >/dev/null 2>&1 || die "jq is needed to preview daemon.json changes: apt-get install -y jq"
        plan "apt-get install -y$missing"; return 0
    fi
    command -v apt-get >/dev/null 2>&1 || die "missing tools:$missing (install them and re-run)"
    say "installing:$missing"
    # shellcheck disable=SC2086  # $missing is a space-separated package list
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing
}

fetch() { # url, destination
    TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$2" "$1" || die "download failed: $1"
}

storage_ok() {
    local root target fstype opts
    root="$DOCKER_ROOT"
    target="$root"
    while [ ! -e "$target" ] && [ "$target" != "/" ]; do target="$(dirname "$target")"; done
    command -v findmnt >/dev/null 2>&1 || die "findmnt not found (util-linux)"
    fstype="$(findmnt -no FSTYPE -T "$target")"
    opts="$(findmnt -no OPTIONS -T "$target")"
    if [ "$fstype" = "xfs" ] && { [[ ",$opts," == *,pquota,* ]] || [[ ",$opts," == *,prjquota,* ]]; }; then
        say "storage: $root is on xfs with project quota ($opts)"
        return 0
    fi
    cat >&2 <<EOF
node-setup: FAIL: $root is on '$fstype' (options: $opts); disk quota needs XFS mounted with pquota.
node-setup: this script never formats or mounts anything. Prepare a data disk yourself:
    1. Pick an EMPTY disk (mkfs destroys its data), for example /dev/vdb:  mkfs.xfs /dev/vdb
    2. Add it to /etc/fstab, preferably by UUID (blkid /dev/vdb):
         UUID=<uuid>  $root  xfs  defaults,pquota  0  0
    3. systemctl stop docker; move old $root contents aside; mount $root (pquota cannot be
       added by a live remount: unmount and mount again). Check: findmnt -T $root
    4. Re-run this script.
EOF
    return 1
}

check_storage() {
    if storage_ok; then return 0; fi
    if [ "$DRY_RUN" -eq 0 ]; then exit 1; fi
    STORAGE_FAILED=1; warn "dry-run continues; a real run would stop here"
}

current_json() {
    if [ -s "$DAEMON_JSON" ]; then
        jq -e 'type == "object"' "$DAEMON_JSON" >/dev/null || die "$DAEMON_JSON is not a JSON object"
        jq -c . "$DAEMON_JSON"
    else
        echo '{}'
    fi
}

canon() { jq -S . <<<"$1"; }

merge_storage() {
    DESIRED="$(jq -c '. + {"storage-driver": "overlay2"} | .features = ((.features // {}) + {"containerd-snapshotter": false})' <<<"$DESIRED")"
}

merge_runtime() { # name, JSON object
    DESIRED="$(jq -c --arg name "$1" --argjson rt "$2" '.runtimes = ((.runtimes // {}) + {($name): $rt})' <<<"$DESIRED")"
}

# Opt-in daemon-wide settings, merged on top of whatever daemon.json already holds.
merge_options() {
    if [ "$DEFAULT_RUNSC" -eq 1 ]; then DESIRED="$(jq -c '. + {"default-runtime": "runsc"}' <<<"$DESIRED")"; fi
    if [ "$USERNS_REMAP" -eq 1 ]; then DESIRED="$(jq -c '. + {"userns-remap": "default"}' <<<"$DESIRED")"; fi
    if [ "$LIVE_RESTORE" -eq 1 ]; then DESIRED="$(jq -c '. + {"live-restore": true}' <<<"$DESIRED")"; fi
}

write_daemon_json() {
    local current tmp
    current="$(current_json)"
    if [ "$(canon "$current")" = "$(canon "$DESIRED")" ]; then
        say "$DAEMON_JSON is already up to date"
        return 0
    fi
    JSON_CHANGED=1
    if [ "$DRY_RUN" -eq 1 ]; then
        plan "write $DAEMON_JSON (original saved to $BACKUP first if no backup exists); diff:"
        diff <(canon "$current") <(canon "$DESIRED") || true
        return 0
    fi
    mkdir -p "$(dirname "$DAEMON_JSON")"
    if [ ! -e "$BACKUP" ]; then
        if [ -f "$DAEMON_JSON" ]; then cp -p "$DAEMON_JSON" "$BACKUP"; else echo '{}' >"$BACKUP"; fi; say "saved the original to $BACKUP"
    fi
    tmp="$(mktemp "$DAEMON_JSON.XXXXXX")"
    canon "$DESIRED" >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$DAEMON_JSON"
    say "wrote $DAEMON_JSON"
}

# Download url to dest; return 1 on HTTP 404 (caller may fall back), die on any other failure.
fetch_or_404() { # url, destination
    local code
    TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
    code="$(curl -sSL --retry 3 --proto '=https' --tlsv1.2 -o "$2" -w '%{http_code}' "$1")" \
        || die "download failed: $1"
    case "$code" in
        200) return 0 ;;
        404) return 1 ;;
        *) die "download failed: $1 (HTTP $code)" ;;
    esac
}

verify_sha512() { # file, sha512 file, label
    local want got
    got="$(sha512sum "$1" | awk '{print $1}')"
    if [ -n "$GVISOR_PIN" ] && [ "$GVISOR_PIN" != "$got" ]; then
        die "pinned sha512 mismatch for $3 $GVISOR_RELEASE (pinned '$GVISOR_PIN', got '$got')"
    fi
    want="$(awk '{print tolower($1); exit}' "$2")"  # secondary check: same origin as the file
    [ -n "$want" ] && [ "$want" = "$got" ] \
        || die "sha512 mismatch for $3 $GVISOR_RELEASE (expected '$want', got '$got')"
}

# Put directory $1 at $2, replacing an existing one with two renames in the same directory.
replace_dir() { # source, target
    local new="$2.new.$$" old="$2.old.$$"
    rm -rf "$new" "$old"
    cp -a "$1" "$new"
    if [ -e "$2" ]; then mv -T "$2" "$old"; fi
    mv -T "$new" "$2"
    rm -rf "$old"
}

# Releases since 2026 ship one tarball per architecture: runsc, containerd-shim-runsc-v1 and
# the gvisor-bin helper directory that the runsc launcher expects next to itself.
install_gvisor_tarball() { # tarball path in TMP_DIR
    local bindir="$(dirname "$GVISOR_BIN")" ex="$TMP_DIR/gvisor-extract"
    verify_sha512 "$TMP_DIR/gvisor.tar.bz2" "$TMP_DIR/gvisor.tar.bz2.sha512" "gvisor.tar.bz2"
    mkdir -p "$ex"
    tar -xjf "$TMP_DIR/gvisor.tar.bz2" -C "$ex"
    [ -f "$ex/runsc" ] && [ -f "$ex/containerd-shim-runsc-v1" ] && [ -d "$ex/$GVISOR_HELPER_DIR" ] \
        || die "gvisor.tar.bz2 lacks runsc, containerd-shim-runsc-v1 or $GVISOR_HELPER_DIR"
    mkdir -p "$bindir"
    install -m 0755 "$ex/runsc" "$GVISOR_BIN"
    install -m 0755 "$ex/containerd-shim-runsc-v1" "$bindir/containerd-shim-runsc-v1"
    replace_dir "$ex/$GVISOR_HELPER_DIR" "$bindir/$GVISOR_HELPER_DIR"
    say "installed helper directory $bindir/$GVISOR_HELPER_DIR next to $GVISOR_BIN"
}

# Older releases: a bare runsc binary with its own sha512 file.
install_gvisor_bare() { # url
    fetch "$1/runsc" "$TMP_DIR/runsc"
    fetch "$1/runsc.sha512" "$TMP_DIR/runsc.sha512"
    verify_sha512 "$TMP_DIR/runsc" "$TMP_DIR/runsc.sha512" "runsc"
    mkdir -p "$(dirname "$GVISOR_BIN")"
    install -m 0755 "$TMP_DIR/runsc" "$GVISOR_BIN"
}

install_gvisor() {
    local url="$GVISOR_BASE_URL/$GVISOR_RELEASE/$GV_ARCH"
    if [ -x "$GVISOR_BIN" ] \
        && "$GVISOR_BIN" --version 2>/dev/null | grep -qF "release-$GVISOR_RELEASE"; then
        say "gVisor release-$GVISOR_RELEASE already installed at $GVISOR_BIN"
    elif [ "$DRY_RUN" -eq 1 ]; then
        plan "download $url/gvisor.tar.bz2 and gvisor.tar.bz2.sha512, verify, extract"
        plan "install runsc to $GVISOR_BIN, containerd-shim-runsc-v1 and the helper directory"
        plan "$GVISOR_HELPER_DIR next to it; on HTTP 404 fall back to $url/runsc and runsc.sha512"
    else
        if fetch_or_404 "$url/gvisor.tar.bz2" "$TMP_DIR/gvisor.tar.bz2"; then
            fetch "$url/gvisor.tar.bz2.sha512" "$TMP_DIR/gvisor.tar.bz2.sha512"
            install_gvisor_tarball
        else
            warn "no gvisor.tar.bz2 for release $GVISOR_RELEASE; using the bare runsc layout"
            install_gvisor_bare "$url"
        fi
        say "installed $("$GVISOR_BIN" --version | head -n 1) (sha512 verified)"
        [ -n "$GVISOR_PIN" ] || warn "gVisor was installed without a pinned sha512 (--unpinned)"
    fi
    merge_runtime runsc "$(jq -nc --arg path "$GVISOR_BIN" --argjson args "$GVISOR_ARGS_JSON" \
        '{path: $path, runtimeArgs: $args}')"
}

link_to() { # target, link
    if [ "$(readlink "$2" 2>/dev/null || true)" = "$1" ]; then
        say "$2 already points to $1"
    elif [ "$DRY_RUN" -eq 1 ]; then
        plan "ln -sfn $1 $2"
    else
        mkdir -p "$(dirname "$2")"
        ln -sfn "$1" "$2"
    fi
}

install_kata() {
    local marker="$KATA_PREFIX/.sandfort-installed" want="$KATA_VERSION $KATA_SHA256" file url
    file="kata-static-$KATA_VERSION-$KATA_ARCH.tar.xz"
    url="$KATA_URL_BASE/$KATA_VERSION/$file"
    if [ "$(cat "$marker" 2>/dev/null || true)" = "$want" ]; then
        say "Kata $KATA_VERSION (pinned sha256) already installed in $KATA_PREFIX"
    elif [ "$DRY_RUN" -eq 1 ]; then
        plan "download $url, verify sha256 $KATA_SHA256, extract into /, record $marker"
    else
        fetch "$url" "$TMP_DIR/$file"
        echo "$KATA_SHA256  $TMP_DIR/$file" | sha256sum -c - >/dev/null || die "sha256 mismatch for $file; nothing was installed"
        tar -xJf "$TMP_DIR/$file" -C /   # official layout: ./opt/kata/...
        [ -x "$KATA_SHIM" ] || die "Rust runtime shim not found at $KATA_SHIM; use a Kata release that ships runtime-rs"
        printf '%s\n' "$want" >"$marker"
        say "installed Kata $KATA_VERSION (sha256 verified)"
    fi
    link_to "$KATA_SHIM" "$KATA_SHIM_LINK"
    if [ -e "$KATA_CONFIG" ] && [ "$(readlink "$KATA_CONFIG" 2>/dev/null || true)" != "$KATA_CONFIG_SRC" ]; then
        say "keeping the existing $KATA_CONFIG (it must be a runtime-rs configuration)"
    else
        link_to "$KATA_CONFIG_SRC" "$KATA_CONFIG"
    fi
    merge_runtime kata '{"runtimeType": "io.containerd.kata.v2"}'
}

runtimes_registered() {
    docker info --format '{{range $name, $_ := .Runtimes}}{{$name}} {{end}}' 2>/dev/null || true
}

# True when daemon.json content $1 sets a storage driver or image store the running daemon
# does not use; reload cannot apply those, only a restart can.
storage_differs() {
    local want_driver want_snapshotter run_driver run_snapshotter=false
    want_driver="$(jq -r '."storage-driver" // ""' <<<"$1")"
    want_snapshotter="$(jq -r 'if ((.features | type) == "object") and (.features | has("containerd-snapshotter")) then (.features["containerd-snapshotter"] | tostring) else "" end' <<<"$1")"
    run_driver="$(docker info --format '{{.Driver}}' 2>/dev/null || true)"
    if docker info --format '{{json .DriverStatus}}' 2>/dev/null | grep -q 'io.containerd.snapshotter'; then
        run_snapshotter=true
    fi
    if [ -n "$want_driver" ] && [ "$want_driver" != "$run_driver" ]; then return 0; fi
    if [ -n "$want_snapshotter" ] && [ "$want_snapshotter" != "$run_snapshotter" ]; then return 0; fi
    return 1
}

userns_active() { docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q 'name=userns'; }

live_restore_active() { [ "$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null || true)" = "true" ]; }

# True when daemon.json content $1 sets a default runtime or user-namespace remapping the
# running daemon does not have, or a storage setting (see storage_differs); only a restart applies those.
restart_needed() {
    local want_runtime run_runtime want_userns run_userns=false
    if storage_differs "$1"; then return 0; fi
    want_runtime="$(jq -r '."default-runtime" // ""' <<<"$1")"
    run_runtime="$(docker info --format '{{.DefaultRuntime}}' 2>/dev/null || true)"
    if [ -n "$want_runtime" ] && [ "$want_runtime" != "$run_runtime" ]; then return 0; fi
    want_userns="$(jq -r '."userns-remap" // ""' <<<"$1")"
    if userns_active; then run_userns=true; fi
    if [ -n "$want_userns" ] && [ "$run_userns" = false ]; then return 0; fi
    return 1
}

wait_docker() {
    local _
    for _ in $(seq 1 30); do
        if docker info >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    die "the Docker daemon did not answer within 30 s"
}

restart_docker() {
    systemctl restart docker || die "systemctl restart docker failed"
    wait_docker
    say "docker restarted"
}

reload_docker() { # $1 = daemon.json content the daemon should end up with
    if restart_needed "$1"; then
        warn "storage, default-runtime or userns-remap settings differ from the running daemon; a reload cannot apply them, restarting docker."
        warn "running containers stop unless live-restore is on; images of another storage driver, image store or userns-remap data root become invisible."
        restart_docker
    elif systemctl reload docker; then
        wait_docker
        say "docker reloaded"
    else
        warn "systemctl reload docker failed; falling back to a restart"
        restart_docker
    fi
}

wait_runtime() {
    local name="$1" _
    for _ in $(seq 1 15); do
        case " $(runtimes_registered)" in *" $name "*) return 0 ;; esac
        sleep 1
    done
    die "runtime $name is not registered with the running Docker daemon"
}

reload_if_needed() {
    local runtime need=0
    if [ "$JSON_CHANGED" -eq 1 ]; then need=1; fi
    if [ "$DRY_RUN" -eq 0 ]; then
        for runtime in runsc $([ "$WITH_KATA" -eq 1 ] && echo kata); do
            case " $(runtimes_registered)" in *" $runtime "*) ;; *) need=1 ;; esac
        done
        if restart_needed "$DESIRED"; then need=1; fi
        if [ "$LIVE_RESTORE" -eq 1 ] && ! live_restore_active; then need=1; fi
    fi
    if [ "$need" -eq 0 ]; then say "docker already runs this configuration; no reload"; return 0; fi
    if [ "$DRY_RUN" -eq 1 ]; then plan "systemctl reload docker (restart if storage settings need it, or reload fails)"; return 0; fi
    reload_docker "$DESIRED"
}

smoke_test() { # runtime
    local out host="$(uname -r)"
    if [ "$DRY_RUN" -eq 1 ]; then plan "docker run --rm --runtime=$1 $SMOKE_IMAGE uname -r"; return 0; fi
    wait_runtime "$1"
    docker pull -q "$SMOKE_IMAGE" >/dev/null || die "cannot pull $SMOKE_IMAGE"
    local userns_args=()  # Kata cannot run in a remapped user namespace: opt out per container
    if [ "$1" = "kata" ] && userns_active; then userns_args=(--userns=host); fi
    out="$(docker run --rm --runtime="$1" "${userns_args[@]}" "$SMOKE_IMAGE" uname -r 2>&1)" || { printf '%s\n' "$out" >&2; die "smoke test failed for runtime $1"; }
    out="$(printf '%s\n' "$out" | tail -n 1)"
    say "smoke test runtime=$1: kernel '$out' (host kernel '$host')"
    [ "$out" != "$host" ] || die "runtime $1 reports the host kernel; it is not isolating the sandbox"
}

install_slice() {
    local want
    want="$(printf '[Unit]\nDescription=Sandfort sandbox cgroup parent\nBefore=slices.target\n\n[Slice]\n\n[Install]\nWantedBy=slices.target')"
    if [ "$(cat "$SLICE_UNIT" 2>/dev/null || true)" = "$want" ] && systemctl is-enabled --quiet "$SLICE_NAME" 2>/dev/null; then
        say "$SLICE_NAME already installed and enabled"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then plan "write $SLICE_UNIT, systemctl daemon-reload, enable and start $SLICE_NAME"; return 0; fi
    printf '%s\n' "$want" >"$SLICE_UNIT"
    systemctl daemon-reload
    systemctl enable "$SLICE_NAME" >/dev/null 2>&1 || die "systemctl enable $SLICE_NAME failed"
    systemctl start "$SLICE_NAME" || die "systemctl start $SLICE_NAME failed"
    say "installed and enabled $SLICE_NAME (cgroup parent for sandboxes)"
}

# The three daemon facts after the change, plus reminders for the settings that need them.
daemon_facts() {
    local runtime userns=off live=off
    runtime="$(docker info --format '{{.DefaultRuntime}}' 2>/dev/null || echo unknown)"
    if userns_active; then userns=on; fi
    if live_restore_active; then live=on; fi
    say "daemon default runtime: $runtime; userns remap: $userns; live-restore: $live"
    if [ "$userns" = on ] || [ "$USERNS_REMAP" -eq 1 ]; then
        warn "userns-remap moves the daemon data root (a dockremap-suffixed directory under $DOCKER_ROOT): images must be pulled again and existing containers are no longer visible."
        warn "the Kata (microvm) tier cannot run in a remapped user namespace; it needs the per-container host-userns opt-out the server now applies."
    fi
}

report() {
    local tiers="container=runc,gvisor=runsc"
    case " $(runtimes_registered)" in *" kata "*) tiers="$tiers,microvm=kata" ;; esac
    say "docker storage driver: $(docker info --format '{{.Driver}}' 2>/dev/null || echo unknown); runtimes: $(runtimes_registered)"
    daemon_facts
    if [ -S "$SOCKET" ]; then
        say "docker socket group id: $(stat -c %g "$SOCKET") (supplementalGroups in deploy/k8s/api.yaml)"
    fi
    say "server settings for this node:"
    printf '  SANDFORT_ISOLATION_RUNTIMES="%s"\n  SANDFORT_DEFAULT_ISOLATION=gvisor\n' "$tiers"
    say "Kubernetes (from a machine with kubectl access):"
    printf '  kubectl label node %s %s=true\n  kubectl taint node %s %s=true:NoSchedule\n' \
        "${NODE_NAME:-$(hostname)}" "$NODE_LABEL" "${NODE_NAME:-$(hostname)}" "$NODE_LABEL"
    say "next: run deploy/host-setup.sh as root now and again on every boot (egress rules)"
}

main_apply() {
    ensure_tools
    check_storage
    DESIRED="$(current_json)"
    merge_storage
    install_gvisor
    if [ "$WITH_KATA" -eq 1 ]; then install_kata; fi
    merge_options
    write_daemon_json
    if [ "$USERNS_REMAP" -eq 1 ] && [ "$DRY_RUN" -eq 1 ]; then
        plan "enable userns-remap: the daemon data root moves, images must be pulled again, existing containers become invisible; Kata needs the host-userns opt-out"
    fi
    if [ "$WITH_SLICE" -eq 1 ]; then install_slice; fi
    reload_if_needed
    smoke_test runsc
    if [ "$WITH_KATA" -eq 1 ]; then smoke_test kata; fi
    if [ "$DRY_RUN" -eq 0 ]; then report; fi
    if [ "$STORAGE_FAILED" -eq 1 ]; then exit 1; fi
}

main_rollback() {
    if [ ! -f "$BACKUP" ]; then
        say "no backup at $BACKUP; nothing to roll back"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        plan "restore $DAEMON_JSON from $BACKUP, remove the backup, reload docker"
        return 0
    fi
    ensure_tools
    cp -p "$BACKUP" "$DAEMON_JSON.restore"
    mv -f "$DAEMON_JSON.restore" "$DAEMON_JSON"
    rm -f "$BACKUP"
    say "restored $DAEMON_JSON"
    reload_docker "$(jq -c . "$DAEMON_JSON")"
    warn "storage-driver/features removed by the rollback only take effect after: systemctl restart docker"
    say "registered runtimes: $(runtimes_registered)"
}

main_check() {
    local failed=0
    storage_ok || failed=1
    case " $(runtimes_registered)" in
        *" runsc "*) say "runtime runsc (gVisor) is registered" ;;
        *) warn "runtime runsc is not registered with Docker"; failed=1 ;;
    esac
    report
    if [ "$failed" -ne 0 ]; then say "one or more checks failed"; fi
    return "$failed"
}

parse_args "$@"
preflight
case "$MODE" in
    apply) main_apply ;;
    rollback) main_rollback ;;
    check) main_check ;;
esac
