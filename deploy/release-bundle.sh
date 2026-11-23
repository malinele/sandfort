#!/usr/bin/env bash
# Build and sign the self-host install bundle for a tag, from the wheels that
# deploy/release-wheels.sh produced.
#
#   SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release \
#       deploy/release-bundle.sh <tag> <wheels-dir> [out-dir]
#
# wheels-dir is the output directory of release-wheels.sh: the server, SDK and CLI wheels,
# SHA256SUMS, SHA256SUMS.sig, release-allowed-signers and RELEASE.txt. out-dir defaults to
# dist/<tag>-bundle. Output: sandfort-selfhost-<tag>.tar.gz (one top directory of the same
# name) and a copy of its BUNDLE-SHA256SUMS and BUNDLE-SHA256SUMS.sig beside it.
#
# The bundle holds the wheels and their signature files, deploy/host-setup.sh,
# deploy/node-setup.sh, deploy/seccomp.json, deploy/selfhost/{Dockerfile,compose.yml,
# sandfort.env.example}, INSTALL.md, and RELEASE.txt. BUNDLE-SHA256SUMS covers every other
# file and is signed with the same key and namespace as the wheels, so a partner checks one
# signature for the whole bundle. See docs/release.md.
#
# Safety checks: the wheels in wheels-dir must verify against their own signature, and the
# deploy files are taken from this checkout, so HEAD must equal the commit named in
# RELEASE.txt and deploy/ must be clean. SANDFORT_BUNDLE_UNSAFE=1 skips those two checks (tests
# only).
set -euo pipefail

NAMESPACE="sandfort-release"
PRINCIPAL="release@sandfort.dev"

die() {
    echo "release-bundle: $*" >&2
    exit 1
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || die "usage: release-bundle.sh <tag> <wheels-dir> [out-dir]"
TAG="$1"
WHEELS_DIR="$2"
case "$TAG" in
    "" | *[!A-Za-z0-9._-]* | -* ) die "tag may hold only letters, digits, dot, underscore, hyphen" ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${3:-dist/$TAG-bundle}"
NAME="sandfort-selfhost-$TAG"

[ -n "${SANDFORT_RELEASE_KEY:-}" ] || die "SANDFORT_RELEASE_KEY is not set (SSH signing key path)"
[ -f "$SANDFORT_RELEASE_KEY" ] || die "SANDFORT_RELEASE_KEY does not point to a file"
[ -d "$WHEELS_DIR" ] || die "wheels dir not found: $WHEELS_DIR"
for tool in tar ssh-keygen shasum sort awk sed; do
    command -v "$tool" >/dev/null || die "required tool not found: $tool"
done
WHEELS_DIR="$(cd "$WHEELS_DIR" && pwd)"

# Files that ship from this checkout, as published path -> source path.
DEPLOY_FILES=(
    deploy/host-setup.sh
    deploy/node-setup.sh
    deploy/seccomp.json
    deploy/selfhost/Dockerfile
    deploy/selfhost/compose.yml
    deploy/selfhost/sandfort.env.example
)
for file in "${DEPLOY_FILES[@]}" deploy/selfhost/INSTALL.md; do
    [ -f "$ROOT/$file" ] || die "missing $ROOT/$file"
done

# 1) the wheels dir holds exactly the expected release output
SERVER_WHEELS=() SDK_WHEELS=() CLI_WHEELS=()
while IFS= read -r wheel; do
    case "$wheel" in
        sandfort-[0-9]*.whl) SERVER_WHEELS+=("$wheel") ;;
        sandfort_sdk-*.whl) SDK_WHEELS+=("$wheel") ;;
        sandfort_cli-*.whl) CLI_WHEELS+=("$wheel") ;;
        *) die "unexpected wheel in $WHEELS_DIR: $wheel" ;;
    esac
done < <(cd "$WHEELS_DIR" && ls -1 ./*.whl 2>/dev/null | sed 's|^\./||')
[ "${#SERVER_WHEELS[@]}" -eq 1 ] || die "expected exactly one server wheel (sandfort-*.whl)"
[ "${#SDK_WHEELS[@]}" -eq 1 ] || die "expected exactly one SDK wheel (sandfort_sdk-*.whl)"
[ "${#CLI_WHEELS[@]}" -eq 1 ] || die "expected exactly one CLI wheel (sandfort_cli-*.whl)"
for file in SHA256SUMS SHA256SUMS.sig release-allowed-signers RELEASE.txt; do
    [ -f "$WHEELS_DIR/$file" ] || die "missing $WHEELS_DIR/$file (run deploy/release-wheels.sh)"
done

# 2) the wheels are what release-wheels.sh signed
(
    cd "$WHEELS_DIR"
    ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
        -s SHA256SUMS.sig < SHA256SUMS > /dev/null
    shasum -a 256 -c SHA256SUMS > /dev/null
) || die "the wheels in $WHEELS_DIR do not match their signature"
for wheel in "${SERVER_WHEELS[0]}" "${SDK_WHEELS[0]}" "${CLI_WHEELS[0]}"; do
    grep -q " ${wheel}\$" "$WHEELS_DIR/SHA256SUMS" || die "$wheel is not listed in SHA256SUMS"
done

# 3) the deploy files come from the commit the wheels were built from
if [ "${SANDFORT_BUNDLE_UNSAFE:-}" != "1" ]; then
    command -v git >/dev/null || die "required tool not found: git"
    WHEEL_COMMIT="$(awk '/^built from sandfort/ { print $5; exit }' "$WHEELS_DIR/RELEASE.txt")"
    [ -n "$WHEEL_COMMIT" ] || die "RELEASE.txt names no commit"
    HEAD_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
    [ "$HEAD_COMMIT" = "$WHEEL_COMMIT" ] \
        || die "HEAD $HEAD_COMMIT is not the wheels' commit $WHEEL_COMMIT"
    [ -z "$(git -C "$ROOT" status --porcelain -- deploy)" ] || die "deploy/ is not clean"
fi

# 4) stage the bundle
STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sandfort-bundle.XXXXXX")"
trap 'rm -rf "$STAGE_ROOT"' EXIT
STAGE="$STAGE_ROOT/$NAME"
mkdir -p "$STAGE/deploy/selfhost"
for wheel in "${SERVER_WHEELS[0]}" "${SDK_WHEELS[0]}" "${CLI_WHEELS[0]}" SHA256SUMS \
    SHA256SUMS.sig release-allowed-signers; do
    cp -p "$WHEELS_DIR/$wheel" "$STAGE/$wheel"
done
for file in "${DEPLOY_FILES[@]}"; do
    cp -p "$ROOT/$file" "$STAGE/$file"
done
cp -p "$ROOT/deploy/selfhost/INSTALL.md" "$STAGE/INSTALL.md"
{
    cat "$WHEELS_DIR/RELEASE.txt"
    printf 'bundle: %s.tar.gz (tag %s)\n' "$NAME" "$TAG"
    printf 'verify the bundle with: ssh-keygen -Y verify -f release-allowed-signers -I %s -n %s' \
        "$PRINCIPAL" "$NAMESPACE"
    printf ' -s BUNDLE-SHA256SUMS.sig < BUNDLE-SHA256SUMS\n'
    printf 'then: sha256sum -c BUNDLE-SHA256SUMS\n'
} > "$STAGE/RELEASE.txt"

# 5) sums over every file, then the signature over the sums
(
    cd "$STAGE"
    find . -type f ! -name BUNDLE-SHA256SUMS ! -name BUNDLE-SHA256SUMS.sig \
        | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r file; do
            shasum -a 256 "$file"
        done > BUNDLE-SHA256SUMS
    rm -f BUNDLE-SHA256SUMS.sig
    ssh-keygen -Y sign -f "$SANDFORT_RELEASE_KEY" -n "$NAMESPACE" BUNDLE-SHA256SUMS
    [ -f BUNDLE-SHA256SUMS.sig ] || die "signing did not produce BUNDLE-SHA256SUMS.sig"
)

# 6) pack
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TARBALL="$OUT/$NAME.tar.gz"
rm -f "$TARBALL"
# COPYFILE_DISABLE keeps macOS tar from adding ._ metadata files to the archive.
COPYFILE_DISABLE=1 tar -czf "$TARBALL" -C "$STAGE_ROOT" "$NAME"
cp "$STAGE/BUNDLE-SHA256SUMS" "$STAGE/BUNDLE-SHA256SUMS.sig" "$OUT/"

# 7) verify the tarball as a partner would: unpack, check the signature, check the sums
CHECK_DIR="$STAGE_ROOT/check"
mkdir -p "$CHECK_DIR"
tar -xzf "$TARBALL" -C "$CHECK_DIR"
(
    cd "$CHECK_DIR/$NAME"
    ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
        -s BUNDLE-SHA256SUMS.sig < BUNDLE-SHA256SUMS
    shasum -a 256 -c BUNDLE-SHA256SUMS
) || die "the finished tarball does not verify"

echo "bundle ok: $TARBALL"
shasum -a 256 "$TARBALL"
