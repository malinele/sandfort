#!/usr/bin/env bash
# Build, sign and verify the release wheels (server + sdk + cli) for a tag.
#
#   SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release deploy/release-wheels.sh <tag> [out-dir]
#
# out-dir defaults to dist/<tag>. Output: three wheels (server, sdk, cli), SHA256SUMS,
# SHA256SUMS.sig, release-allowed-signers and RELEASE.txt (commit, server wheel, signing key
# fingerprint, verify command).
# See docs/release.md.
set -euo pipefail

NAMESPACE="sandfort-release"
PRINCIPAL="release@sandfort.dev"
STAMP_NAME="_build_info.json"

die() {
    echo "release-wheels: $*" >&2
    exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: release-wheels.sh <tag> [out-dir]"
TAG="$1"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${2:-dist/$TAG}"
SIGNERS="$ROOT/deploy/release-allowed-signers"

[ -n "${SANDFORT_RELEASE_KEY:-}" ] || die "SANDFORT_RELEASE_KEY is not set (SSH signing key path)"
[ -f "$SANDFORT_RELEASE_KEY" ] || die "SANDFORT_RELEASE_KEY does not point to a file"
[ -f "$SIGNERS" ] || die "missing $SIGNERS"
for tool in git pip shasum ssh-keygen python3; do
    command -v "$tool" >/dev/null || die "required tool not found: $tool"
done

# 1) clean tree, HEAD equals the tag's commit
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
TAG_COMMIT="$(git rev-parse --verify --quiet "refs/tags/$TAG^{commit}")" \
    || die "tag not found: $TAG"
COMMIT="$(git rev-parse HEAD)"
[ "$COMMIT" = "$TAG_COMMIT" ] || die "HEAD $COMMIT is not tag $TAG ($TAG_COMMIT)"

# 2) stamp, build, unstamp
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMPS=(
    "src/sandfort/$STAMP_NAME"
    "sdk/python/src/sandfort_sdk/$STAMP_NAME"
    "cli/src/sandfort_cli/$STAMP_NAME"
)
VENV_DIR=""
KEY_FILE=""
cleanup() {
    rm -f "${STAMPS[@]}"
    if [ -n "$KEY_FILE" ]; then rm -f "$KEY_FILE"; fi
    if [ -n "$VENV_DIR" ]; then rm -rf "$VENV_DIR"; fi
}
trap cleanup EXIT

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# The allowed-signers file travels with the wheels, so the verify recipe works from this directory.
cp "$SIGNERS" "$OUT/release-allowed-signers"

# Fingerprint of the first public key in the allowed-signers file (principal, optional options,
# key type and key, optional comment; preceded by comment lines). The key type is the first
# field that looks like one, so an options field does not shift the columns. The trap removes
# the temporary file even when ssh-keygen fails.
KEY_AWK='!/^#/ && NF { for (i = 2; i < NF; i++)
    if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $i, $(i + 1); exit } }'
KEY_FILE="$(mktemp "${TMPDIR:-/tmp}/sandfort-release-key.XXXXXX")"
awk "$KEY_AWK" "$SIGNERS" > "$KEY_FILE"
FINGERPRINT="$(ssh-keygen -lf "$KEY_FILE")" || die "cannot read a public key from $SIGNERS"
VERIFY_CMD="ssh-keygen -Y verify -f release-allowed-signers -I $PRINCIPAL -n $NAMESPACE"
VERIFY_CMD="$VERIFY_CMD -s SHA256SUMS.sig < SHA256SUMS"

for stamp in "${STAMPS[@]}"; do
    printf '{"commit": "%s", "tag": "%s", "built_at": "%s"}\n' \
        "$COMMIT" "$TAG" "$BUILT_AT" > "$stamp"
done

pip wheel --no-deps --wheel-dir "$OUT" ./sdk/python
pip wheel --no-deps --wheel-dir "$OUT" ./cli
# The server (root package) wheel, for self-hosting without the container image.
pip wheel --no-deps --wheel-dir "$OUT" .
rm -f "${STAMPS[@]}"

# WHEELS holds the SDK and CLI wheels (installed by step 5); the server wheel is checksummed
# and signed with them but not installed there, since it pulls the full server dependency set.
WHEELS=()
SERVER_WHEELS=()
while IFS= read -r wheel; do
    case "$wheel" in
        sandfort-[0-9]*.whl) SERVER_WHEELS+=("$wheel") ;;
        *) WHEELS+=("$wheel") ;;
    esac
done < <(cd "$OUT" && ls -1 ./*.whl | sed 's|^\./||')
[ "${#WHEELS[@]}" -ge 2 ] || die "expected at least two wheels in $OUT"
[ "${#SERVER_WHEELS[@]}" -eq 1 ] || die "expected exactly one server wheel (sandfort-*.whl) in $OUT"
SERVER_WHEEL="${SERVER_WHEELS[0]}"

(
    cd "$OUT"
    shasum -a 256 "${WHEELS[@]}" "$SERVER_WHEEL" > SHA256SUMS
    {
        printf 'built from sandfort main %s (tag %s) on %s\n' "$COMMIT" "$TAG" "$BUILT_AT"
        printf 'server wheel: %s\n' "$SERVER_WHEEL"
        printf 'signing key fingerprint: %s\n' "$FINGERPRINT"
        printf 'verify with: %s\n' "$VERIFY_CMD"
        printf 'then: shasum -a 256 -c SHA256SUMS\n'
    } > RELEASE.txt
)

# 3) sign
rm -f "$OUT/SHA256SUMS.sig"
(cd "$OUT" && ssh-keygen -Y sign -f "$SANDFORT_RELEASE_KEY" -n "$NAMESPACE" SHA256SUMS)
[ -f "$OUT/SHA256SUMS.sig" ] || die "signing did not produce SHA256SUMS.sig"

# 4) verify the signature and the sums
(
    cd "$OUT"
    # The delivered copy, so the recipe in RELEASE.txt is what was just checked.
    ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
        -s SHA256SUMS.sig < SHA256SUMS
    shasum -a 256 -c SHA256SUMS
)

# 5) install into a throwaway venv and check the reported build
VENV_DIR="$(mktemp -d)"
python3 -m venv "$VENV_DIR"
WHEEL_PATHS=()
for wheel in "${WHEELS[@]}"; do WHEEL_PATHS+=("$OUT/$wheel"); done
"$VENV_DIR/bin/pip" install --quiet "${WHEEL_PATHS[@]}"
VERSION_OUT="$("$VENV_DIR/bin/sandfort" version)"
echo "$VERSION_OUT"
# The text line shows the first 12 characters of the commit.
case "$VERSION_OUT" in
    *"${COMMIT:0:12}"*) ;;
    *) die "'sandfort version' does not contain commit ${COMMIT:0:12}" ;;
esac

echo "release ok: $OUT"
