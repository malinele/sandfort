#!/usr/bin/env bash
# Build, test, sign and verify the TypeScript SDK tarball (@sandfort/sdk).
#
#   SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release deploy/release-ts-sdk.sh [out-dir]
#
# out-dir defaults to dist/ts-sdk-<version>. Output: sandfort-sdk-<version>.tgz (npm pack of
# sdk/typescript), SHA256SUMS, SHA256SUMS.sig, release-allowed-signers and RELEASE-TS.txt
# (commit, version, test counts, signing key fingerprint, verify command). The signature uses
# the same key, namespace and principal as the wheel releases, so a partner verifies every
# Sandfort artifact with one recipe:
#
#   ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
#       -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS
#
# Safety checks: the sdk/typescript subtree must be clean (the tarball must equal the recorded
# commit), and tsc --noEmit plus the vitest suite must pass before anything is signed.
# SANDFORT_TS_SKIP_CI=1 reuses the existing node_modules instead of running npm ci.
set -euo pipefail

NAMESPACE="sandfort-release"
PRINCIPAL="release@sandfort.dev"

die() {
    echo "release-ts-sdk: $*" >&2
    exit 1
}

[ "$#" -le 1 ] || die "usage: release-ts-sdk.sh [out-dir]"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SDK_DIR="$ROOT/sdk/typescript"
SIGNERS="$ROOT/deploy/release-allowed-signers"

[ -n "${SANDFORT_RELEASE_KEY:-}" ] || die "SANDFORT_RELEASE_KEY is not set (SSH signing key path)"
[ -f "$SANDFORT_RELEASE_KEY" ] || die "SANDFORT_RELEASE_KEY does not point to a file"
[ -f "$SIGNERS" ] || die "missing $SIGNERS"
[ -d "$SDK_DIR" ] || die "missing $SDK_DIR"
for tool in git npm node shasum ssh-keygen; do
    command -v "$tool" >/dev/null || die "required tool not found: $tool"
done

# 1) clean subtree: the tarball must match the recorded commit
[ -z "$(git status --porcelain -- sdk/typescript)" ] || die "sdk/typescript is not clean"
COMMIT="$(git rev-parse HEAD)"
VERSION="$(node -p "require('$SDK_DIR/package.json').version")"
[ -n "$VERSION" ] || die "cannot read the version from package.json"

OUT="${1:-dist/ts-sdk-$VERSION}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cp "$SIGNERS" "$OUT/release-allowed-signers"

# Fingerprint of the first public key in the allowed-signers file (same extraction as
# release-wheels.sh: the key type is the first field that looks like one).
KEY_AWK='!/^#/ && NF { for (i = 2; i < NF; i++)
    if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $i, $(i + 1); exit } }'
KEY_FILE="$(mktemp "${TMPDIR:-/tmp}/sandfort-release-key.XXXXXX")"
cleanup() { rm -f "$KEY_FILE"; }
trap cleanup EXIT
awk "$KEY_AWK" "$SIGNERS" > "$KEY_FILE"
FINGERPRINT="$(ssh-keygen -lf "$KEY_FILE")" || die "cannot read a public key from $SIGNERS"
VERIFY_CMD="ssh-keygen -Y verify -f release-allowed-signers -I $PRINCIPAL -n $NAMESPACE"
VERIFY_CMD="$VERIFY_CMD -s SHA256SUMS.sig < SHA256SUMS"

# 2) install, typecheck, test, pack
cd "$SDK_DIR"
if [ -z "${SANDFORT_TS_SKIP_CI:-}" ]; then
    npm ci --no-audit --no-fund >/dev/null
fi
npx tsc --noEmit || die "tsc --noEmit failed"
TEST_TAIL="$(npx vitest run 2>&1 | tail -4)" || die "vitest suite failed"
TEST_LINE="$(printf '%s\n' "$TEST_TAIL" | grep -E '^\s*Tests' | tr -s ' ' | sed 's/^ //')"
[ -n "$TEST_LINE" ] || die "cannot read the vitest summary"
printf '%s\n' "$TEST_LINE" | grep -q "failed" && die "vitest reports failures: $TEST_LINE"

TARBALL="sandfort-sdk-$VERSION.tgz"
npm pack --pack-destination "$OUT" >/dev/null
[ -f "$OUT/$TARBALL" ] || die "npm pack did not produce $TARBALL"

# 3) release note, checksums, signature, self-verify
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NODE_V="$(node --version)"
{
    printf 'commit: %s\n' "$COMMIT"
    printf 'source: sdk/typescript @ %s\n' "$COMMIT"
    printf 'version: %s\n' "$VERSION"
    printf 'built_at: %s\n' "$BUILT_AT"
    printf 'node: %s\n' "$NODE_V"
    printf 'tests: %s; tsc --noEmit clean\n' "$TEST_LINE"
    printf 'signing key: %s\n' "$FINGERPRINT"
    printf 'verify: %s\n' "$VERIFY_CMD"
} > "$OUT/RELEASE-TS.txt"

cd "$OUT"
shasum -a 256 "$TARBALL" > SHA256SUMS
ssh-keygen -Y sign -f "$SANDFORT_RELEASE_KEY" -n "$NAMESPACE" SHA256SUMS >/dev/null 2>&1 \
    || die "signing failed"
ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
    -s SHA256SUMS.sig < SHA256SUMS >/dev/null || die "self-verification failed"
shasum -a 256 -c SHA256SUMS >/dev/null || die "checksum self-check failed"

echo "release-ts-sdk: $OUT"
echo "  $TARBALL ($(wc -c < "$TARBALL" | tr -d ' ') bytes)"
echo "  $TEST_LINE"
echo "  verify: $VERIFY_CMD"
