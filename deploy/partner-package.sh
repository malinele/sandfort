#!/usr/bin/env bash
# Assemble a partner delivery zip from a signed release directory.
#
#   SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release \
#       deploy/partner-package.sh <release-dir> <partner-tag> [extra-file...]
#
# release-dir is the output of deploy/release-ts-sdk.sh or deploy/release-wheels.sh: artifacts,
# SHA256SUMS, SHA256SUMS.sig, release-allowed-signers and a release note (RELEASE-TS.txt or
# RELEASE.txt). Each extra-file is copied in and added to SHA256SUMS, which is then re-signed
# with the same key, namespace and principal and self-verified. Output:
# <release-dir>/<dirname>-<partner-tag>.zip holding the artifacts, SHA256SUMS, SHA256SUMS.sig,
# release-allowed-signers and the release note; the zip's own SHA-256 is printed for the
# delivery message. This replaces the manual copy/re-sign/zip steps done per delivery.
set -euo pipefail

NAMESPACE="sandfort-release"
PRINCIPAL="release@sandfort.dev"

die() {
    echo "partner-package: $*" >&2
    exit 1
}

[ "$#" -ge 2 ] || die "usage: partner-package.sh <release-dir> <partner-tag> [extra-file...]"
DIR="$1"
TAG="$2"
shift 2
case "$TAG" in
    "" | *[!A-Za-z0-9._-]* | -* ) die "partner tag may hold only letters, digits, dot, underscore, hyphen" ;;
esac
[ -d "$DIR" ] || die "not a directory: $DIR"
[ -n "${SANDFORT_RELEASE_KEY:-}" ] || die "SANDFORT_RELEASE_KEY is not set (SSH signing key path)"
[ -f "$SANDFORT_RELEASE_KEY" ] || die "SANDFORT_RELEASE_KEY does not point to a file"
for tool in shasum ssh-keygen zip; do
    command -v "$tool" >/dev/null || die "required tool not found: $tool"
done

EXTRAS=()
for extra in "$@"; do
    [ -f "$extra" ] || die "extra file not found: $extra"
    EXTRAS+=("$extra")
done

cd "$DIR"
[ -f SHA256SUMS ] || die "missing SHA256SUMS in $DIR"
[ -f SHA256SUMS.sig ] || die "missing SHA256SUMS.sig in $DIR"
[ -f release-allowed-signers ] || die "missing release-allowed-signers in $DIR"
NOTE=""
for candidate in RELEASE-TS.txt RELEASE.txt; do
    [ -f "$candidate" ] && NOTE="$candidate" && break
done
[ -n "$NOTE" ] || die "missing RELEASE-TS.txt or RELEASE.txt in $DIR"

# The incoming manifest must verify before anything is added to it.
ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
    -s SHA256SUMS.sig < SHA256SUMS >/dev/null || die "existing signature does not verify"
shasum -a 256 -c SHA256SUMS >/dev/null || die "existing checksums do not verify"

# Artifact list: every file the manifest names, plus the extras (copied in by base name).
ARTIFACTS=()
while read -r _hash name; do
    [ -n "$name" ] && ARTIFACTS+=("$name")
done < SHA256SUMS
for extra in ${EXTRAS[@]+"${EXTRAS[@]}"}; do
    base="$(basename "$extra")"
    if [ ! "$extra" -ef "./$base" ]; then
        cp "$extra" "./$base"
    fi
    ARTIFACTS+=("$base")
done

shasum -a 256 "${ARTIFACTS[@]}" > SHA256SUMS
rm -f SHA256SUMS.sig
ssh-keygen -Y sign -f "$SANDFORT_RELEASE_KEY" -n "$NAMESPACE" SHA256SUMS >/dev/null 2>&1 \
    || die "signing failed"
ssh-keygen -Y verify -f release-allowed-signers -I "$PRINCIPAL" -n "$NAMESPACE" \
    -s SHA256SUMS.sig < SHA256SUMS >/dev/null || die "self-verification failed"
shasum -a 256 -c SHA256SUMS >/dev/null || die "checksum self-check failed"

ZIP="$(basename "$PWD")-$TAG.zip"
rm -f "$ZIP"
zip -q -X "$ZIP" "${ARTIFACTS[@]}" SHA256SUMS SHA256SUMS.sig release-allowed-signers "$NOTE"
echo "partner-package: $DIR/$ZIP"
shasum -a 256 "$ZIP"
