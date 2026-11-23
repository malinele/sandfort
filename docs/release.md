# Releases

## What a release is

A release is a git tag `v0.1.0-beta.N` on `main`, created after the gate passes. The tag fixes
the commit. The artifacts are the Python SDK wheel, the CLI wheel and the server wheel (the
`sandfort` package, for self-hosting without the container image) built from that commit, plus
a signed checksum file. Nothing is built from a dirty tree or from a commit that is not
the tag.

During the beta the code is delivered as these signed wheels and the repository is private.
The license is source-available (FSL-1.1-Apache-2.0); see `LICENSE.md`.

## How artifacts are built and signed

`deploy/release-wheels.sh <tag> [out-dir]` does the whole job. The output directory defaults to
`dist/<tag>`. The maintainer runs it with the signing key in the environment:

```bash
SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release deploy/release-wheels.sh v0.1.0-beta.N
```

The script:

1. Refuses to run unless the working tree is clean and `HEAD` equals the tag's commit.
2. Writes a build-info stamp into the server, SDK and CLI package directories, builds the three
   wheels with `pip wheel --no-deps`, and removes the stamps again (also on failure). It stops
   unless the output directory holds exactly one server wheel (`sandfort-<version>-*.whl`).
3. Copies `deploy/release-allowed-signers` into the output directory, and writes `SHA256SUMS`
   (`shasum -a 256` over all three wheels, so the signature covers the server wheel too) and
   `RELEASE.txt`.
4. Signs `SHA256SUMS` with `ssh-keygen -Y sign -n sandfort-release`, which produces
   `SHA256SUMS.sig`. The key path comes from `SANDFORT_RELEASE_KEY`; the script stops with a
   message when it is unset.
5. Verifies the signature against the copied `release-allowed-signers` and the sums with
   `shasum -a 256 -c`.
6. Installs the SDK and CLI wheels into a throwaway venv and runs `sandfort version`, failing
   unless the output contains the commit. The server wheel is not installed in this step; the
   sums in step 5 cover it.

## Verify a download

The directory that holds the wheels also holds `release-allowed-signers`, so nothing else has to
be fetched. Check the signature and the sums in that directory:

```bash
ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
    -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

The first command must print `Good "sandfort-release" signature`; the second must report `OK`
for every wheel. Install the wheels only after both pass.

The signers file that came with the wheels is only as trustworthy as the channel that delivered
it. Compare the key in it with the signing key fingerprint printed in `RELEASE.txt` and with the
file `deploy/release-allowed-signers` in the repository at the release tag. To print the
fingerprint of the key in the delivered file yourself, copy its key type and key (the second
and third fields of the line) into a file and run `ssh-keygen -lf` on that file.

## Release note file and build-info stamp

`RELEASE.txt` holds the build line, the file name of the server wheel, the fingerprint of the
signing key (`ssh-keygen -lf` of the public key in `release-allowed-signers`) and the verify
command:

```text
built from sandfort main <commit> (tag <tag>) on <utc time>
server wheel: sandfort-<version>-py3-none-any.whl
signing key fingerprint: <bits> SHA256:<hash> no comment (<type>)
verify with: ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev ...
then: shasum -a 256 -c SHA256SUMS
```

**Current signing key fingerprint.** The wheels release note of {{CURRENT_RELEASE}} holds this
line, as `deploy/release-wheels.sh` writes it. The key is unchanged since `v0.1.0-beta.64`:

```text
signing key fingerprint: 256 SHA256:UWtIFenxp6dnXQyEpqi644mbBZlV5BLPrq9e/MctZfg no comment (ED25519)
```

The `SHA256:` value is the fingerprint to compare. It must be identical in `RELEASE.txt`, on
this page and in the fingerprint you compute from the delivered signers file (see "Verify a
download"). If one of the three differs, do not install the wheels.

The verify command is the one `RELEASE.txt` carries on its `verify with:` line, followed by the
`then:` line (the same two commands as under "Verify a download"):

```bash
ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
    -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

The stamp is `_build_info.json` with the keys `commit`, `tag` and `built_at`. It sits inside
the `sandfort`, `sandfort_sdk` and `sandfort_cli` packages of the built wheels only; a source
checkout has none. `sandfort version` shows the first 12 characters of the commit and the tag
for the CLI and the SDK, and `sandfort_sdk.build_info()` returns the same fields. Both report
`unknown` when no stamp is present. The server does not read its stamp; `GET /v1/status`
reports `build_sha` from `SANDFORT_BUILD_SHA` (see "Server build").

## Self-host from the server wheel

The server ships as a container image (see "Image provenance") and, from the same release, as
the wheel `sandfort-<version>-py3-none-any.whl`. Use the wheel when the image is not available
to you, for example while the image registry is unreachable. Its version is the tag version
(`0.1.0bN` for `v0.1.0-beta.N`, see "Version numbers").

1. Verify the download first (see "Verify a download"). `SHA256SUMS` lists the server wheel,
   so `shasum -a 256 -c SHA256SUMS` must report `OK` for it.
2. Install it with Python 3.12 into a fresh virtual environment. The wheel was built with
   `--no-deps`, so `pip` fetches the server dependencies from the package index:

   ```bash
   python3.12 -m venv .venv
   .venv/bin/pip install sandfort-<version>-py3-none-any.whl
   ```

   For Postgres, install the extra: `.venv/bin/pip install
   "sandfort-<version>-py3-none-any.whl[postgres]"`.
3. Set the `SANDFORT_` environment (database URL, environment, role; see
   `docs/operations.md`), apply the migrations and start the server:

   ```bash
   .venv/bin/python -m sandfort.admin_cli migrate
   .venv/bin/python -m sandfort.main --host 0.0.0.0 --port 8000
   ```

   `python -m sandfort.main` is the same entry point as the `sandfort-server` console script
   (`--role`, `--host` and `--port` override `SANDFORT_ROLE`, `SANDFORT_HOST` and
   `SANDFORT_PORT`). It does not migrate on start, unlike the image's default command.

The wheel carries the server only. The host still needs a Docker daemon and the host steps
from `docs/operations.md` ("Node preparation" and `deploy/host-setup.sh`); the `prod`
environment refuses to start on a weakly isolated host.

## Version numbers

The version comes from git, not from a file: the server, SDK and CLI `pyproject.toml` files use
`hatch-vcs` (`version_scheme = "guess-next-dev"`, `local_scheme = "no-local-version"`). A tag
`v0.1.0-beta.N` gives the version `0.1.0bN`. A commit after a tag gives a dev version for the
next beta, for example `0.1.0b60.devN` when the last tag is `v0.1.0-beta.59` and `N` is the
number of commits since that tag. Without git metadata the fallback is `0.1.0.dev0`. A wheel
built by `deploy/release-wheels.sh` sits on a tagged commit, so its version has no `.dev` part.

The API image is built from a checkout copy without git metadata, so the fallback would apply.
`deploy/Dockerfile` therefore has the build argument `SANDFORT_VERSION` (empty by default). When
it is set, the build exports `SETUPTOOLS_SCM_PRETEND_VERSION` with that value and the installed
server package carries it, so `GET /v1/status` reports it. `deploy/redeploy-beta.sh api` computes
the value from `git describe`: `0.1.0b61` when `HEAD` is the tag `v0.1.0-beta.61`, otherwise the
dev version for the next beta, for example `0.1.0b62.dev41` for 41 commits after that tag. It
passes it with `--build-arg SANDFORT_VERSION=...` next to the build commit. The CI image workflow
has to pass the same argument.

## Image provenance

The `Release image` workflow (`.github/workflows/release.yml`) runs on every pushed tag `v*`. It
builds `deploy/Dockerfile` and publishes the API image to the GitHub container registry as
`ghcr.io/malinele/sandfort:<tag>` and `ghcr.io/malinele/sandfort:sha-<commit>`. The commit is
baked into the image in two places:

- the file `/app/BUILD_SHA`, written from the build argument `SANDFORT_BUILD_SHA`;
- the OCI label `org.opencontainers.image.revision`. The image also carries the labels
  `org.opencontainers.image.source` and `org.opencontainers.image.version` (the tag).

The unauthenticated `GET /v1/status` route reports `image_sha` (the content of `/app/BUILD_SHA`,
or `null` when the file is absent or empty) next to `build_sha` (from `SANDFORT_BUILD_SHA`).
`build_matches_image` is `true` when both are set and equal, `false` when they differ, and `null`
when either is missing. A `false` value means the container runs an image that was not built from
the commit it claims.

`deploy/redeploy-beta.sh api --image <ref>` deploys a CI-built image instead of building on the
VM. The script:

1. Pulls the image on the VM and refuses it unless its `org.opencontainers.image.revision` label
   equals the commit being deployed.
2. Tags the running image as `sandfort-api:previous` before every recreate, then recreates the
   API with `--no-build`.
3. Downloads the live OpenAPI document and compares its paths with `openapi/sandfort.v1.json`.

`deploy/redeploy-beta.sh rollback` is the rollback target: it retags `sandfort-api:previous` as
the compose image name and recreates the API. The image that was running becomes the new
`sandfort-api:previous`, so a second rollback swaps back. Add `--dry-run` to print the steps.

## Docs site specification copy

The docs site serves `openapi.json`, a compact re-serialisation of `openapi/sandfort.v1.json`
(no indentation, same key order, so it fits the ConfigMap budget). It is semantically equal to
the repository file, not byte-identical, so a hash of the copy will not match the repository
file. The byte-exact specification is `openapi/sandfort.v1.json` in the repository and the API's
own specification route.

The docs site build writes `openapi.json.sha256` next to the copy: the SHA-256 of the repository
file, in `sha256sum` format. The sidecar is informational and is not published to the docs site.
To compare, from the repository root:

1. `sha256sum -c site/docs/openapi.json.sha256` checks that the repository file is the one the
   copy was built from (use `shasum -a 256 -c` on macOS).
2. To compare content, load both files as JSON and check that the parsed values are equal.

## Server build

The server reports its own build on the unauthenticated `GET /v1/status` route: `build_sha`
(from `SANDFORT_BUILD_SHA`), `image_sha` (the commit baked into the image) and
`build_matches_image`, which compares the two (see "Image provenance"). Compare `build_sha` with
the commit in `RELEASE.txt` to confirm that a server and a wheel come from the same release.

## Self-host install bundle

For a design partner who has no repository access, `deploy/release-bundle.sh` packs one signed
tarball from the output of `deploy/release-wheels.sh`:

```bash
SANDFORT_RELEASE_KEY=~/.ssh/sandfort-release \
    deploy/release-bundle.sh v0.1.0-beta.N dist/v0.1.0-beta.N dist/v0.1.0-beta.N-bundle
```

The arguments are the tag, the wheels directory and an optional output directory (default
`dist/<tag>-bundle`). The output is `sandfort-selfhost-<tag>.tar.gz`, plus copies of
`BUNDLE-SHA256SUMS` and `BUNDLE-SHA256SUMS.sig` beside it. The tarball has one top directory of
the same name. It holds the three wheels, `SHA256SUMS`, `SHA256SUMS.sig`,
`release-allowed-signers`, `RELEASE.txt`, `deploy/host-setup.sh`, `deploy/node-setup.sh`,
`deploy/seccomp.json`, `deploy/selfhost/{Dockerfile,compose.yml,sandfort.env.example}` and
`INSTALL.md` (from `deploy/selfhost/INSTALL.md`).

`BUNDLE-SHA256SUMS` lists every file except itself and its signature. It is signed with the same
key, principal (`release@sandfort.dev`) and namespace (`sandfort-release`) as the wheels, so the
partner checks one signature for the whole bundle (the wheels' own signature stays valid inside
it). The script refuses to run unless the wheels still match their signature, `HEAD` is the
commit named in `RELEASE.txt` and `deploy/` is clean, and it unpacks and verifies the finished
tarball before it reports success.

Send the partner the tarball, and send the signing key fingerprint over a different channel: the
public key travels inside the bundle, so it proves nothing by itself.
