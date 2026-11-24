# Sandfort self-host install

This bundle installs Sandfort on your own Linux host for a stability soak. You need no
repository access. Everything you need is in this directory.

The bundle is signed. Verify it before you run anything from it (chapter 2).

The layout, relative to the bundle root:

```text
INSTALL.md                      this file
RELEASE.txt                     the commit, the server wheel and the signing key fingerprint
sandfort-<ver>-py3-none-any.whl server wheel (built into the image)
sandfort_sdk-<ver>-*.whl        Python SDK
sandfort_cli-<ver>-*.whl        CLI (the sandfort command)
SHA256SUMS, SHA256SUMS.sig      checksums and signature of the three wheels
BUNDLE-SHA256SUMS, .sig         checksums and signature of every file in the bundle
release-allowed-signers         the public signing key
deploy/host-setup.sh            egress rules for sandboxes (run as root, on every boot)
deploy/node-setup.sh            prepares Docker: overlay2, XFS quota, gVisor, optional Kata
deploy/seccomp.json             the seccomp profile for sandboxes
deploy/selfhost/Dockerfile      image from the server wheel
deploy/selfhost/compose.yml     API and Postgres 16
deploy/selfhost/sandfort.env.example  every setting, secrets empty
```

## 1. Host requirements

The soak is only comparable to the beta if your host matches it. Use this:

- Ubuntu 24.04, a dedicated host or VM. Sandboxes run on it. Do not share it with other work.
- Docker Engine (the packages from Docker's own apt repository) with the compose plugin.
  Docker runs with the overlay2 storage driver.
- `/var/lib/docker` on its own XFS filesystem mounted with `pquota`. Per-sandbox disk limits
  need it. The production profile refuses to start without it.
- gVisor `runsc` registered with Docker. `deploy/node-setup.sh` installs and registers it.
- Optional: Kata Containers for the `microvm` tier. It needs `/dev/kvm`. On a VM that means
  nested virtualization.
- Postgres 16. The compose file runs it for you.
- Packages: `jq`, `curl`, `bzip2`, `python3-venv`, `iptables`. For Kata also `xz-utils`.
- Outbound network for image pulls. Sandbox images come from Docker Hub by default.

Check the filesystem before you go on:

```bash
findmnt -no SOURCE,FSTYPE,OPTIONS /var/lib/docker
```

The type must be `xfs`. The options must contain `prjquota` (the kernel's name for `pquota`).
If the command prints a different type, or the options lack it, prepare a data disk first:

```bash
sudo systemctl stop docker
sudo mkfs.xfs /dev/<your-data-disk>
echo '/dev/<your-data-disk> /var/lib/docker xfs defaults,pquota 0 0' | sudo tee -a /etc/fstab
sudo mount /var/lib/docker
```

Back up anything already in `/var/lib/docker` before you mount over it. Then check again.
After Docker starts, this must print `overlay2`:

```bash
docker info --format '{{.Driver}}'
```

## 2. Verify the bundle

Unpack the tarball, then check the signature and the checksums from the bundle root:

```bash
tar -xzf sandfort-selfhost-<tag>.tar.gz
cd sandfort-selfhost-<tag>
ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
    -n sandfort-release -s BUNDLE-SHA256SUMS.sig < BUNDLE-SHA256SUMS
sha256sum -c BUNDLE-SHA256SUMS
```

The first command must print `Good "sandfort-release" signature`. The second must print `OK`
for every file. If either fails, stop and tell us. Do not run anything from the bundle.

The public key travels inside the bundle, so it proves nothing by itself. Compare the
fingerprint with the one we gave you over another channel:

```bash
awk '!/^#/ && NF {print $2, $3}' release-allowed-signers > /tmp/signer.pub
ssh-keygen -lf /tmp/signer.pub
```

It must equal the line `signing key fingerprint` in `RELEASE.txt`, and the value we sent
you separately. The wheels have their own signature too. This one is optional:

```bash
ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
    -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS
```

## 3. Prepare the node

Look first. This changes nothing:

```bash
bash deploy/node-setup.sh --check
```

Then prepare the node. Read the dry run, then run it. Docker may restart:

```bash
sudo bash deploy/node-setup.sh --dry-run
sudo bash deploy/node-setup.sh --default-runtime-runsc --live-restore --with-slice
```

For the `microvm` tier add `--with-kata` and set `KATA_SHA256` to the sha256 of the Kata
tarball, taken from a source you trust:

```bash
sudo KATA_SHA256=<sha256> bash deploy/node-setup.sh --with-kata --default-runtime-runsc
```

Run the check again. It must report the XFS quota, `overlay2` and the `runsc` runtime.

Now install the egress rules. They block sandbox traffic to cloud metadata and private
ranges. Run them now and again on every boot. A small systemd unit ordered after
`docker.service` does that:

```bash
sudo sh deploy/host-setup.sh
```

In the production profile the server tests these rules at start. It refuses to start if a
sandbox can reach a blocked address.

## 4. Configure and start

Work in `deploy/selfhost`:

```bash
cd deploy/selfhost
cp sandfort.env.example sandfort.env
chmod 600 sandfort.env
```

Edit `sandfort.env`. Fill these three secrets. Keep them. Changing the pepper later
invalidates every API key:

```bash
openssl rand -hex 32                          # SANDFORT_API_KEY_PEPPER
openssl rand -hex 32                          # SANDFORT_AUDIT_CHAIN_KEY
openssl rand -base64 32 | tr '+/' '-_'        # SANDFORT_WEBHOOK_SECRET_KEY (a Fernet key)
```

Set the host capacity to your own figures. Leave headroom for the OS and Docker. If you added
Kata, switch the isolation line to `gvisor=runsc,microvm=kata`.

Create `.env` for compose with the database password and the Docker socket group id:

```bash
printf 'POSTGRES_PASSWORD=%s\nDOCKER_GID=%s\n' \
    "$(openssl rand -hex 24)" "$(stat -c %g /var/run/docker.sock)" > .env
chmod 600 .env
```

The socket group is root-equivalent on this host. Put no human account in it that may not be
root here.

Build and start. The build installs the verified server wheel from the bundle root:

```bash
docker compose up -d --build
docker compose logs -f api
```

The `api` container applies the database migrations when it starts. Watch for `database
upgraded to head`, then for the server start. In prod the start gate reports every problem
at once. If it refuses, read the `error:` lines, fix the host or the settings and run
`docker compose up -d` again. To see the same findings without a start attempt:

```bash
docker compose run --rm --no-deps api python -m sandfort.admin_cli doctor
```

The API listens on `127.0.0.1:8000` only. Put a TLS reverse proxy in front if anyone else
must reach it.

## 5. Migrate and bootstrap

The container already migrated. Running it again is safe and shows the state:

```bash
docker compose exec api python -m sandfort.admin_cli migrate
```

Create the first organization and its key. The plaintext key starts with `sf_`. It is
printed once and cannot be recovered:

```bash
docker compose exec api python -m sandfort.admin_cli bootstrap \
    --org-name "Your Company" --org-slug yourco
```

Store the key now. If you lose it, `create-key --org-slug yourco` issues a new one.

## 6. Install the CLI and run the smoke test

Install the SDK and the CLI from the verified wheels, in a virtual environment on any
machine that can reach the API:

```bash
cd ../..
python3 -m venv .venv
.venv/bin/pip install ./sandfort_sdk-*.whl ./sandfort_cli-*.whl
export PATH="$PWD/.venv/bin:$PATH"
export SANDFORT_BASE_URL=http://127.0.0.1:8000
printf 'API key: '; read -rs SANDFORT_API_KEY; echo; export SANDFORT_API_KEY
```

Check the server, then run a first sandbox:

```bash
curl -fsS http://127.0.0.1:8000/readyz
curl -fsS http://127.0.0.1:8000/v1/status
sandfort sandbox create hello --wait
sandfort exec hello python3 -c "print(21 * 2)"
sandfort sandbox rm hello
```

`/v1/status` must show `"status": "ok"` and the `build_sha` of this release. The exec must
print `42`. The first create pulls the image, so it is slower than later ones.
Also try each isolation tier you enabled:

```bash
sandfort sandbox create tier-gvisor --isolation gvisor --wait
sandfort sandbox rm tier-gvisor
```

`/metrics` is open unless `SANDFORT_METRICS_TOKEN` is set (optional bearer token, at least 32
characters). Do not publish that port either way.

## 7. Upgrade and rollback

Each release is a new bundle. Verify it (chapter 2) in a new directory. Then:

1. Write a notice if others use the instance, and wait two minutes.
2. Back up the database. Keep the dump until the upgrade is verified:

   ```bash
   docker compose exec -T postgres pg_dump -U sandfort -Fc sandfort > pre-upgrade.dump
   ```

3. Keep the running image as the rollback target:

   ```bash
   docker tag sandfort-api sandfort-api:previous
   ```

4. Copy `sandfort.env` and `.env` into the new bundle's `deploy/selfhost`. Build and start:

   ```bash
   docker compose up -d --build
   docker compose logs api
   ```

   The container migrates on start. Read the log for `alembic` errors before you trust it.
5. Check `/readyz`, `/v1/status` and one sandbox create.

Migrations only go forward. The supported rollback is a restore:

1. `docker compose stop api`
2. Restore the pre-upgrade dump into an empty database.
3. Start the old image: tag `sandfort-api:previous` back to `sandfort-api`, then
   `docker compose up -d --no-build`.

Sandboxes created after the dump are removed from the node after a grace period. Never roll
back by only starting the old image against a migrated database. Its behavior is undefined.

## 8. Snapshot recovery through a registry

A snapshot lives as an image on the node. To move one to another host, or to rebuild a node,
go through a registry. Registering a snapshot always pulls from a registry. The target server
needs pull access, and the reserved repository `sandfort-snapshot` is refused. Use any
registry both sides can reach.

First make a snapshot and note a hash you can compare later:

```bash
sandfort sandbox create src --wait
sandfort exec src sh -c 'head -c 1048576 /dev/urandom > /root/data.bin'
sandfort exec src sha256sum /root/data.bin
sandfort snapshot create src after-setup --wait
```

Then follow the path:

1. Export the snapshot to a tar file:

   ```bash
   sandfort snapshot export after-setup -o after-setup.tar
   ```

2. Load it on a Docker host. The tar names no repository, so Docker prints
   `Loaded image ID: sha256:...` and creates no tag:

   ```bash
   docker load -i after-setup.tar
   ```

3. Tag the image ID from that line and push it to a registry the server can pull from:

   ```bash
   docker tag <image id> registry.example.org/team/after-setup:v1
   docker push registry.example.org/team/after-setup:v1
   ```

   The push prints a line `v1: digest: sha256:<digest> size: ...`. Keep the digest.
4. Register the image by digest. A digest pins the exact content. Docker on the API host
   must be able to pull it (run `docker login` there if the registry needs it):

   ```bash
   sandfort snapshot register \
       registry.example.org/team/after-setup@sha256:<digest> --name after-setup-restored
   ```

   If you set `SANDFORT_ALLOWED_REGISTRIES`, the registry must be on that list.
5. Create a new sandbox from it and compare the hash with the one you noted:

   ```bash
   sandfort sandbox create restored --snapshot after-setup-restored --wait
   sandfort exec restored sha256sum /root/data.bin
   ```

The two `sha256sum` lines must match. If they do, the snapshot survived the trip. A sandbox
created from a registered snapshot gets the default resources unless you pass them.

The export holds the filesystem and a safe image config only. It has no sandbox environment
variables, no secrets and no labels.

## 9. Webhook endpoints that got disabled

An endpoint is disabled after 50 consecutive failed deliveries. The audit log gets a
`webhook.endpoint_disabled` event. Recover in this order:

1. Fix the receiver so it answers 2xx within 10 seconds.
2. Enable the endpoint. This also resets the failure counter:

   ```bash
   sandfort webhook update <endpoint-id> --enable
   ```

   In the REST API that is `PATCH /v1/webhooks/<endpoint-id>` with `{"enabled": true}`.
3. Only then redeliver the failed deliveries:

   ```bash
   sandfort webhook deliveries <endpoint-id> --state failed
   sandfort webhook redeliver <endpoint-id> <delivery-id>
   ```

Redeliver on an endpoint that is still disabled answers 409 `INVALID_STATE`. So does redeliver
of a delivery that already succeeded. Enable first, then redeliver. A redelivery repeats the
event, so deduplicate on the `webhook-id` header.

## 10. Reporting problems

Send us the output of these. They contain no secrets:

```bash
cat RELEASE.txt
docker compose logs --since 24h api > api.log
docker compose run --rm --no-deps api python -m sandfort.admin_cli doctor --json
```

Report suspected security issues privately, through the channel you were given. Sandfort
does not report usage to us. Traffic leaves your network only where you configure it.
