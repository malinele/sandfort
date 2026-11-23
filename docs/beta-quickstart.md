# Sandfort hosted beta: quickstart

One page from delivery package to a working sandbox. Every step here is a condensed copy of the
[connect guide](https://docs.sandfort.dev/guide.html); when anything is unclear or fails, the
guide section named in each step is the authority. The beta is an invite-only evaluation
instance: shared, no SLA, not for production secrets (guide §5).

## 1. Verify the delivery (1 minute)

You received a package with the SDK files, `SHA256SUMS`, `SHA256SUMS.sig`,
`release-allowed-signers` and `RELEASE.txt`. In the directory that holds them:

```bash
ssh-keygen -Y verify -f release-allowed-signers -I release@sandfort.dev \
  -n sandfort-release -s SHA256SUMS.sig < SHA256SUMS   # prints "Good ..." and exits 0
shasum -a 256 -c SHA256SUMS                            # every file: OK
```

Install nothing that fails either check. Details: guide §1, "What you receive from the maintainer".

## 2. Save the key, install the SDK (2 minutes)

Open the one-time secret link, save the `sf_` key in your secret manager (it is shown exactly
once), and export it:

```bash
export SANDFORT_API_KEY=sf_...                 # from the secret link
pip install ./sandfort_sdk-*.whl               # Python SDK (always included)
# npm install ./sandfort-sdk-*.tgz             # TypeScript SDK, if your package includes it
```

Install details per stack (CLI, MCP server, TypeScript): guide §2.

## 3. First sandbox (2 minutes)

```python
import os
from sandfort_sdk import Client

client = Client(base_url="https://api.sandfort.dev", api_key=os.environ["SANDFORT_API_KEY"])
sbx = client.create_sandbox(
    name="first",
    snapshot="python:3.12-slim",
    labels={"purpose": "quickstart"},
    auto_delete_minutes=60,
    wait=True,
)
try:
    print(sbx.code_run("python", "print(21 * 2)").stdout.strip())   # 42
    sbx.fs.upload_file("/tmp/hello.txt", b"hello\n")
    print(sbx.fs.read_bytes("/tmp/hello.txt"))                      # b'hello\n'
finally:
    sbx.delete()
```

`labels=` makes the sandbox findable later; `auto_delete_minutes=` removes one you forgot.
The default image (`python:3.12-slim` without `snapshot=`) has Python and pip but no git, curl or
build tools; pick another image when you need them. Full walkthrough and the CLI alternative:
guide §3.

## 4. Where to go next

| You want | Guide section |
|---|---|
| Exec, sessions, PTY, code contexts (state between runs) | §3 and "Code contexts" |
| Files, git, snapshots, volumes | the matching toolbox sections |
| Narrow keys for CI, label-scoped keys | §1 "Scopes" and "Keys limited to labelled sandboxes" |
| Isolation tiers (`container`, `gvisor`, `microvm`) and their limits | "Isolation tiers" |
| What the beta does and does not guarantee | §5 and the [beta terms](https://docs.sandfort.dev/beta-terms.html) |

Support: `office@sandfort.dev`, response target next business day (Monday–Friday, CET), best
effort ([beta terms](https://docs.sandfort.dev/beta-terms.html)).
