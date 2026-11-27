# Isolation tiers

Sandfort runs untrusted, often AI-generated code. Plain containers share the host kernel, so
a kernel exploit inside one sandbox reaches the host. To let you pick a boundary per workload,
Sandfort offers three tiers, chosen per sandbox, behind the same API.

| Tier | Runtime | Boundary | Trade-off |
|---|---|---|---|
| container | runc | Linux namespaces, cgroups, seccomp, a reduced capability set (below) | Fastest, especially for spawn-heavy and small-file-heavy work; shares the host kernel |
| gvisor | runsc (gVisor) | A user-space kernel handles the sandbox's system calls; the host kernel sees a small, filtered surface (a bug in gVisor itself can still expose it) | About the same for create, exec, CPU-bound work and file transfer; several times slower (about 3x to about 9x measured, more for fork-heavy shell loops) for spawn-heavy and small-file-heavy work (see Overhead); limits behave differently |
| microvm | kata (Kata Containers 4.3.1, Rust runtime, QEMU, on KVM) | Hardware virtualization: each sandbox has its own guest kernel (on the beta: Kata on nested KVM) in a lightweight VM | Create to started about 4 s (about 8-9 s with `block_network=True`), start about 3.7 s (measured on the beta); more memory per sandbox; needs KVM |

Capabilities (the same set on all three tiers, because the driver applies one `cap_drop` and
`cap_add` to every container): all capabilities are dropped except `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `KILL`, `SETGID`, `SETUID` and `NET_BIND_SERVICE`.

Boundary: gVisor is a user-space kernel, not a hardware boundary. A bug in gVisor itself could
still expose the host kernel. That is why the `microvm` tier (hardware virtualization) exists
for code that `container` or `gvisor` isolation does not suit; on the beta it is nested KVM and
the beta is still not the place for your highest-risk code.

## API and configuration

- Create takes an optional `isolation` (`container`, `gvisor`, `microvm`); omitted means the
  deployment default; an unavailable tier is a 422 that lists the available tiers.
- Every sandbox response carries `isolation`; `GET /v1/isolation` returns
  `{"default": ..., "available": [...]}`.
- A deployment maps tiers to Docker runtimes with
  `SANDFORT_ISOLATION_RUNTIMES=container=,gvisor=runsc,microvm=kata` (an empty runtime is the
  daemon default) and picks the default with `SANDFORT_DEFAULT_ISOLATION`. With no map, the
  only tier is the default tier on `SANDFORT_CONTAINER_RUNTIME`, as before.
- An empty runtime means whatever the daemon default is. If the daemon default runtime is
  gVisor (`default-runtime` set to `runsc`, which keeps image builds off plain runc), an
  empty `container=` would run the container tier on gVisor. Map the container tier
  explicitly to runc in that case: `container=runc,gvisor=runsc,microvm=kata`. In `prod`, a
  blank runtime in an explicit tier map refuses the start at preflight unless
  `SANDFORT_ALLOW_DEFAULT_RUNTIME_TIER=true` accepts the daemon default (since 2026-11-23).
- If the node enables user-namespace remapping (`userns-remap`, a daemon-wide setting), the
  `microvm` tier runs with the host user namespace, because Kata cannot run in a remapped
  one; the other tiers run remapped. The Docker driver sets that per-container opt-out
  (`userns_mode="host"`) for the tiers listed in `SANDFORT_USERNS_HOST_TIERS`, which
  defaults to `microvm`; a blank value removes the opt-out. With a single runtime and no tier
  map, a Kata runtime sits on the `container` tier, which is not in the default list: set
  `SANDFORT_USERNS_HOST_TIERS=container` there. `SANDFORT_REQUIRE_USERNS_REMAP` (default
  `false`) makes `prod` refuse to start without remapping; the default-runtime finding is
  advisory only ([operations], "Daemon settings beyond node-setup.sh").
- The tier is stored as a reserved internal label; sandboxes created before tiers existed
  report the deployment default.

## gVisor: verified behavior

Verified on a Docker daemon with the same gVisor build (release-20261102.0) and runtime
arguments (`--overlay2=none --file-access=shared`) as the beta node: the sandbox sees kernel
`4.19.0-gvisor`; exec, timeouts and the process-tree kill work; file copy in and out and
snapshots work; `--network none` blocks all traffic; the docker test suite passes. The
gVisor-specific differences, each handled or documented:

1. If `/tmp` is empty when a gVisor sandbox starts, gVisor mounts a private in-memory tmpfs
   there that Docker's archive API cannot see, so file transfer under `/tmp` would not work.
   Sandfort therefore puts an empty marker file, `/tmp/.sandfort-keep`, before every gVisor
   start; gVisor then keeps `/tmp` in the root filesystem. `/tmp` is covered by the disk quota
   (where it is enforced, see Disk size below) and included in snapshots on every tier, and file
   upload and download under `/tmp` work. Do not delete `/tmp/.sandfort-keep`: if `/tmp` is empty
   at the next start, the private in-memory `/tmp` comes back. gVisor sandboxes created before
   2026-11-04 keep their old separate `/tmp` volume until they are deleted.
2. The Docker seccomp profile is not applied to the sandboxed processes' system calls the way
   `runc` applies it (gVisor's documentation). gVisor's Sentry filters those calls itself, and the
   host-side `runsc` processes run under gVisor's own seccomp filters. gVisor is the system-call
   boundary.
3. Exceeding the memory or process limit usually stops the whole sandbox (the limits count
   gVisor's own host processes). After such an unexpected stop the command reports "the sandbox
   stopped while running this command: it exceeded its memory or process limit; start it again"
   with exit code 137, the sandbox moves to state `stopped` with an `error_reason` that explains
   it, its files are kept, and starting it again works. Sometimes only the offending process is
   killed (exit code 137 with empty stderr, sandbox still `started`), and hitting the process
   limit can also just make new process creation fail (fork errors such as ENOMEM) without
   stopping anything. Advice: after any exit code 137, check `sandbox_stopped` in the exec
   result before continuing. When it is true, the sandbox state is already `stopped` when the
   response arrives (the server settles it first), so `start()` can follow at once and the next
   exec works; no polling is needed. Verified on the beta at commit 6a4bcd8 (gvisor,
   `bytearray(3<<30)`: exit 137, `sandbox_stopped` true, state `stopped`, start, `echo alive`
   exit 0).
4. Large writes count toward the memory limit. gVisor keeps file data in sandbox memory, so
   writing large amounts of data also counts toward the memory limit. Verified on a 512 MiB
   gvisor sandbox: writes of 1-2 GiB were fine on both `/root` and `/tmp`, while 3.5 GiB writes
   stopped the sandbox in some runs on either path (3 of 7 under `/tmp`, 4 of 6 under `/root`).
   Advice for the gvisor tier: keep single large writes well under a few GiB per sandbox, or
   raise the memory limit.
5. DNS: gvisor sandboxes resolve names through public resolvers (`1.1.1.1` and `8.8.8.8` by
   default on the hosted beta; a self-hosted operator can change them), because gVisor cannot
   reach Docker's internal resolver. On the allowlist network, direct lookups fail immediately
   (see Network modes and DNS).
6. User namespaces: `unshare` itself works inside gvisor, but writing `/proc/self/uid_map` is
   refused (EPERM), so a process cannot map itself to root. See "User namespaces per tier".
7. Kernel introspection such as the kernel symbol table (`kallsyms`) is absent. `nproc` and
   `MemTotal` reflect the sandbox limits.

Supervisors: treat a 409 "the sandbox container is not running" from exec as the sandbox being
down, and re-read the sandbox state. It moves to `stopped` within a few seconds after an exec
sees the sandbox die.

## Process limits per tier

The driver passes `pids_limit=512` to Docker for every tier. What that limit bounds depends on
the runtime. Measured on the hosted beta host on 2026-11-26 with one throwaway container per
runtime, the create options of a sandbox (1 CPU, 512 MiB memory without swap, `pids_limit=512`,
the capability set above, `no-new-privileges`) and a loop that forks up to 1500 sleeping
children. The host was unaffected in all three cases. These are single measurements on a shared
instance, not a benchmark:

| Tier | `pids.max` inside | Fork loop |
|---|---|---|
| container (runc) | 512 | stopped at 511 children with `EAGAIN` |
| gvisor (runsc) | cgroup files not visible | the 512 MiB memory limit ended it before 100 children: the sandbox was OOM-killed (exit 137) |
| microvm (Kata) | `max` | passed 1300 children, then the whole VM ended |

- Only on the `container` tier does the guest see a process-count limit (`pids.max` 512). On
  `gvisor` Docker applies the limit to the host cgroup that holds the `runsc` processes, and the
  guest does not see it. In the measurement the memory limit ended the fork loop first, and fork
  can also fail with an error such as `ENOMEM` ("gVisor: verified behavior" item 3). On `microvm`
  the guest kernel does not take the limit over, and the measured loop ended with the whole VM.
- On `gvisor` and `microvm` the measured fork loops ended with the sandbox or VM, not with a
  refusal of the 513th process. Exec reports it as described under "gVisor: verified behavior"
  item 3 and "microVM (Kata): verified behavior".
- The one live fork-bomb test, `test_fork_bomb_exhausts_its_pid_budget_and_spares_the_host` in
  `tests/test_docker_hardening_phase5.py`, builds its driver from default `Settings()`, which
  sets no tier runtime, so it runs on the Docker daemon's default runtime (`runc`, unless the
  daemon is configured otherwise). The `gvisor` and `microvm` rows above are not covered by a
  test in the repository.

## User namespaces per tier

Measured on the same host, date and create options as above: a process calls
`unshare(CLONE_NEWUSER)` and then writes `/proc/self/uid_map`.

| Tier | `unshare` | `uid_map` write |
|---|---|---|
| container (runc) | refused (EPERM) | not reached |
| gvisor (runsc) | works | refused (EPERM) |
| microvm (Kata) | works | refused (EPERM) |

- The repository's seccomp profile (`deploy/seccomp.json`) leaves `unshare` out of its
  allowlist, so its default action refuses it with errno 1 (`EPERM`), and it also denies `clone`
  with the flag that creates a user namespace. The live test
  `test_repository_seccomp_profile_denies_user_namespaces` (skipped under gVisor) runs
  `unshare -U` and checks that refusal. It covers the repository profile only, where
  `SANDFORT_SECCOMP_PROFILE_PATH` is set.
- The measured `container` row used the throwaway container's options, which name no seccomp
  profile, so Docker's default profile applied. There `unshare` needs `CAP_SYS_ADMIN`, which is
  dropped.
- The `microvm` tier runs with the host user namespace option (`userns_mode=host`,
  `SANDFORT_USERNS_HOST_TIERS`), and the repository configures no seccomp profile inside the
  Kata guest.

## Contained, not hidden

The tiers contain untrusted code. They do not hide the sandbox from it, and hiding it is not a
goal. Code inside a sandbox can work out that it runs in Sandfort and on which tier:

- the kernel: `4.19.0-gvisor` on `gvisor`, a guest kernel of its own on `microvm` (6.18.56 on
  the beta), the host's kernel on `container`.
- `/.sandfort-reserve`, a 16 MiB file that exists when the disk quota is on (always in `prod`
  and on the beta), and `/tmp/.sandfort-keep` on `gvisor` (see "gVisor: verified behavior").
- `docker-init` as PID 1 (`init=True`), and the `/tmp/.sf-exec-<id>.pid` and
  `/tmp/.sf-pty-<id>.pid` files while an exec or a PTY runs.
- on an egress allowlist sandbox, the `http_proxy` and `https_proxy` variables, whose URL
  carries the sandbox id.

These traces do work (disk reserve, process kill, keepalive, egress), and Sandfort has no layer
that masks them. Detonating or analysing malware that checks for sandbox traces is therefore not
a supported use case.

## Disk size

The requested disk size (`disk_gib`) is enforced only on hosts with XFS project quotas. The
hosted beta enforces it: its Docker uses overlay2 on XFS with project quotas, and the deployment
sets `SANDFORT_ENFORCE_DISK_QUOTA=true`, so `disk_gib` applies on all three tiers. Verified on
the beta on 2026-11-04 with `disk_gib=1`: writing 1.5 GiB stopped at 1 GiB (1073676288 bytes;
`dd` exit 1, "no space left") in both `/tmp` and `/root` on container, gvisor and microvm, and
the sandbox kept running. Free space by deleting files, or create a sandbox with a larger
`disk_gib`. The quota covers `/tmp` on every tier (item 1 above). Self-hosted deployments
without XFS project quotas do not enforce it.

A full disk, verified on the beta on 2026-11-04 (commit 6a4bcd8, and 203370a for the restart
at 0 bytes free):

- Writes fail with "No space left on device" (ENOSPC), and exec keeps working with no stray
  stderr.
- A file upload into a full sandbox answers HTTP 409 CONFLICT (`Conflict` in the SDK) with "the
  sandbox disk is full (no space left on device): delete files in the sandbox or create it with a
  larger disk_gib" and no host paths.
- A sandbox written until ENOSPC with 0 bytes free restarts with its data on all three tiers
  (verified on gvisor, microvm and container). Stop, start and snapshot of a full sandbox work;
  a snapshot of a full microvm sandbox restored all files into a new `disk_gib=3` sandbox.
- Mechanism: the quota is `disk_gib` plus 32 MiB, and Sandfort keeps a 16 MiB file,
  `/.sandfort-reserve`, in the sandbox. It empties the file in place before every stop and
  refills it after every start, so `df` shows about 32 MiB more than `disk_gib` (1.1G for
  `disk_gib=1`). Do not delete `/.sandfort-reserve`: a user who deletes or truncates it loses
  the protection until the next start recreates it.

## Overhead: gvisor compared with container

Overhead varies by host and workload. Two measurements follow; treat both as indicative, not as
a benchmark of the hosted beta.

First measurement: a laptop-class machine inside a nested Docker daemon; each value is the
median of 6 runs.

| Operation | container | gvisor | Ratio |
|---|---|---|---|
| Create to started | 158 ms | 160 ms | about the same |
| Trivial exec | about 20 ms | about 20 ms | about the same |
| CPU-bound Python loop | baseline | within about 2-5% | about the same |
| 5 MB upload / download | baseline | within about 5% | about the same |
| Stop, start, delete | baseline | within about 10% | about the same |
| 200 sequential process spawns | 103 ms | 384 ms | about 3.7x |
| Create, stat and delete 10,000 small files | 172 ms | 776 ms | about 4.5x |

Second measurement: a second evaluator, a different run.

| Operation | container | gvisor | Ratio |
|---|---|---|---|
| 200 Python subprocess spawns | 26 ms | 216 ms | about 8x |
| 200 `/bin/true` runs from a bash loop | 0.044 s | 1.80 s | about 40x |
| 10,000 small files | 0.30 s | 2.63 s | about 9x |

Create, exec, CPU-bound work and file transfer cost about the same on both tiers. Spawn-heavy
and small-file-heavy work (package installs, git, compilers, large test suites) is several
times slower on gvisor, from about 3x to about 9x in our measurements, and more for very
fork-heavy shell loops. Buyers should time their own build or test command on both tiers
before choosing.

## microVM (Kata): verified behavior

The `microvm` tier is offered on the hosted beta (verified there on 2026-11-04).
`GET /v1/isolation` returns the available tiers `container`, `gvisor` and `microvm`; the
default stays `gvisor`. The beta VM exposes KVM (nested virtualization). The Kata install
script in the operations repository installs Kata 4.3.1 pinned by SHA-256, registers the Docker
runtime `kata` next to `runsc`, and reloads Docker's runtime list without restarting containers;
it has a rollback mode. The runtime is the Rust one, with QEMU as the hypervisor.

- Each sandbox has its own guest kernel. It reported 6.18.56, not the host's 6.8.
- Measured on the beta: create to started about 4 s (six runs 3.70-3.96 s, median 3.84 s) and
  start 3.7 s. With `block_network=True` create takes about 8-9 s (8.1-9.1 s observed over 22
  creates). The other tiers are well under a second. Treat these as measurements on one shared
  instance, not a benchmark.
- The extra 5 s with `block_network=True` is Kata behaviour (measured 2026-11-05: about 3.9 s with
  the network, 8.6-9.0 s without; gvisor 0.35-0.47 s either way). In Docker's network mode `none`
  the Kata runtime-rs shim finds no interface after start, waits for its rescan timeout of about
  5 s and logs "no network interfaces after rescan timeout; networking may rely on hooks only".
  Sandfort's start path adds nothing measurable. No workaround: an internal bridge network would
  give the sandbox an interface and weaken the no-network guarantee.
- Exec, the clean 127 messages, timeouts (124), file upload and download including `/tmp`,
  `code_run`, stop and start with files kept, and delete (0.7 s) all work.
- A program that touches more memory than the limit is OOM-killed inside the VM: exit code 137
  with empty stderr (the guest kernel logs "Out of memory: Killed process"). The sandbox keeps
  running and `sandbox_stopped` is false. A single huge allocation can instead fail with
  `MemoryError` (exit code 1).
- A fork bomb can stop the whole microvm, as on gvisor. The exec then reports exit code 137 with
  `sandbox_stopped` true and the message "the sandbox stopped while running this command ...";
  the sandbox is already `stopped` when the response arrives, with an `error_reason`, and
  starting it again works at once (start takes about 4 s on microvm). Measured on the
  beta: of 29 python fork bombs on microvm, 26 returned exit 137 with `sandbox_stopped` true
  within 6.1-12.7 s; 3 returned 124 `timed_out` with the sandbox already dead. Since commit
  5243f36 a death wins over the deadline: when the sandbox dies before or at the deadline the
  result is exit 137 with `sandbox_stopped` true, not a timeout. Earlier check at commit
  6a4bcd8 (python and bash bombs, `timeout_s=60`, 4 of 4 runs): exit 137, `sandbox_stopped`
  true, `timed_out` false after 6-10 s, state `stopped`, clean message. Before those fixes the
  exec often returned exit 124 only at the full timeout, or 255, with `sandbox_stopped` false.
  The state is polled for up to 3 s after a suspect exit or timeout, and an exec on a dead
  runsc/kata container returns within about 2 s instead of at its deadline. `timeout_s` is a
  budget, not an exact cutoff: a command at `timeout_s=10` returned after about 13 s (kill and
  cleanup). Remaining caveat, narrowed: the classic bash fork bomb `:(){ :|:& };:` usually
  returns exit 0 within about 1 s on gvisor and microvm, and that exec response itself still
  says exit 0. Since the post-exec death probe (`src/sandfort/api/death_probe.py`), the exec
  route on these two tiers re-inspects the container 2, 6 and 15 seconds after the latest exec
  and settles a dead sandbox through the reconciler (state `stopped`, `sandbox.drift_detected`
  audit row), so the row no longer waits for the next exec or the periodic pass; a later exec
  still reports `sandbox_stopped` as before.
- The CPU limit is enforced: CPU-seconds per wall second matched the requested 500, 1000 and 2000
  millicores. `nproc` reports 1, 2 and 3 for those sizes rather than the requested count, and
  `MemTotal` is somewhat below the requested memory (454328 kB for 512 MiB). Size thread pools
  from the requested resources.
- DNS: microvm sandboxes resolve through the same public resolvers as gvisor (`1.1.1.1` and
  `8.8.8.8`); with `block_network=True` they have no DNS configuration (see Network modes and
  DNS).
- Boundary: the beta VM is itself virtualized, so the microvm tier is Kata on nested KVM. We make
  no claim beyond other microVM offerings. The container and gvisor tiers are not
  microVM-grade isolation. Per-sandbox disk size is enforced on the beta (see Disk size).

## Network modes and DNS, per tier

- open: names resolve on all tiers (gvisor and microvm through `1.1.1.1` and `8.8.8.8`).
- blocked (`block_network=True`): no network and no DNS on any tier. The sandbox shows no DNS
  configuration from the host, and lookups fail at once on every tier.
- allowlist: allowlisted hosts are reachable only through the egress proxy that the sandbox's
  `HTTP_PROXY` and `HTTPS_PROXY` variables point to (pip, curl and Python requests use them);
  every other destination is refused. On gvisor and microvm, direct DNS lookups fail
  immediately. On the container tier the sandbox's only DNS server is the egress proxy's sink
  (on the beta since the API restart at 2026-11-25T08:12:30Z), which answers every query
  REFUSED and forwards nothing, so only the proxy resolves names and direct lookups fail here
  too (`docs/egress-v2-design.md` section 6). Gate 11 and the D3/D4 driver tests passed on the
  beta VM's Docker daemon on 2026-11-25. Gate 11 starts its own server and proxy and D3/D4
  drive the driver directly, so neither exercised the deployed API. A container-tier sandbox
  created before the sink was enabled, including one created earlier on 2026-11-25, keeps the
  old resolvers until it is reset or recreated. The proxy variables, including the per-sandbox proxy credentials,
  are visible to code inside the sandbox.

## Exec results, output cap and untrusted submissions

- Out-of-memory kills read `stop_reason` `oom_killed` (and `stop_cause` `oom_killed` on the
  sandbox, `oom_killed` true in the drift audit row) when the container died of it on the
  `container` (runc) and `gvisor` (runsc) tiers: the Docker daemon records `OOMKilled` for the
  dead container (measured 2026-11-27, Docker 29.10.0, cgroup v2), and the server reads it only
  with exit code 137. The daemon does not set it under `microvm` (Kata), so there an
  out-of-memory kill still reads `killed`, or `sandbox_stopped` with `container_exited`. The
  server also reads the cgroup `oom_kill` counter for a single process killed while the
  container keeps running, and that works on the `container` tier only (gVisor and microVM keep
  their own kernel, so the host does not see those kills). Limit: Docker keeps the flag set
  after an out-of-memory kill the container survived, so a container that survived one and is
  later SIGKILLed by something else still reads `oom_killed`.
- Exec results include `sandbox_stopped` (REST field; SDK `ExecResult.sandbox_stopped`): true
  when the command's sandbox stopped (a gvisor limit overrun, or a fork bomb on gvisor or
  microvm). The CLI then prints a hint to
  start the sandbox again. Use it instead of re-reading the state right after an exit code 137.
  The sandbox state is already `stopped` when such a response arrives, so calling `start()`
  right away is safe and the exec after it works; no polling is needed. A sandbox that dies
  before or at the deadline is reported as exit 137 with `sandbox_stopped` true, not as a
  timeout (124); `timeout_s` is a budget, not an exact cutoff (about 13 s observed at 10).
- When a command's output reaches the 1 MiB cap, the command is stopped, the result has
  `truncated=true`, and stderr says "the command was stopped because its output exceeded the
  limit of 1048576 bytes".
- Untrusted submissions (graders, course platforms): use one sandbox per untrusted submission.
  On the gvisor tier a limit overrun stops the whole sandbox, and a backgrounded fork bomb can
  exit 0 before the sandbox stops, so in a reused sandbox the next submission would fail
  instead. A fork bomb can stop a whole microvm too, so the same advice applies there. Separate
  sandboxes are not affected by each other. Treat `sandbox_stopped`, exit code 137 and a failing
  follow-up exec as failure of the submission. After every submission run one trivial probe exec
  (for example `true`) in the same sandbox and treat an exception, a non-zero exit or
  `sandbox_stopped` as a runtime error; on `timed_out`, probe before reporting a timeout (a dead
  sandbox is a runtime error). The server retries a delete after a crash, so no client retry is
  needed.
- On the container tier `nproc` and `MemTotal` show the host's values, not the sandbox limits;
  size thread pools from the requested resources.

## Snapshots and isolation tier

- A snapshot taken from a sandbox records that sandbox's isolation tier (shown as `isolation` on
  the snapshot).
- A sandbox created from it without an explicit `isolation` gets the same tier; an explicit
  `isolation` overrides it.
- If the recorded tier is not offered, the create is refused with the 422 that names the
  available tiers.
- Snapshots made from a public image or an image spec have no recorded tier.
- A sandbox created from a snapshot does not inherit the source sandbox's resources: it gets
  the defaults (`cpu_millicores` 1000, `memory_mib` 512, `disk_gib` 3) unless `resources=` is
  passed. It does inherit the isolation tier. Its disk quota counts only what it writes
  itself; the snapshot content it starts from does not count against `disk_gib`.

## Resize

`POST /v1/sandboxes/{id}/resize` changes CPU and memory of a stopped sandbox (409 INVALID_STATE
when it is started). The TypeScript SDK has `resize`; the Python SDK and the CLI have no helper
for it yet. The root filesystem is kept: the
start that follows commits the stopped container to a local image (`sf-resize-<id>`) and creates
the new container from it, on all three tiers. The image stays while the sandbox lives (the next
resize commits to the same tag) and goes with the sandbox. A reset still wipes.

## Rollout

1. Deploy the gVisor driver fixes and per-sandbox tiers. Done.
2. On the beta: offer `container` and `gvisor`, default `gvisor`. New sandboxes get gVisor. Done
   (2026-11-04).
3. Install Kata, verify, then add `microvm`. Done (2026-11-04): the beta offers all three tiers.
4. Re-run the evaluation personas per tier. Start time and overhead for container and gvisor
   are measured (see Overhead, laptop-class nested Docker); repeat them on the beta node's
   hardware. The microvm times were measured on the beta (create to started about 4 s, about 8-9 s
   with `block_network=True`).

## Beta status: image builds and user-namespace remapping

The hosted beta is moving image builds onto gVisor (the daemon `default-runtime` set to
`runsc`) and enabling user-namespace remapping on its sandbox node. There is no date for
either, and neither changes the tier descriptions above. Until remapping is on, container root
maps to host root on the `container` and `gvisor` tiers. Once it is on, the `container` and `gvisor` tiers run
remapped and the `microvm` tier keeps the host user namespace through
`SANDFORT_USERNS_HOST_TIERS` (see "API and configuration" and [security] section 2).

[operations]: https://docs.sandfort.dev/operations.html
[security]: https://docs.sandfort.dev/security.html
