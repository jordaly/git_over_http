# Configurable Docker limits

Remote pipelines request a Docker execution profile in `execution.docker`.
The Ubuntu worker separately enforces an administrator-owned policy. A repository
can request capabilities, **not authorize itself** to use them.

Omitting `docker` preserves the existing hardened container defaults. Unknown
fields, arbitrary Docker flags, host networking, host-path mounts and privileged
containers are rejected rather than silently accepted.

## Default profile and worker ceilings

| Pipeline field | Default | Meaning |
|---|---|---|
| `cpus` | `1` | CPU quota; numeric, minimum `0.1` |
| `memory_mb` | `1024` | Container memory limit in MiB |
| `pids_limit` | `128` | Maximum container processes |
| `tmpfs_mb` | `256` | Writable `/tmp` capacity in MiB |
| `read_only` | `true` | Read-only container root filesystem |
| `network` | `"none"` | No container networking |
| `user` | `"runner"` | Worker UID/GID, not container root |
| `checkout_path` | `"/workspace"` | Exact-commit checkout mount |
| `checkout_read_only` | `false` | Whether checkout is read-only |
| `workdir` | checkout path | Initial working directory |
| `mounts` | `[]` | Declarative checkout/results/named-secret mounts |
| `tmpfs` | `[]` | Additional disposable writable container directories |

By default the worker ceilings match those resources, permit only network `none`,
deny writable root and root-user requests, expose no secrets, and limit job
`timeout_seconds` to 1800. Extra tmpfs sizes plus `/tmp` count against the aggregate
tmpfs ceiling. Requests over a ceiling **fail**, not silently clamp.

`PYGITHOST_WORKTREE` and command substitutions follow `checkout_path`.
Every step gets a fresh container: only checkout/results files persist. Tmpfs,
container-root changes, processes and shell state do not survive between steps.
Checkout mount aliases refer to the same job checkout, never a live host repository.

## Pipeline example

This configuration requests more memory/CPU, a read-only `/source`, a writable
`/work` tmpfs, and a separate results mount. It needs the worker policy below:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {
        "runner": "remote-docker",
        "image": "my-project-ci:1",
        "timeout_seconds": 3600,
        "docker": {
          "cpus": 2,
          "memory_mb": 2048,
          "pids_limit": 256,
          "tmpfs_mb": 256,
          "checkout_path": "/source",
          "checkout_read_only": true,
          "workdir": "/source",
          "tmpfs": [{"target": "/work", "size_mb": 512}],
          "mounts": [{"source": "results", "target": "/results"}]
        }
      },
      "triggers": {"manual": {"enabled": true}},
      "steps": [
        {"name": "Tests", "run": "python -m unittest discover -v > /results/tests.log 2>&1"}
      ],
      "artifacts": {"paths": [".ci-results/*"], "when": "always"}
    }
  ]
}
```

`my-project-ci:1` must exist on Ubuntu and contain the project's dependencies.
The results mount maps to `.ci-results` inside the host checkout, allowing normal
artifact collection even when the container's `/source` view is read-only.
Do not commit `.ci-results` as a symlink.

## Worker policy

Store this JSON **on Ubuntu, outside any repository**, for example
`/etc/pygithost-runner/policy.json`:

```json
{
  "max_cpus": 2,
  "max_memory_mb": 2048,
  "max_pids_limit": 256,
  "max_tmpfs_mb": 1024,
  "max_timeout_seconds": 3600,
  "networks": ["none"],
  "allow_writable_root": false,
  "allow_root": false,
  "secrets": {}
}
```

Launch with `--policy-file /etc/pygithost-runner/policy.json`. The file must be at
most 64 KiB, owned by root or the service user, not a symlink, not group-writable
and inaccessible to other users. A root-owned file with group `githost-runner` and
mode `640` is suitable. The worker loads it at startup; restart an idle worker
after changes. A missing flag means the restrictive built-in policy, not unlimited
resources. Invalid policy prevents startup.

Changing repository JSON cannot raise these worker ceilings. Ensure the VM has
enough actual CPU/RAM/disk; increasing a ceiling does not provision capacity.
One-worker/per-token concurrency and GitHost scheduler limits remain unchanged.

### Controlled network access

The pipeline may request `"network": "bridge"` or an existing named Docker
network, but the exact name must be in the worker's `networks` allowlist.
The runner does not create networks. Docker `host` and `container:...` networking
are never allowed.

**A network allowlist is not a destination firewall.** Allowing `bridge` can
permit general outbound access. Apply host/network firewall rules separately if
jobs should reach only the test SQL server. Do not expose the Docker daemon or
mount its socket.

### Writable directories and root

Prefer a read-only root with explicit tmpfs directories. Extra tmpfs directories
are owned by the requested container UID/GID and are recreated per step.
For software such as Wine, prepare an image compatible with the runner UID and
copy its prepared prefix into writable storage before testing.

If unavoidable, a trusted pipeline may request `"read_only": false` and/or
`"user": "root"`; the worker must explicitly enable `allow_writable_root` and/or
`allow_root`. The worker service itself must still run unprivileged. Capabilities
remain dropped and `no-new-privileges` remains enabled. These permissions broaden
the attack surface and are not a guarantee that legacy software will work.

### Named private-file mounts

Repository JSON can reference a name, never an Ubuntu/Windows host path:

```json
{
  "mounts": [
    {"source": "secret:test-database", "target": "/test-config/App.config", "read_only": true}
  ]
}
```

This is an `execution.docker` fragment. The corresponding worker policy fragment:

```json
{
  "secrets": {
    "test-database": {
      "path": "/etc/pygithost-runner/secrets/authorized-test.config",
      "repositories": ["root/SistemaFuente"],
      "events": ["manual", "push", "pull_request_merged"]
    }
  }
}
```

The actual file must be a regular, non-symlink file with no symlink path
components. Keep permissions private. Secret mounts are always read-only and
require both the exact repository and an explicitly permitted trusted event.
PR checks cannot receive these mounts. Do not configure runner tokens, Docker
sockets or worker control files as secrets.

Mounting a file gives the job its contents: trusted commands can still copy it to
logs/artifacts or send it over an allowed network. Read-only does not mean
non-readable or non-exfiltratable. Supply only test-scoped credentials and retain
the project's guards against production database access.

### Mount/path rules

Allowed mount sources are `checkout`, `results`, or `secret:NAME`. Targets and
working directories are absolute Linux container paths without traversal or
Docker-option separators. Mounts/tmpfs cannot overlap each other, the checkout
mount or `/tmp`; sensitive system destinations are forbidden. Arbitrary host
directories, device mounts, Docker arguments, privileged mode, capability changes,
port publishing and entrypoint overrides are not supported.

## What is not configurable here

Source, logs, artifacts and transfer budgets are configured separately through
`execution.source_limit_mb` and `execution.limits`; see [CI limits](ci-limits.md).
The source default is 100 MiB, with no hard-coded upper configured size ceiling.
Image pulls remain administrator-managed. There is no automatic retry,
Docker-in-Docker or distributed SQL test lock.

The SistemaFuente Wine wrappers currently launch Docker themselves; do not run
those host wrappers inside a CI container. Invoke the image's internal test
process directly and adapt its directory/Wine-prefix layout. Merely granting a
network and mount does not validate its full SQL suite or make concurrent database
tests safe. No application pipeline or worker policy is changed automatically.
