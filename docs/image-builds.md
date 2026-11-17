# Build missing CI images

[HTTP runner](http-runner.md) · [Worker Docker policy](docker-profiles.md)

Builds are **disabled by default**, and supported only on the Linux HTTP worker.
Building repository Dockerfiles executes trusted code through the worker daemon;
this is not an untrusted-pull-request sandbox.

## Pipeline configuration

```json
{
  "version": 1,
  "pipelines": [{
    "name": "tests",
    "execution": {
      "runner": "remote-docker",
      "image": "local/project-ci:v1",
      "image_build": {
        "policy": "if-missing",
        "pull": false,
        "dockerfile": "docker/ci.Dockerfile",
        "context": ".",
        "target": "",
        "args": {},
        "prerequisites": [],
        "timeout_seconds": 1800,
        "memory_mb": 1024,
        "cpus": 1,
        "network": "none"
      }
    },
    "steps": [{"name": "Tests", "run": "python -m unittest discover -v"}]
  }]
}
```

Omitting `image_build` or setting it to `null` preserves download-only behavior.
Fields above show defaults except `pull` defaults to **true**, and `dockerfile`
defaults to **Dockerfile**. Paths are checkout-relative (including `dockerfile`
when context is a subdirectory). Traversal, URL contexts and symlink components
are rejected. Build fallback requires an image tag, not an immutable digest.

The worker checks out the exact queued source, then:

1. Reuses a local requested image or matching private build-cache image.
2. With `pull: true`, tries downloading the requested final image.
3. Falls back to building only on confirmed **manifest unknown**, or Docker 29's
   exact `failed to resolve reference "REF": REF: not found` response. Authentication,
   ambiguous "pull access denied", DNS, TLS, network and daemon errors fail visibly.
4. With explicit `pull: false`, skips that pull and builds when absent. No registry
   is required for these local-only tags.
5. Prepares declared prerequisites, builds the final image, then runs existing steps.

Worker `image_pull: "never"` also skips these tag pulls; `always` bypasses cache
shortcuts and refreshes requested images. `pull: false` conflicts with `always`.
Dockerfile **FROM images may still be downloaded by the daemon**, independently
of tag pulls and RUN networking. For offline operation provision every base/stage
image/dependency and enforce host egress policy.

## Explicit worker authorization

Merge this block into the existing administrator-owned policy and restart the
worker. Preserve existing secrets, resource ceilings and repository restrictions.

```json
{
  "builds": {
    "repositories": ["root/project"],
    "events": ["manual", "push", "pull_request_merged"],
    "networks": ["none"],
    "max_timeout_seconds": 1800,
    "max_memory_mb": 1024,
    "max_cpus": 1
  }
}
```

Repository/event lists default to empty. Authorization is required even when the
final image is already cached. Unmerged PR events, host networking, arbitrary
Docker flags, host preparation commands, build-secret mounts and Docker socket
mounts are unsupported. Explicitly allow build network `bridge` if trusted RUN
instructions must install packages. Test-container policy is separate.
Build args are literal, visible inputs—not secrets; never pass credentials.

## Backend, reporting and limits

This version explicitly uses the **legacy Docker builder**, `DOCKER_BUILDKIT=0`.
It supports the memory, equal memory/swap, CPU period/quota and network controls
used here. Docker is deprecating this backend: hosts without it fail; the runner
does not silently switch to BuildKit and ignore resource limits.

Limits apply to RUN containers, not daemon/context/disk usage or all host processes.
There is no build PID or disk quota. Use a dedicated host with administrator-owned
daemon/disk limits. Layer caching is enabled. Pin bases and verify downloads.

One preparation budget covers cache locks, inspections, pulls and all builds
(`timeout_seconds`, default 1800, bounded by worker policy). Each pull is also
bounded by `execution.limits.image_pull_timeout_seconds`. Test execution retains
its separate budget. Build output streams to bounded combined logs under phase
**image build**; failure/timeout skips tests and is distinguished from test failure.

Heartbeats continue during preparation. Cancellation terminates the Docker CLI
and disconnects the daemon request; the legacy builder cancels intermediates.
The detached watchdog targets this attempt's labelled build CLI on worker exit.
Cached layers may remain. Do not prune shared Docker data to cancel jobs.

## Prerequisites and reproducible inputs

Declare at most four prerequisite recipes in dependency order, each with `name`,
`image`, `dockerfile`, `context`, optional `target` and `args`. They share final
pull policy, resources, networking and total budget. Argument `${image:NAME}`
resolves an earlier prerequisite's selected private image tag; no shell/environment
interpolation occurs. A cached/downloaded final image skips prerequisites.

For example, an image extending SistemaFuente's Wine base could request:

```json
{
  "pull": false,
  "dockerfile": "docker/wine/ci-image.Dockerfile",
  "context": "docker/wine",
  "args": {"BASE_IMAGE": "${image:wine}"},
  "prerequisites": [{
    "name": "wine",
    "image": "sistemafuente-wine-e2e:latest",
    "dockerfile": "docker/wine/Dockerfile",
    "context": "docker/wine",
    "target": "desktop-runner"
  }],
  "timeout_seconds": 7200,
  "network": "bridge"
}
```

This requires corresponding administrator network/time authorization. It is
**not yet a clean-worker recipe**: the current `COPY sqlpackage /opt/sqlpackage`
also needs `docker/wine/sqlpackage` in that context. Provide a reviewed input or
change the project Dockerfile to fetch a pinned, checksum-verified archive in a
build stage and COPY from it. The worker does not download arbitrary archives or
run host scripts to silently prepare application dependencies.
Use `.dockerignore` to exclude `.git`, secrets and unrelated files. Keep private
database configuration in runtime named-secret mounts, never build args/contexts.
Checkouts are private. COPY can therefore preserve restrictive input permissions;
set appropriate ownership/read permissions in the Dockerfile for the unprivileged
runtime UID rather than weakening checkout privacy or running tests as root.
The existing Wine Dockerfile also contains experimental earlier stages; the legacy
builder can execute stages that BuildKit would skip. A clean-worker production
recipe must separate those probes or use a reviewed, prebuilt base image.

## Cache and cleanup

Results get private `pygithost-build/REPOSITORY_HASH:KEY` tags keyed by repository,
queued commit and recipe. They do not overwrite requested tags or other
repositories' build outputs. Existing requested tags are intentionally reused;
version them when changing their intended content. Pin Dockerfile bases/downloads.

Same-account workers serialize duplicate builds via file locks in private
`~/.cache/pygithost-images` (0700). Different accounts/hosts do not share locks;
use one build-worker account per daemon. Lock waits support cancellation.
A shared guard spans build-enabled execution to prevent administrative pruning
from racing active jobs.

As that same worker account:

```sh
python3 -m pygithost.runner prune-images --older-than-hours 168
```

This refuses while build-enabled jobs are active and removes only old, unused
`pygithost.build-cache=1` images. Docker protects images referenced by running or
stopped containers. Age means creation age, not last use. It does not prune
volumes, unrelated images or all intermediate layer cache. No automatic cleanup
schedule is installed. Do not run a broad `docker system prune`.
