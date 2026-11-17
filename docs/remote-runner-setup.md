# Deploy a remote Docker CI runner on a new Ubuntu server

This walkthrough installs a **new** worker. It does not move GitHost or deployments
off Windows. Administrators may use SSH for installation; CI itself uses outbound
HTTP(S), without an inbound worker port.

[Installed test VM](http-runner.md) · [Docker limits and policy](docker-profiles.md)

## 1. Verify the server requirements

Check every item before proceeding:

| Requirement | What the future runner server needs |
|---|---|
| OS | Linux Docker host; Ubuntu 26.04 is the tested installation target. Windows container images cannot run here. |
| Architecture | CPU architecture matching the CI images and native dependencies; the current installation is x86-64. |
| Python | Python 3.14-compatible interpreter for this GitHost revision. An older Ubuntu release's default Python may be insufficient. |
| Git | Available to the service account for exact-commit checkout and PR preparation outside the container. |
| Docker | Local Docker Engine and CLI using Linux containers; working cgroup resource enforcement. Compose is optional and is not used by this runner. |
| CPU/RAM | Container budget **plus** Ubuntu/Docker/checkout overhead. A practical small-job starting point is 2 vCPU / 4 GiB RAM, not a guarantee for Wine/.NET jobs. |
| Disk | Images/layers, Git histories, checkout and temporary artifacts. Start with at least 20 GiB free for small images; Wine/vendor images may require substantially more. Monitor disk: complete job disk quotas are not provided. |
| GitHost connectivity | Outbound TCP to its HTTP(S) listener. No public worker IP, inbound worker port, shared Windows drive or server-to-worker SSH connection is necessary. |
| Provisioning connectivity | Approved OS packages, Git source and image registries reachable during installation, or provided through an approved offline process. Containers have no network by default. |
| Clock | Synchronized host time for logs, leases and tests involving authentication expiry. |
| Account | Dedicated unprivileged service account. Docker group membership effectively grants root access to the machine; use a dedicated VM/server. |
| GitHost version | Same tested supporting code revision on GitHost and worker; `/api/runner/v1` available. |
| GitHost allowlist | Permits the worker's actual observed source IP, accounting for NAT. Do not disable filtering globally to make it work. |
| Credential | Unique dedicated runner token restricted to explicit repositories, not a personal API token or a token shared by another worker. |
| Workload | Linux-compatible commands and prebuilt dependencies. Windows paths such as `/mnt/c/...` are not automatically available. |
| Private inputs | Test-only credentials/fixtures and an administrator-reviewed policy when network or secret mounts are needed. No production credentials. |

Do not host unrelated production secrets/workloads on a machine intended for
untrusted CI. Containers are not a complete hostile-code isolation boundary.
Resource ceilings do not provision hardware.

Inspect the proposed server:

```bash
cat /etc/os-release
uname -m
nproc
free -h
df -h / /var/lib
timedatectl status
```

Resolve insufficient capacity or incompatible architecture/interpreter before
installing. Size heavier workloads from measurements rather than these examples.

## 2. Choose the address, identity and scope

Record the GitHost origin, exact repository namespace/name, unique worker name,
approved image and resource/security ceilings. On the existing private VM network
GitHost is `http://192.168.250.1:8000`; a different server needs its own reachable
address.

Prefer HTTPS. Plain HTTP requires `--allow-http` and transmits credentials,
source and job data unencrypted. Never disable TLS verification or expose Docker
on port 2375 as a workaround.

Check reachability from Ubuntu:

```bash
curl --noproxy '*' -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  http://YOUR_GITHOST:8000/api/runner/v1/openapi.json
```

Replace `YOUR_GITHOST`. Expected: `401`, meaning reachable but authentication
required. `403` means review the IP allowlist. Connection errors mean check routing,
firewalls, address and GitHost listener. Verify the source IP GitHost sees under
NAT rather than assuming it matches the guest's interface address.

## 3. Install prerequisites

On Ubuntu 26.04:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv docker.io ca-certificates curl
sudo systemctl enable --now docker
python3 --version
git --version
sudo docker version
sudo docker info
```

On another release, obtain a compatible interpreter through your approved
installation process. `apt install python3` does not necessarily install 3.14.
Ensure Docker reports Linux and its resource-control environment is functional.

## 4. Create the account and install the reviewed code

These commands assume a new account/path. If they exist, inspect them first;
do not overwrite, reset or discard another installation.

```bash
sudo useradd --system --create-home --home-dir /var/lib/githost-runner \
  --shell /usr/sbin/nologin githost-runner
sudo usermod -aG docker githost-runner
sudo git clone https://github.com/jordaly/git_over_http.git /opt/pygithost
sudo git -C /opt/pygithost checkout --detach YOUR_REVIEWED_COMMIT
sudo python3 -m venv /opt/pygithost/.venv
sudo install -d -m 700 -o githost-runner -g githost-runner \
  /var/lib/githost-runner/config /var/lib/githost-runner/work
sudo install -d -m 750 -o root -g githost-runner /etc/pygithost-runner
```

Replace `YOUR_REVIEWED_COMMIT` with the version used by GitHost. The runner itself
uses the standard library; no application dependencies need installing into this
venv. Keep the code administrator-owned, outside job mounts. Never run the worker
service as root.

Verify:

```bash
sudo -u githost-runner git --version
sudo -u githost-runner /opt/pygithost/.venv/bin/python --version
sudo -u githost-runner docker info --format '{{.ServerVersion}}'
```

Fix group membership if Docker access is denied; restart an existing worker after
membership changes. Do not grant jobs the Docker socket.

## 5. Choose and verify the approved job image

For a standard-library smoke test, optionally pre-pull the image to verify access:

```bash
sudo docker pull python:3.14-slim
sudo -u githost-runner docker image inspect python:3.14-slim >/dev/null
```

For the real application, build or publish a reviewed dependency image beforehand,
or explicitly authorize [building missing images](image-builds.md) for a trusted
repository/event. Builds remain disabled by default.
With worker policy `image_pull: "missing"` (the default), the service downloads
absent images on the Ubuntu host before execution; pre-pulling is not required.
Use `never` for offline/cache-only workers or `always` to refresh before each job.
Containers still use `--pull=never` and cannot download packages with the default
network isolation. Ensure the service can reach the registry, including DNS and
any required proxy/firewall configuration for the Docker daemon.
Keep private-registry credentials in the administrative provisioning process,
not a job-mounted Docker configuration.
See [Dependency images](http-runner.md#docker-images-and-dependencies).

## 6. Install conservative worker ceilings

Create `/etc/pygithost-runner/policy.json` with `sudoedit`:

```json
{
  "max_cpus": 1,
  "max_memory_mb": 1024,
  "max_pids_limit": 128,
  "max_tmpfs_mb": 256,
  "max_timeout_seconds": 1800,
  "networks": ["none"],
  "allow_writable_root": false,
  "allow_root": false,
  "image_pull": "missing",
  "max_image_pull_timeout_seconds": 600,
  "secrets": {}
}
```

Set permissions:

```bash
sudo chown root:githost-runner /etc/pygithost-runner/policy.json
sudo chmod 640 /etc/pygithost-runner/policy.json
```

Raise only reviewed ceilings the machine can support. Secret entries require
explicit repository/trusted-event restrictions. Allowing a network name does not
restrict outbound destinations: use firewall rules where necessary.
See [Docker profiles](docker-profiles.md). A repository cannot grant itself higher
ceilings. Never put worker policy or private files in a source repository.

## 7. Issue and securely install the token

On the **GitHost host**, from its checkout/Python environment:

```powershell
cd C:\git_over_http
python -m pygithost.runner create-token --db C:\temp\pygithost.db --name ubuntu-build-02 --repository root/my-project
```

Adapt the paths/name/repository to the real server. Repeat `--repository` for
additional explicit repositories. Use the actual existing database. The token is
displayed once: transfer through a secure administrative channel. Do not put it in
chat, Git, command-line arguments, CI variables or saved console transcripts.

In an interactive **Bash** terminal on Ubuntu:

```bash
sudo -v
read -rsp 'Runner token: ' RUNNER_TOKEN
echo
printf '%s' "$RUNNER_TOKEN" | sudo tee /var/lib/githost-runner/config/token >/dev/null
unset RUNNER_TOKEN
sudo chown githost-runner:githost-runner /var/lib/githost-runner/config/token
sudo chmod 600 /var/lib/githost-runner/config/token
```

The parent directory is private and the token is never mounted in job containers.
Use a distinct token and private state directory per worker. Protect any backups.

## 8. Install the service

Create `/etc/systemd/system/pygithost-runner.service`:

```ini
[Unit]
Description=PyGitHost remote Docker CI runner
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=githost-runner
Group=githost-runner
SupplementaryGroups=docker
WorkingDirectory=/opt/pygithost
ExecStart=/opt/pygithost/.venv/bin/python -m pygithost.runner run --server http://YOUR_GITHOST:8000 --token-file /var/lib/githost-runner/config/token --work-dir /var/lib/githost-runner/work --policy-file /etc/pygithost-runner/policy.json --allow-http
Restart=on-failure
RestartSec=10
TimeoutStopSec=150
UMask=0077

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_GITHOST`; for HTTPS change the scheme and remove `--allow-http`.
Do not run a foreground worker alongside this service.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pygithost-runner
sudo systemctl status pygithost-runner --no-pager
sudo journalctl -u pygithost-runner --no-pager -n 50
```

Idle workers may produce no new logs. Fix invalid policy, permission and interpreter
errors before attempting a job. Active service status is not proof of job success.

The first job may show phase `image` while the daemon downloads a missing image.
Check its combined CI log for registry errors. The default image-provisioning
budget is 600 seconds, independent of the command execution budget.

## 9. Validate a disposable smoke pipeline

In an authorized repository's **CI → Settings → Configuration JSON**, add a smoke
pipeline while preserving unrelated pipelines, policies and deployments:

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "remote-smoke",
      "execution": {
        "runner": "remote-docker",
        "image": "python:3.14-slim",
        "timeout_seconds": 120,
        "docker": {"cpus": 1, "memory_mb": 512}
      },
      "triggers": {"manual": {"enabled": true}},
      "steps": [
        {"name": "Verify Linux", "run": "python -c \"import os,platform; assert platform.system() == 'Linux'; assert os.getuid() != 0; print(os.environ['PYGITHOST_COMMIT'])\""},
        {"name": "Artifact", "run": "python -c \"open('runner-proof.txt','w').write('remote Docker CI succeeded')\""}
      ],
      "artifacts": {"paths": ["runner-proof.txt"], "when": "always"}
    }
  ]
}
```

Trigger `remote-smoke` manually. Manual CI never deploys. Verify:

1. The run is assigned rather than left waiting for an eligible worker.
2. Both steps pass; logs show the recorded exact commit.
3. `runner-proof.txt` downloads from GitHost and has the expected content.
4. `sudo docker ps -a --filter label=pygithost.http-attempt` shows no leftover job
   container after completion.
5. The worker stays active and its work directory has no leftover `job-*` directory
   from the successful run.

Then validate disposable failure/timeout/cancellation runs and their cleanup.
Do not confuse an active service with passing tests.

## 10. Onboard real workloads and plan maintenance

Use reviewed images and Linux-compatible commands. Match `execution.docker`
requests to the worker policy; rejected requests fail with phase `runner policy`,
not silent fallback. Keep shared-database suites sequential and use only guarded
test targets. Wine/.NET needs an adapted prefix/writable layout; do not run
Docker-launching host wrappers inside the container.

Plan OS/image updates, free-space monitoring, credential rotation and idle windows
for worker upgrades. Update the worker to the same tested code revision as GitHost;
it does not update itself. Stop the idle service before changing its code/policy.
Do not reset local changes, delete receipts/SQLite files, prune Docker indiscriminately
or remove database fixture recovery journals to force progress.

GitHost keeps new source bundles in private temporary files, with paths/cleanup
metadata in SQLite. Blocked deletions are queued persistently and retried; monitor
`source_cleanup_deferred` warnings and free space on the **GitHost host** as well
as the worker. Do not delete cleanup records or unrelated temporary files.
See [Server-side source storage](http-runner.md#server-side-source-storage).

For a deliberate stop: `sudo systemctl stop pygithost-runner`. Stopping an active
job interrupts it; this is not pause/resume. For decommissioning, also disable the
service and revoke its token on GitHost with `revoke-token --db ... --name ...`.
After unexpected worker loss, inspect containers/external state before manually
creating a new run. Uncertain attempts are never automatically replayed.

See [Operations and troubleshooting](http-runner.md#operate-the-installed-ubuntu-service).
This installation does not require restarting Windows or stopping application
services such as `FuenteInteligenteAPI`.
