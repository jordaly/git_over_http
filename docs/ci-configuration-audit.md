# CI configuration audit

- **Reviewed:** November 18, 2026
- **Scope:** Repository-owned CI configuration, manual runs, secret scoping, retention, and API provenance.
- **Recommendation:** Inventory and migrate legacy CI definitions before rollout. The original findings and the separate conflict-resolution protection gap have fixes.

## High: Repository-wide merge protection

**Original finding:** Both merge handlers read `require_ci` from the target branch, so a release branch could omit the default branch's repository-wide requirement.

**Remediation:** Web and API merge handlers read the requirement from the default branch. The exact target commit still selects required pipelines, and a successful check must match the current target and source commits. Regressions cover release branches and checks from a different target commit.

## High: Protection when Git policy reads fail

**Original finding:** A failed Git read could select a preset with push protection disabled.

**Remediation:** A Git failure resolving `HEAD` or reading the root policy is treated as unverifiable, not as missing configuration. HTTP receive-pack rejects the write, and merge and branch mutation gates fail closed. A verified unborn repository remains writable. Regression tests cover both Git failure and the verified-unborn case.

## Medium: Retention cleanup with stale or missing policy

**Original finding:** Cleanup could use a stale cache after a ref update, and a refresh failure could prevent CI scheduling.

**Remediation:** The cache records the default-branch commit. A missing, unavailable, or mismatched entry pauses deletion; server defaults apply when a verified policy omits a limit. Cleanup rechecks `HEAD` before releasing its savepoint and rolls back if it detects a change. A retention refresh failure is not allowed to stop the push finalizer from reaching CI scheduling.

## Medium: Remote assignment secret retention

**Original finding:** Assignment documents retained the effective job environment after the attempt was closed or recovered.

**Remediation:** The remote coordinator removes environment and scope fields on completion, close, or recovery and scrubs legacy terminal rows. Active assignments still carry the environment for execution. Attempt identity, results, and no-replay behavior remain intact. This is logical cleanup, not secure erasure of previous backups, database pages, or job logs.

## Independent re-audit

An OpenCode Go subagent using DeepSeek V4.1 Flash 1017 reviewed the combined code. It confirmed the original merge and push regressions were addressed in the changed paths, verified fail-closed retention on missing or stale cache rows, and confirmed remote assignment records are scrubbed on terminal transitions.

### Fixed on follow-up: conflict resolution could write protected refs

The web form and Web IDE conflict-resolution handlers used to call [`apply_resolution`](../pygithost/pr_resolver.py) without enforcing the source branch's direct-push policy. Both handlers now read the default-branch policy and reject protected source-branch writes under the repository push lock. Both require a CSRF token. Regression tests cover rejection without a ref update, invalid form submissions, and successful resolution on an unprotected branch.

### Remaining limitations and follow-up

- **Retention concurrency:** SQLite can hold its write lock while resolving Git `HEAD`. The final recheck is not atomic with Git ref updates, and a concurrent change to server retention caps is not revalidated. An unavailable row with a known commit can also leave cleanup paused until a subsequent push or restart. Test contention and close these gaps before relying on retention for tight storage limits.
- **Historical secret storage:** Assignment scrubbing does not rewrite older run or deployment snapshots. Operators should review historical exposure and rotate affected credentials as appropriate. This also does not erase logs or existing backups.
- **Defense in depth:** Make Git-policy failure checks explicit at mutation entry points, serialize API merge policy checks with ref mutations, and make the UI state for unverifiable policy or paused retention clearer. For non-bare repositories, policy follows Git `HEAD`. A separate CI enqueue failure can still surface after a push has already updated refs.

## Verification

After the conflict-resolution fix, the full suite passed: 661 tests run, 11 skipped, no failures. The earlier 73 focused retention, validation, and remote-runner tests also passed. All applicable pre-commit hooks (including strict mypy and Ruff) and `git diff --check` passed.

These checks do not establish production migration readiness.
