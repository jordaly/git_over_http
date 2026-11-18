# CI retention and pagination

## Configure retention

Set administrator defaults under **Admin → Settings → Runs and artifacts**. These
defaults apply to repositories without project retention, and to any
retention field omitted from a project's configuration. The repository
**CI → Settings** page has no retention form.

A project may add this `retention` block alongside `pipelines` in the full
grouped **`ci/config.json`** document:

```json
{
  "retention": {
    "artifacts": {"days": 30, "max_count": 50},
    "runs": {"max_count": 100}
  }
}
```

The simple single-pipeline form cannot set retention. Cleanup uses the policy in
**`ci/config.json` on the default branch**. Feature branches and reruns cannot
change it. GitHost refreshes the policy at scheduler startup and after branch
updates it handles. The cached policy is tied to the commit it was verified at;
if `HEAD` later differs, including after a default-branch switch or an
out-of-band Git update, deletion pauses until the next successful refresh. If
the default branch configuration cannot be validated or the cache cannot be
updated, cleanup is paused rather than deleting data under a fallback policy.

An explicit nonzero administrator setting also acts as a cap: a repository may
choose a lower limit, but cannot exceed or disable that cap. A zero administrator
setting does not impose a cap.

| Setting | Default | Zero means | Maximum |
| --- | --- | --- | --- |
| Artifact expiration, in days | 7 | Never expire by age | 36500 |
| Maximum artifact bundles | 0 | No count limit | 1000000 |
| Completed CI runs to retain | 100, or administrator default | Keep unlimited completed runs | 1000000 |

A **bundle** is the ZIP archive collected from one CI run, not an individual file
inside the ZIP. Per-run artifact limits (default 20 MiB uncompressed and 1000
files, configurable through `execution.limits`) still apply; unlimited retention
does not remove those limits.

### Examples

| Goal | Expiration days | Maximum bundles | Completed runs |
| --- | --- | --- | --- |
| Keep artifacts for up to 30 days, at most 50 bundles | 30 | 50 | 100 |
| Keep the newest 20 bundles regardless of age | 0 | 20 | 100 |
| Keep all artifacts and all run history forever | 0 | 0 | 0 |
| Keep 100 runs but retain every artifact indefinitely | 0 | 0 | 100, plus protected artifact-bearing runs |

Age and count limits work together: an archive is removed when **either** limit
requires it. Count cleanup removes bundles belonging to the oldest run IDs first.
The age deadline is calculated from the archive's creation time, not from when
you last changed the policy.

Retained artifacts protect their parent CI run records. This prevents run pruning
from unexpectedly deleting artifacts you asked to keep. Active runs and runs
with pending CI email delivery are also protected. As a result, the completed-run
limit is not a strict cap on all stored rows. Deployment history is independent
and is not pruned by the CI run limit.

### When cleanup happens

These limits apply across the repository, including older runs. Lower limits can
permanently delete data at the next cleanup, not necessarily when the run is
queued. Cleanup happens during normal operations such as run completion, artifact
reads/uploads, and server startup. There is no exact-time deletion timer.

The Artifacts page displays the current age-based expiration, or **Never expires**
when age expiration is zero. A nonzero count limit can still delete that archive.
To disable automatic artifact deletion, set **both artifact limits to zero**.

**Deletion is permanent.** Higher limits cannot restore removed data. Make backups
before lowering limits on important repositories. Unlimited retention can exhaust
disk space, so monitor database growth. Artifacts live in SQLite; deleting rows
may free reusable database pages without reducing the database file's physical size.

The server environment variable `PYGITHOST_CI_RETENTION` supplies the default run
limit. It accepts 0–10000, with 0 meaning unlimited. Project configuration allows
values up to 1000000, subject to administrator defaults where a field is omitted.

## Browse multiple pages

These lists default to **25 entries per page**:

- **Home → Repositories:** sorted by owner and repository name; search is preserved.
- **CI → Runs:** **All workflows** shows the newest runs first. Use the workflow
  sidebar to narrow the list to one pipeline, including pipelines with retained
  history. Expand **Filters** for more options; the selected workflow and active
  filters are preserved during pagination.
  Runs show the triggering commit's subject as their title, along with the
  workflow name. Pull request runs use the recorded head commit.
  Open a run to jump between its summary, job steps, combined log, and artifact
  ZIP if one was retained. **Configuration snapshot** links to the full committed file
  at the run's recorded configuration SHA, which may differ from its head SHA
  for pull requests. Runs without recorded provenance do not link to the
  current branch configuration.
  The Warnings filter supports all runs, only runs with warnings, or only runs
  without warnings. Click a Warning badge to inspect the recorded issue. Warnings
  do not change a successful run into a failure.
- **CI → Deployments:** newest attempt first, independent of retained CI history.
- **Artifacts:** newest run's archive first; age/count policies still apply.
- **Tokens** and **Admin → Users:** paginated management tables. The password-reset
  selector continues to include all users, not just the current page.
- **Pull requests:** pagination preserves the selected open/closed/merged/all filter.
- **Pull request → Commits:** 25 commits per page, without the former 200-commit cap.
- **Commit → Files:** the changed-file list is paginated; the patch remains a
  separate, bounded view of the commit.
- **Branches:** filters and sorting survive page changes; the default branch
  remains in its own section when it matches the filter.

Full **commit history** retains its existing 50-commit chunks and Load more button,
and also provides Previous/Next page links. The selected revision and path filter
are preserved. Commit-history page controls appear above and below the table,
near the Repo, Branches, and Pull requests navigation. Those navigation links
open their own separately paginated lists, starting on their first page.
Fixed-size documentation/reference tables are not paginated.
Repository Code pages and folder explorers show the full directory listing, folders
first, with last-commit information. Directories wider than 100 entries are paged
100 at a time (the `per_page` parameter accepts 10/25/50/100), and last-commit
metadata is resolved only for the visible page.

Each list uses the same pagination controls:

- **First / Last:** jump directly to the beginning or end of the list.
- **Previous / Next:** move one page at a time.
- **Numbered pages:** select a nearby page; ellipses mark omitted page ranges.
- **Result summary:** shows the displayed range, total matches, and current/total pages.

Unavailable controls remain visible but disabled at list boundaries. Out-of-range
page requests are clamped to the final page. Page size, filters, sorting, revision,
and path are preserved in navigation links. Commit history defaults to 50 entries;
its Load more button remains available. There are no page-size or jump-to-page forms.
If a Git count cannot be obtained, commit lists omit the unknown total and Last
control rather than guessing where the list ends.

Submitting a new search/filter starts at page 1. Pages are live rather than frozen snapshots: new entries or
cleanup can shift results between page visits. Refresh deployment pages to update
running attempts and delivery status; CI run lists continue polling on their
selected page.

Pagination changes only the display. It does not delete records or change retention.
Skipped deployments do not appear because no deployment attempt was recorded.
