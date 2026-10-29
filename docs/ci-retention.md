# CI retention and pagination

## Configure retention in the website

Open a repository's **CI → Settings → Additional settings → Artifact and run
retention**. Administrator access is required when authentication is enabled.
Set the limits and click **Save CI settings**.

| Setting | Default | Zero means | Maximum |
| --- | --- | --- | --- |
| Artifact expiration, in days | 7 | Never expire by age | 36500 |
| Maximum artifact bundles | 0 | No count limit | 1000000 |
| Completed CI runs to retain | 100, or server default | Keep unlimited completed runs | 1000000 |

A **bundle** is the ZIP archive collected from one CI run, not an individual file
inside the ZIP. Existing per-run artifact limits (20 MiB and 1000 files) still
apply; unlimited retention does not remove those limits.

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

These are **current repository storage policies**, not per-run configuration
snapshots. Saving settings applies them to existing data immediately. Artifact
expiration is also enforced at startup, artifact reads/uploads, and run/configuration
pruning. There is no exact-time deletion timer.

The Artifacts page displays the current age-based expiration, or **Never expires**
when age expiration is zero. A nonzero count limit can still delete that archive.
To disable automatic artifact deletion, set **both artifact limits to zero**.

**Deletion is permanent.** Higher limits cannot restore removed data. Make backups
before lowering limits on important repositories. Unlimited retention can exhaust
disk space, so monitor database growth. Artifacts live in SQLite; deleting rows
may free reusable database pages without reducing the database file's physical size.

The server environment variable `PYGITHOST_CI_RETENTION` supplies the default run
limit for repositories without an explicit override. It accepts 0–10000, with 0
meaning unlimited. Repository settings allow values up to 1000000.

## Browse multiple pages

These lists default to **25 entries per page**:

- **Home → Repositories:** sorted by owner and repository name; search is preserved.
- **CI → Runs:** newest run first; status, event, branch, and text filters are preserved.
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
Repository Code pages and folder explorers are also not paginated: they show the
full directory listing, folders first, with last-commit information.

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
