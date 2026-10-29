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

These lists show **25 entries per page**:

- **Home → Repositories:** sorted by owner and repository name; search is preserved.
- **CI → Runs:** newest run first; status, event, branch, and text filters are preserved.
- **CI → Deployments:** newest attempt first, independent of retained CI history.

Use **Previous** and **Next** under each list. The current page number is displayed;
Next disappears when there are no more results. Submitting a new search/filter
starts at page 1. Pages are live rather than frozen snapshots: new entries or
cleanup can shift results between page visits. Refresh deployment pages to update
running attempts and delivery status; CI run lists continue polling on their
selected page.

Pagination changes only the display. It does not delete records or change retention.
Skipped deployments do not appear because no deployment attempt was recorded.
