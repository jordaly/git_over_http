# Browser editing and pull requests

[Operations](../README.md#repository-interface) · [CI reference](ci-options.md)

## Edit one file or open the Web IDE

From a branch's file view, choose **Edit → Edit single file** for focused Monaco
editing. **Preview changes** compares both syntax-highlighted versions; **Write**
returns to editing. Enter a message and **Commit changes**, or **Cancel** to leave.

For multiple files, choose **Edit → Open in Web IDE**, or **Code → Open in Web IDE**
from a repository, folder or pull request. Branch/file/folder context is preserved;
a PR opens its source branch. Expanding from the single-file editor preserves the
model, undo history and pending edits. Tags and commit permalinks are read-only.

## Explorer, Search and Source Control

- Explorer sorts folders before files at every level and displays folder/file icons.
- **New file** adds a pending file. **New folder** adds a `.gitkeep` placeholder
  because Git does not track empty directories. Commit or discard these like other changes.
- **Collapse all folders** closes the tree and clears the filename filter.
- **Go to file** / **Ctrl/⌘+P** searches filenames. The Explorer filter is filename-only.
- **Search** / **Ctrl/⌘+Shift+F** searches contents, including pending edits/new files
  and excluding pending deletions. Results open their matching line. It is a literal,
  case-insensitive search capped at 200 lines, 256 KiB of Git output and 10 seconds.
- **Source Control** / **Ctrl/⌘+Shift+G** lists added/modified/deleted files, opens
  highlighted diffs, and offers per-file or all-change discard actions.
- **Ctrl/⌘+Shift+E** opens Explorer. **Ctrl/⌘+S** keeps the current panel, file and
  focus; it does not commit. Use the explicit commit action when ready.

Closing a tab does not discard edits. Commits include all pending changes and keep
open tabs; committing while viewing a diff does not switch to another editor view.
Edits are tab-local, not persistent drafts. Leaving/reloading warns about pending work.
Copy your work before reloading after a branch conflict; there is no automatic rebase.

This is a local-Monaco workbench, not full VS Code: no extensions, terminal or remote
development container. Only UTF-8 regular text files up to 1 MiB can be opened;
commits are capped at 100 changed files and 5 MiB content, with a 10 MiB encoded-form
limit. Repositories over 10,000 files, symlink/submodule editing, and commits to
server-side checked-out branches are not supported.

## Create a pull request

1. Create/select a source branch under **Branches**. Edit and commit your changes
   there; protected targets may reject direct commits.
2. Choose **New pull request** from the branch, or open **Pull requests** and fill in
   the title, optional description, source branch and target branch.
3. Submit. Both branches must exist and must be different; creating a PR requires
   write access. Without authentication, the IP allowlist controls access.
4. Review the diff and any CI checks. Required CI must pass for the exact current
   source/target commits before merging. Source or target updates can trigger fresh checks.

Signed-in PRs record the actual author. With authentication disabled, the author is
empty (`NULL`); no dummy user account is needed. Older databases may still enforce
`NOT NULL` on the author column even after application code is updated. Back up
the database, then restart the updated server: startup automatically migrates that
legacy constraint while preserving PR records, IDs, references, indexes and triggers.
This addresses both the old anonymous-author `FOREIGN KEY constraint failed` bug
and `NOT NULL constraint failed: pull_requests.author_user_id` on legacy schemas.
Do not disable foreign-key checks or create user ID `0` as a workaround.

## PR discussion, editing and merge readiness

Open PRs support a **Discussion** panel: comments are listed in order with author
and time, and write-authorized users can add comments (up to 50,000 characters).
Comment authors and administrators can delete comments; with authentication
disabled, the IP-allowlist trust model also allows moderation. Open PRs also
offer an inline **Edit title and description** form.

The PR page shows a **Changed files** table with per-file added/deleted counts and
added/deleted/modified badges (A/D/M). Selecting a file highlights it and filters
the diff section to that file; **All files** restores the full diff. Diffs are
computed from the **merge base**, so unrelated target-branch changes do not appear.
The pull-request list shows Open/Merged/Closed/All tabs with counts, comment
counts, colored status markers and relative creation times with exact-date
tooltips. **+ New pull request** opens a dedicated creation page
(`pulls/new`) with branch prefill support; the list page itself is not cluttered
with the form. When the target branch has advanced past the merge base,
the merge panel reports a simulated merge: a conflict warning appears before you
attempt the ff-only merge, or a note that a clean fast-forward is still possible.

## Resolving conflicts in the web UI

The **Resolve conflicts in the web IDE** link in the conflict warning opens the
Web IDE in resolve mode directly (see below). The simpler form-based resolver
remains at `pulls/<id>/resolve` as a fallback; it simulates the three-way merge
and lists every conflicted file
with a textarea containing Git conflict markers (`<<<<<<< HEAD (source branch)`,
`=======`, `>>>>>>> target (branch)`):

- Edit the marked sections to the exact content the file should have, then
  **Apply resolution**. The file is deleted instead when *Delete this file* is
  checked (pre-checked when the target deleted the file).
- Files that are binary, too large or otherwise not text-mergeable show the
  source content with a note instead of markers.
- **Open in Web IDE** switches to the same editor as the browser IDE in resolve
  mode: the conflicted files are preloaded with markers, the branch is locked to
  the source branch, and *Apply resolution* commits the same merge commit.
- Applying creates a **merge commit on the source branch** (parents: source
  commit, target commit) so the source now contains the target, the activity
  feed records the resolution, a `pull_request` CI run is queued, and the
  normally ff-only merge becomes available.
- The ref update is a compare-and-swap against the commit you started from: if
  the source branch advanced while you were editing, applying fails with a
  "reload and resolve again" message and the branch is left unchanged.
- Limits: 1 MiB per resolution, at most 40 conflicted files can be presented;
  more than that must be resolved with Git and pushed. Resolutions must cover
  every conflicted file before a commit is created.

## Permalinks

**Permalink** points at the file in a specific commit. It keeps showing that exact
version after a branch advances. Use it for stable references; choose an actual
branch to edit and commit changes.
