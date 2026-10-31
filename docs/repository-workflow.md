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

## Permalinks

**Permalink** points at the file in a specific commit. It keeps showing that exact
version after a branch advances. Use it for stable references; choose an actual
branch to edit and commit changes.
