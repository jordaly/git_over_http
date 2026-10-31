"""Bounded, worktree-free Git operations for the browser editor."""

import os
import re
import subprocess
import tempfile
import threading

MAX_FILE = 1024 * 1024
MAX_REQUEST = 5 * MAX_FILE


class IDEError(ValueError):
    pass


def git(repo, *args, data=None, env=None):
    result = subprocess.run(["git", "--git-dir=" + repo, *args], input=data,
                            capture_output=True, env=env, timeout=30)
    if result.returncode:
        raise IDEError("Git operation failed: " + result.stderr.decode("utf-8", "replace")[:500])
    return result.stdout


def path(value):
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096
            or any(ord(c) < 32 for c in value) or "\\" in value
            or any(p in ("", ".", "..") or p.lower() == ".git" for p in value.split("/"))):
        raise IDEError("Invalid repository file path.")
    return value


def head(repo, branch):
    if not isinstance(branch, str) or not branch or branch.startswith("-"):
        raise IDEError("Choose an existing branch.")
    git(repo, "check-ref-format", "refs/heads/" + branch)
    return git(repo, "rev-parse", "--verify", "refs/heads/" + branch).decode().strip()


def tree(repo, commit):
    entries = {}
    for record in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        try:
            name = name.decode("utf-8")
        except UnicodeDecodeError:
            continue
        entries[name] = {"path": name, "mode": mode, "type": kind, "oid": oid}
        if len(entries) > 10000:
            raise IDEError("This repository exceeds the editor's 10,000-file limit.")
    return entries


def snapshot(repo, branch):
    commit = head(repo, branch)
    return {"branch": branch, "commit": commit, "files": list(tree(repo, commit).values())}


def read_file(repo, branch, commit, filename):
    path(filename)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or ""):
        raise IDEError("Invalid base commit.")
    # Only serve snapshots from this branch's history, not arbitrary objects.
    git(repo, "merge-base", "--is-ancestor", commit, head(repo, branch))
    entry = tree(repo, commit).get(filename)
    if not entry or entry["mode"] not in ("100644", "100755"):
        raise IDEError("Only regular text files can be edited (not symlinks or submodules).")
    if int(git(repo, "cat-file", "-s", entry["oid"])) > MAX_FILE:
        raise IDEError("Files larger than 1 MiB cannot be edited.")
    content = git(repo, "cat-file", "blob", entry["oid"])
    if b"\0" in content:
        raise IDEError("Binary files cannot be edited.")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IDEError("Only UTF-8 text files can be edited.") from exc


def search(repo, branch, commit, query):
    """Literal, case-insensitive search with bounded output and runtime."""
    if not isinstance(query, str) or not query.strip() or len(query) > 200 or any(c in query for c in "\0\r\n"):
        raise IDEError("Enter a single-line search term of 1–200 characters.")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise IDEError("Invalid base commit.")
    git(repo, "merge-base", "--is-ancestor", commit, head(repo, branch))
    entries = tree(repo, commit)
    limit = 256 * 1024
    timed_out = threading.Event()
    with subprocess.Popen(["git", "--git-dir=" + repo, "grep", "--no-textconv", "-z", "-n", "-I", "-F", "-i",
                           "-e", query, commit, "--"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        def expire():
            timed_out.set()
            try:
                proc.kill()
            except ProcessLookupError:
                pass

        timer = threading.Timer(10, expire)
        timer.daemon = True
        timer.start()
        try:
            output = proc.stdout.read(limit + 1)
            if len(output) > limit:
                proc.kill()
            proc.wait()
        finally:
            timer.cancel()
        truncated = len(output) > limit or timed_out.is_set()
        if proc.returncode not in (0, 1) and not truncated:
            raise IDEError("Repository search failed.")
    results = []
    remaining = output[:limit]
    while remaining:
        fields = remaining.split(b"\0", 2)
        if len(fields) != 3 or b"\n" not in fields[2]:
            break  # Ignore the final partial record when output was limited.
        raw_name, raw_line, rest = fields
        text, remaining = rest.split(b"\n", 1)
        try:
            filename = raw_name[len(commit) + 1:].decode("utf-8")
            path(filename)
            entry = entries.get(filename)
            if not entry or entry["mode"] not in ("100644", "100755"):
                continue
            result = {"path": filename, "line": int(raw_line), "text": text.decode("utf-8")[:300]}
        except (UnicodeError, ValueError):
            continue
        if len(results) == 200:
            truncated = True
            break
        results.append(result)
    return {"results": results, "truncated": truncated}


def commit_changes(repo, branch, base, changes, message, username):
    if head(repo, branch) != base:
        raise IDEError("The branch changed. Your edits are retained; reload before committing.")
    if not isinstance(message, str) or not message.strip() or len(message) > 4000 or "\0" in message:
        raise IDEError("Enter a commit message (up to 4,000 characters).")
    if not isinstance(changes, dict) or not 1 <= len(changes) <= 100:
        raise IDEError("Commit between 1 and 100 changed files.")
    # Never desynchronize a server-side checkout, including linked worktrees.
    worktrees = git(repo, "worktree", "list", "--porcelain").decode("utf-8", "replace")
    if "branch refs/heads/" + branch + "\n" in worktrees:
        raise IDEError("This branch is checked out on the server. Use a different branch.")
    entries = tree(repo, base)
    updates = []
    total = 0
    for filename, content in changes.items():
        path(filename)
        old = entries.get(filename)
        if old and old["mode"] not in ("100644", "100755"):
            raise IDEError("Symlinks and submodules cannot be changed in the editor.")
        if content is None:
            if not old:
                raise IDEError("Cannot delete a nonexistent file.")
            updates.append((filename, None, None))
            continue
        if not isinstance(content, str) or "\0" in content:
            raise IDEError("Only UTF-8 text content is supported.")
        encoded = content.encode("utf-8")
        total += len(encoded)
        if len(encoded) > MAX_FILE or total > MAX_REQUEST:
            raise IDEError("Changes exceed the editor size limit.")
        if old:
            read_file(repo, branch, base, filename)
        oid = git(repo, "hash-object", "-w", "--stdin", data=encoded).decode().strip()
        updates.append((filename, old["mode"] if old else "100644", oid))
    with tempfile.TemporaryDirectory(prefix="pygithost-ide-") as directory:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = os.path.join(directory, "index")
        # Do not permit inherited identity to impersonate another user.
        name = re.sub(r"[<>\r\n\x00]", "", username or "Browser user")[:100] or "Browser user"
        email = re.sub(r"[^a-zA-Z0-9_.-]", "_", name) + "@users.pygithost.local"
        env.update(GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                   GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
        git(repo, "read-tree", base, env=env)
        for filename, mode, oid in updates:
            record = ((mode + " " + oid) if oid else "0 " + "0" * len(base)) + "\t" + filename
            git(repo, "update-index", "-z", "--index-info", data=record.encode() + b"\0", env=env)
        new_tree = git(repo, "write-tree", env=env).decode().strip()
        if new_tree == git(repo, "rev-parse", base + "^{tree}").decode().strip():
            raise IDEError("There are no changes to commit.")
        commit = git(repo, "commit-tree", new_tree, "-p", base,
                     data=(message.strip() + "\n").encode(), env=env).decode().strip()
        # Local receive-pack honors repository receive hooks/configuration. The
        # explicit lease protects against pushes outside the HTTP server too.
        # Objects already exist in this repository, so no checkout is necessary.
        git(repo, "push", "--no-verify", "--porcelain",
            "--force-with-lease=refs/heads/" + branch + ":" + base,
            "--", os.path.abspath(repo), commit + ":refs/heads/" + branch, env=env)
        return commit
