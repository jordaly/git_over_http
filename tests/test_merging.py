"""Tests for pygithost.merging (bare-repository merge plumbing)."""

import os
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from unittest import mock

from pygithost import merging
from pygithost.merging import Identity, MergeError

ALICE = Identity("Alice", "alice@example.com")
BOB = Identity("Bob", "bob@example.com")
MERGER = Identity("Merger", "merger@example.com")


def _env(identity: Identity = ALICE, date: str | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME=identity.name,
        GIT_AUTHOR_EMAIL=identity.email,
        GIT_COMMITTER_NAME=identity.name,
        GIT_COMMITTER_EMAIL=identity.email,
    )
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    return env


class RepoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pygithost-merging-test-")
        self.repo = os.path.join(self._tmp.name, "repo.git")
        subprocess.run(
            ["git", "init", "-q", "--bare", "-b", "main", self.repo], check=True, env=_env()
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def git(
        self, *args: str, data: bytes | None = None, env: Mapping[str, str] | None = None
    ) -> str:
        result = subprocess.run(
            ["git", "--git-dir=" + self.repo, *args],
            input=data,
            capture_output=True,
            env=dict(env) if env is not None else _env(),
            check=True,
        )
        return result.stdout.decode()

    def commit(
        self,
        branch: str,
        files: Mapping[str, bytes | str | None],
        message: str = "change",
        *,
        author: Identity = ALICE,
        parents: list[str] | None = None,
        date: str | None = None,
        modes: Mapping[str, str] | None = None,
    ) -> str:
        """Commit file changes (None deletes) on top of ``branch`` and move it."""
        tip = self.tip(branch)
        if parents is None:
            parents = [tip] if tip else []
        env = _env(author, date)
        with tempfile.TemporaryDirectory() as directory:
            env["GIT_INDEX_FILE"] = os.path.join(directory, "index")
            if parents:
                self.git("read-tree", parents[0], env=env)
            for name, content in files.items():
                if content is None:
                    record = "0 " + "0" * 40 + "\t" + name
                else:
                    raw = content.encode() if isinstance(content, str) else content
                    oid = self.git("hash-object", "-w", "--stdin", data=raw).strip()
                    mode = (modes or {}).get(name, "100644")
                    record = f"{mode} {oid}\t{name}"
                self.git(
                    "update-index", "-z", "--index-info", data=record.encode() + b"\0", env=env
                )
            tree = self.git("write-tree", env=env).strip()
        args = ["commit-tree", tree]
        for parent in parents:
            args += ["-p", parent]
        sha = self.git(*args, data=message.encode() + b"\n", env=env).strip()
        self.git("update-ref", "refs/heads/" + branch, sha)
        return sha

    def tip(self, branch: str) -> str | None:
        result = subprocess.run(
            [
                "git",
                "--git-dir=" + self.repo,
                "rev-parse",
                "--verify",
                "--quiet",
                "refs/heads/" + branch,
            ],
            capture_output=True,
            env=_env(),
        )
        return result.stdout.decode().strip() or None

    def branch(self, name: str, start: str) -> str:
        sha = self.tip(start)
        assert sha
        self.git("update-ref", "refs/heads/" + name, sha)
        return sha

    def parents(self, sha: str) -> list[str]:
        return self.git("rev-list", "--parents", "-n1", sha).split()[1:]

    def fmt(self, sha: str, spec: str) -> str:
        return self.git("log", "-1", "--format=" + spec, sha)

    def show(self, sha: str, path: str) -> bytes:
        return subprocess.run(
            ["git", "--git-dir=" + self.repo, "cat-file", "blob", f"{sha}:{path}"],
            capture_output=True,
            env=_env(),
            check=True,
        ).stdout

    def diverge(self) -> tuple[str, str]:
        """main and feature with independent, non-conflicting changes."""
        self.commit("main", {"a.txt": "a\n", "b.txt": "b\n"}, "base")
        self.branch("feature", "main")
        self.commit("feature", {"f1.txt": "1\n"}, "feat one", author=BOB, date="1700000000 +0200")
        self.commit("feature", {"f2.txt": "2\n"}, "feat two\n\nbody line", author=ALICE)
        self.commit("main", {"m.txt": "m\n"}, "main work")
        tgt, src = self.tip("main"), self.tip("feature")
        assert tgt and src
        return tgt, src

    def conflicting(self) -> tuple[str, str]:
        self.commit("main", {"a.txt": "base\n"}, "base")
        self.branch("feature", "main")
        self.commit("feature", {"a.txt": "feature\n"}, "feature edit")
        self.commit("main", {"a.txt": "main\n"}, "main edit")
        tgt, src = self.tip("main"), self.tip("feature")
        assert tgt and src
        return tgt, src

    def merge(self, method: merging.MergeMethod, tgt: str, src: str, **kw: object) -> str:
        return merging.merge_pull(
            self.repo,
            target_branch="main",
            source_branch="feature",
            expected_target=tgt,
            expected_source=src,
            method=method,
            committer=MERGER,
            title="Merge PR #1",
            **kw,  # type: ignore[arg-type]
        )


class MergeMethodTests(RepoTestCase):
    def test_merge_commit(self) -> None:
        tgt, src = self.diverge()
        new = self.merge("merge", tgt, src, message="Details")
        self.assertEqual(self.tip("main"), new)
        self.assertEqual(self.parents(new), [tgt, src])
        self.assertEqual(
            self.fmt(new, "%an|%ae|%cn|%ce"),
            "Merger|merger@example.com|Merger|merger@example.com\n",
        )
        self.assertEqual(self.fmt(new, "%B"), "Merge PR #1\n\nDetails\n\n")
        names = self.git("ls-tree", "--name-only", new).split()
        self.assertEqual(sorted(names), ["a.txt", "b.txt", "f1.txt", "f2.txt", "m.txt"])
        self.assertEqual(self.tip("feature"), src)

    def test_squash(self) -> None:
        tgt, src = self.diverge()
        new = self.merge("squash", tgt, src, squash_author=BOB)
        self.assertEqual(self.parents(new), [tgt])
        self.assertEqual(self.fmt(new, "%an|%cn|%s"), "Bob|Merger|Merge PR #1\n")
        names = self.git("ls-tree", "--name-only", new).split()
        self.assertIn("f2.txt", names)
        self.assertIn("m.txt", names)

    def test_squash_defaults_author_to_committer(self) -> None:
        tgt, src = self.diverge()
        new = self.merge("squash", tgt, src)
        self.assertEqual(self.fmt(new, "%an|%cn"), "Merger|Merger\n")

    def test_rebase_preserves_authors_messages_and_order(self) -> None:
        tgt, src = self.diverge()
        originals = self.git("rev-list", "--reverse", f"{tgt}..{src}").split()
        new = self.merge("rebase", tgt, src)
        replayed = self.git("rev-list", "--reverse", f"{tgt}..{new}").split()
        self.assertEqual(len(replayed), 2)
        self.assertEqual(self.parents(replayed[0]), [tgt])
        for old, rebased in zip(originals, replayed, strict=True):
            self.assertNotEqual(old, rebased)
            self.assertEqual(self.fmt(old, "%an|%ae|%ad|%B"), self.fmt(rebased, "%an|%ae|%ad|%B"))
            self.assertEqual(self.fmt(rebased, "%cn|%ce"), "Merger|merger@example.com\n")
        self.assertEqual(
            self.fmt(replayed[0], "%an|%at|%ai"), "Bob|1700000000|2023-11-15 00:13:20 +0200\n"
        )
        self.assertEqual(self.fmt(replayed[1], "%B"), "feat two\n\nbody line\n\n")
        self.assertEqual(self.tip("main"), new)

    def test_rebase_skips_commits_that_become_empty(self) -> None:
        self.commit("main", {"a.txt": "a\n"}, "base")
        self.branch("feature", "main")
        self.commit("feature", {"x.txt": "x\n"}, "already upstream")
        self.commit("feature", {"y.txt": "y\n"}, "new work")
        self.commit("main", {"x.txt": "x\n"}, "cherry-picked upstream")
        tgt, src = self.tip("main"), self.tip("feature")
        assert tgt and src
        new = self.merge("rebase", tgt, src)
        replayed = self.git("rev-list", f"{tgt}..{new}").split()
        self.assertEqual(len(replayed), 1)
        self.assertEqual(self.fmt(new, "%s"), "new work\n")

    def test_rebase_rejects_merge_commits(self) -> None:
        tgt, src = self.diverge()
        self.branch("side", "feature")
        self.commit("side", {"s.txt": "s\n"}, "side")
        side = self.tip("side")
        assert side
        merged = self.commit("feature", {"s.txt": "s\n"}, "merge side", parents=[src, side])
        with self.assertRaises(MergeError) as ctx:
            self.merge("rebase", tgt, merged)
        self.assertEqual(ctx.exception.code, "unsupported")
        self.assertIn("merge commits", ctx.exception.message)
        self.assertEqual(self.tip("main"), tgt)

    def test_fast_forward(self) -> None:
        self.commit("main", {"a.txt": "a\n"}, "base")
        tgt = self.branch("feature", "main")
        src = self.commit("feature", {"b.txt": "b\n"}, "more")
        self.assertEqual(self.merge("ff", tgt, src), src)
        self.assertEqual(self.tip("main"), src)

    def test_fast_forward_refused_when_diverged(self) -> None:
        tgt, src = self.diverge()
        with self.assertRaises(MergeError) as ctx:
            self.merge("ff", tgt, src)
        self.assertEqual(ctx.exception.code, "unsupported")
        self.assertEqual(self.tip("main"), tgt)


class ConflictTests(RepoTestCase):
    def test_merge_squash_rebase_conflicts(self) -> None:
        tgt, src = self.conflicting()
        for method in ("merge", "squash", "rebase"):
            with self.subTest(method=method), self.assertRaises(MergeError) as ctx:
                self.merge(method, tgt, src)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "conflict")
            self.assertEqual(ctx.exception.conflicts, ["a.txt"])
        self.assertEqual(self.tip("main"), tgt)

    def test_update_branch_conflict(self) -> None:
        tgt, src = self.conflicting()
        with self.assertRaises(MergeError) as ctx:
            merging.update_branch(
                self.repo,
                head_branch="feature",
                base_branch="main",
                expected_head=src,
                expected_base=tgt,
                committer=MERGER,
                message="Merge main into feature",
            )
        self.assertEqual(ctx.exception.code, "conflict")
        self.assertEqual(ctx.exception.conflicts, ["a.txt"])

    def test_merge_tree_and_mergeability(self) -> None:
        tgt, src = self.conflicting()
        self.assertEqual(merging.merge_tree(self.repo, tgt, src), (None, ["a.txt"]))
        info = merging.mergeability(self.repo, "main", "feature")
        self.assertEqual(
            info,
            {
                "fast_forward": False,
                "clean": False,
                "conflicts": ["a.txt"],
                "up_to_date": False,
                "rebase_clean": False,
            },
        )

    def test_mergeability_clean(self) -> None:
        tgt, src = self.diverge()
        info = merging.mergeability(self.repo, tgt, src)
        self.assertTrue(info["clean"])
        self.assertTrue(info["rebase_clean"])
        self.assertFalse(info["fast_forward"])
        tree, conflicts = merging.merge_tree(self.repo, tgt, src)
        self.assertIsNotNone(tree)
        self.assertEqual(conflicts, [])
        self.assertEqual(merging.mergeability(self.repo, src, src)["up_to_date"], True)
        with self.assertRaises(MergeError) as ctx:
            merging.mergeability(self.repo, "main", "missing")
        self.assertEqual(ctx.exception.code, "not_found")


class StaleAndStateTests(RepoTestCase):
    def test_expected_sha_mismatch(self) -> None:
        tgt, src = self.diverge()
        with self.assertRaises(MergeError) as ctx:
            self.merge("merge", tgt, tgt)
        self.assertEqual(ctx.exception.code, "stale")
        with self.assertRaises(MergeError) as ctx:
            self.merge("merge", src, src)
        self.assertEqual(ctx.exception.code, "stale")

    def test_concurrent_source_change_detected(self) -> None:
        tgt, src = self.diverge()
        original = merging.merge_tree

        def racing(*args: object, **kwargs: object) -> tuple[str | None, list[str]]:
            self.commit("feature", {"late.txt": "late\n"}, "pushed meanwhile")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(merging, "merge_tree", side_effect=racing):
            with self.assertRaises(MergeError) as ctx:
                self.merge("merge", tgt, src)
        self.assertEqual(ctx.exception.code, "stale")
        self.assertEqual(self.tip("main"), tgt)

    def test_concurrent_target_change_detected(self) -> None:
        tgt, src = self.diverge()
        original = merging.merge_tree

        def racing(*args: object, **kwargs: object) -> tuple[str | None, list[str]]:
            self.commit("main", {"late.txt": "late\n"}, "pushed meanwhile")
            return original(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(merging, "merge_tree", side_effect=racing):
            with self.assertRaises(MergeError) as ctx:
                self.merge("squash", tgt, src)
        self.assertEqual(ctx.exception.code, "stale")
        self.assertNotEqual(self.tip("main"), tgt)

    def test_up_to_date(self) -> None:
        self.commit("main", {"a.txt": "a\n"}, "base")
        src = self.branch("feature", "main")
        tgt = self.commit("main", {"b.txt": "b\n"}, "ahead")
        for method in ("merge", "squash", "rebase", "ff"):
            with self.subTest(method=method), self.assertRaises(MergeError) as ctx:
                self.merge(method, tgt, src)  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "up_to_date")

    def test_missing_branch(self) -> None:
        self.commit("main", {"a.txt": "a\n"}, "base")
        sha = self.tip("main")
        assert sha
        with self.assertRaises(MergeError) as ctx:
            self.merge("merge", sha, sha)
        self.assertEqual(ctx.exception.code, "not_found")

    def test_resolve_and_merge_base(self) -> None:
        tgt, src = self.diverge()
        self.assertEqual(merging.resolve(self.repo, "main"), tgt)
        self.assertEqual(merging.resolve(self.repo, "refs/heads/feature"), src)
        self.assertEqual(merging.resolve(self.repo, src), src)
        self.assertIsNone(merging.resolve(self.repo, "nope"))
        self.assertIsNone(merging.resolve(self.repo, "0" * 40))
        base = merging.merge_base(self.repo, tgt, src)
        self.assertEqual(base, self.parents(self.parents(src)[0])[0])
        self.assertEqual(len(merging.commits_to_replay(self.repo, tgt, src)), 2)


class UpdateBranchTests(RepoTestCase):
    def test_update_branch_merges_base_into_head(self) -> None:
        tgt, src = self.diverge()
        new = merging.update_branch(
            self.repo,
            head_branch="feature",
            base_branch="main",
            expected_head=src,
            expected_base=tgt,
            committer=MERGER,
            message="Merge branch 'main' into feature",
        )
        self.assertEqual(self.tip("feature"), new)
        self.assertEqual(self.tip("main"), tgt)
        self.assertEqual(self.parents(new), [src, tgt])
        self.assertEqual(
            self.fmt(new, "%s|%an|%cn"), "Merge branch 'main' into feature|Merger|Merger\n"
        )

    def test_update_branch_up_to_date(self) -> None:
        self.commit("main", {"a.txt": "a\n"}, "base")
        tgt = self.branch("feature", "main")
        src = self.commit("feature", {"b.txt": "b\n"}, "ahead")
        with self.assertRaises(MergeError) as ctx:
            merging.update_branch(
                self.repo,
                head_branch="feature",
                base_branch="main",
                expected_head=src,
                expected_base=tgt,
                committer=MERGER,
                message="Update",
            )
        self.assertEqual(ctx.exception.code, "up_to_date")


class ReplaceLinesTests(RepoTestCase):
    def replace(
        self,
        path: str,
        start: int,
        end: int,
        expected: list[str],
        text: str,
        head: str | None = None,
    ) -> str:
        return merging.replace_lines(
            self.repo,
            branch="main",
            expected_head=head or self.tip("main") or "",
            path=path,
            start_line=start,
            end_line=end,
            expected_lines=expected,
            new_text=text,
            message="Apply suggestion",
            author=BOB,
        )

    def test_single_line(self) -> None:
        head = self.commit("main", {"f.txt": "one\ntwo\nthree\n"})
        new = self.replace("f.txt", 2, 2, ["two"], "TWO")
        self.assertEqual(self.show(new, "f.txt"), b"one\nTWO\nthree\n")
        self.assertEqual(self.parents(new), [head])
        self.assertEqual(self.tip("main"), new)
        self.assertEqual(self.fmt(new, "%an|%cn|%s"), "Bob|Bob|Apply suggestion\n")

    def test_range_delete_and_insert(self) -> None:
        self.commit("main", {"f.txt": "1\n2\n3\n4\n5\n"})
        new = self.replace("f.txt", 2, 4, ["2", "3", "4"], "x")
        self.assertEqual(self.show(new, "f.txt"), b"1\nx\n5\n")
        new = self.replace("f.txt", 2, 2, ["x"], "")
        self.assertEqual(self.show(new, "f.txt"), b"1\n5\n")
        new = self.replace("f.txt", 1, 1, ["1"], "a\nb\nc\n")
        self.assertEqual(self.show(new, "f.txt"), b"a\nb\nc\n5\n")

    def test_nested_directory_and_mode(self) -> None:
        self.commit(
            "main",
            {"src/pkg/run.sh": "#!/bin/sh\necho hi\n", "src/other.txt": "o\n"},
            modes={"src/pkg/run.sh": "100755"},
        )
        new = self.replace("src/pkg/run.sh", 2, 2, ["echo hi"], "echo bye")
        self.assertEqual(self.show(new, "src/pkg/run.sh"), b"#!/bin/sh\necho bye\n")
        self.assertIn("100755", self.git("ls-tree", "-r", new, "--", "src/pkg/run.sh"))
        self.assertEqual(self.show(new, "src/other.txt"), b"o\n")

    def test_crlf_preserved(self) -> None:
        self.commit("main", {"w.txt": b"a\r\nb\r\nc\r\n"})
        self.assertEqual(
            merging.file_lines(self.repo, self.tip("main") or "", "w.txt"), ["a", "b", "c"]
        )
        new = self.replace("w.txt", 2, 2, ["b"], "x\ny")
        self.assertEqual(self.show(new, "w.txt"), b"a\r\nx\r\ny\r\nc\r\n")

    def test_no_trailing_newline_preserved(self) -> None:
        self.commit("main", {"n.txt": "a\nb"})
        new = self.replace("n.txt", 2, 2, ["b"], "c\nd")
        self.assertEqual(self.show(new, "n.txt"), b"a\nc\nd")
        new = self.replace("n.txt", 3, 3, ["d"], "")
        self.assertEqual(self.show(new, "n.txt"), b"a\nc")

    def test_stale_lines_rejected(self) -> None:
        head = self.commit("main", {"f.txt": "one\ntwo\n"})
        with self.assertRaises(MergeError) as ctx:
            self.replace("f.txt", 2, 2, ["changed"], "x")
        self.assertEqual(ctx.exception.code, "stale")
        with self.assertRaises(MergeError) as ctx:
            self.replace("f.txt", 2, 3, ["two", "three"], "x")
        self.assertEqual(ctx.exception.code, "stale")
        self.commit("main", {"g.txt": "g\n"})
        with self.assertRaises(MergeError) as ctx:
            self.replace("f.txt", 2, 2, ["two"], "x", head=head)
        self.assertEqual(ctx.exception.code, "stale")
        with self.assertRaises(MergeError) as ctx:
            self.replace("missing.txt", 1, 1, ["x"], "y")
        self.assertEqual(ctx.exception.code, "stale")


class LineMappingTests(RepoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.old = self.commit("main", {"f.txt": "".join(f"{i}\n" for i in range(1, 11))})

    def test_identical(self) -> None:
        self.assertEqual(merging.map_line(self.repo, self.old, self.old, "f.txt", 4), 4)
        self.assertFalse(merging.path_changed(self.repo, self.old, self.old, "f.txt"))

    def test_insertion_shifts_lines_below(self) -> None:
        lines = [f"{i}\n" for i in range(1, 11)]
        lines[4:4] = ["new a\n", "new b\n"]  # Insert after line 4.
        new = self.commit("main", {"f.txt": "".join(lines)})
        self.assertTrue(merging.path_changed(self.repo, self.old, new, "f.txt"))
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 4), 4)
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 5), 7)
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 10), 12)

    def test_deletion_and_modification(self) -> None:
        lines = [f"{i}\n" for i in range(1, 11)]
        del lines[1:3]  # Remove lines 2-3.
        lines[5] = "eight changed\n"  # Original line 8.
        new = self.commit("main", {"f.txt": "".join(lines)})
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 1), 1)
        self.assertIsNone(merging.map_line(self.repo, self.old, new, "f.txt", 2))
        self.assertIsNone(merging.map_line(self.repo, self.old, new, "f.txt", 3))
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 4), 2)
        self.assertIsNone(merging.map_line(self.repo, self.old, new, "f.txt", 8))
        self.assertEqual(merging.map_line(self.repo, self.old, new, "f.txt", 9), 7)

    def test_deleted_file(self) -> None:
        new = self.commit("main", {"f.txt": None, "g.txt": "g\n"})
        self.assertIsNone(merging.map_line(self.repo, self.old, new, "f.txt", 1))
        self.assertIsNone(merging.blob_id(self.repo, new, "f.txt"))
        self.assertIsNotNone(merging.blob_id(self.repo, self.old, "f.txt"))

    def test_file_lines(self) -> None:
        new = self.commit("main", {"bin.dat": b"\x00\x01\x02", "d/x.txt": "x\n"})
        self.assertIsNone(merging.file_lines(self.repo, new, "bin.dat"))
        self.assertIsNone(merging.file_lines(self.repo, new, "missing"))
        self.assertIsNone(merging.file_lines(self.repo, new, "d"))
        self.assertEqual(merging.file_lines(self.repo, new, "d/x.txt"), ["x"])


class ValidationTests(RepoTestCase):
    def test_invalid_refs_and_paths(self) -> None:
        tgt, src = self.diverge()
        for bad in ("-main", "--upload-pack=x", "a..b", "@{-1}", "bad name", ""):
            with self.subTest(branch=bad), self.assertRaises(MergeError) as ctx:
                merging.merge_pull(
                    self.repo,
                    target_branch=bad,
                    source_branch="feature",
                    expected_target=tgt,
                    expected_source=src,
                    method="merge",
                    committer=MERGER,
                    title="x",
                )
            self.assertEqual(ctx.exception.code, "invalid")
        with self.assertRaises(MergeError) as ctx:
            merging.resolve(self.repo, "-HEAD")
        self.assertEqual(ctx.exception.code, "invalid")
        with self.assertRaises(MergeError) as ctx:
            self.merge("merge", "not-a-sha", src)
        self.assertEqual(ctx.exception.code, "invalid")
        for bad_path in (
            "../etc/passwd",
            "/abs",
            "a\\b",
            "a/../b",
            ".git/config",
            "a\0b",
            "x/.GIT/y",
        ):
            with self.subTest(path=bad_path), self.assertRaises(MergeError) as ctx:
                merging.file_lines(self.repo, tgt, bad_path)
            self.assertEqual(ctx.exception.code, "invalid")
        with self.assertRaises(MergeError) as ctx:
            merging.map_line(self.repo, tgt, src, "../x", 1)
        self.assertEqual(ctx.exception.code, "invalid")
        with self.assertRaises(MergeError) as ctx:
            merging.merge_pull(
                self.repo,
                target_branch="main",
                source_branch="feature",
                expected_target=tgt,
                expected_source=src,
                method="merge",
                committer=Identity("Evil <x>", "e@x"),
                title="x",
            )
        self.assertEqual(ctx.exception.code, "invalid")
        self.assertEqual(self.tip("main"), tgt)

    def test_identity_for(self) -> None:
        identity = merging.identity_for("jane <doe>")
        self.assertNotIn("<", identity.name)
        self.assertTrue(identity.email.endswith("@users.pygithost.local"))
        self.assertEqual(merging.identity_for(None).name, "Browser user")


if __name__ == "__main__":
    unittest.main()
