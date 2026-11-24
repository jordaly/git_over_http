"""Conformance suite for every Git Smart HTTP backend implementation.

Two layers, both driven by ``tests.git_http_backends.BACKENDS``:

* ``WireConformanceTests`` sends a matrix of raw HTTP requests to the server once
  per backend, checks each response against an expected status, and compares
  every backend with the reference ``git-http-backend`` byte for byte.
* ``ClientBehavior_<backend>`` classes run real git client workflows (clone,
  shallow/partial clone, fetch, push variants, auth scopes, concurrency,
  ``Expect: 100-continue``, disconnects) against each backend.
"""

from __future__ import annotations

import base64
import email.utils
import gzip
import http.client
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from pygithost import database
from pygithost.ci import validate_config
from pygithost.git_http_fallback import pkt_line
from tests.ci_fixtures import commit_legacy_config
from tests.git_http_backends import (
    BACKENDS,
    REFERENCE_BACKEND,
    bare_clone,
    build_project_root,
    git,
    git_env,
    isolate_git_config,
    make_source,
    restore_git_config,
)
from tests.test_server import ServerRunner, _which_git

FLUSH = b"0000"
DELIM = b"0001"
UPLOAD_REQ = "application/x-git-upload-pack-request"
RECEIVE_REQ = "application/x-git-receive-pack-request"
V2 = {"Git-Protocol": "version=2"}


@dataclass
class Scenario:
    name: str
    path: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    chunked: bool = False
    expect_status: int | tuple[int, ...] = 200
    expect_type: str | None = None
    # Error bodies are implementation-specific prose; only compare successes.
    compare_body: bool = True
    # Documented, intentional status difference from the reference backend.
    status_may_differ: bool = False
    # Response carries a side-band pack. git may build a byte-different but
    # equivalent pack for the same request, so packs compare by object set.
    pack_response: bool = False


def scenarios(facts: dict[str, str]) -> list[Scenario]:
    main, loose, pack = facts["main"], facts["loose"], facts["pack"]
    v0_want = (
        pkt_line(f"want {main} multi_ack_detailed side-band-64k ofs-delta no-progress\n")
        + FLUSH
        + pkt_line("done\n")
    )
    v2_fetch = (
        pkt_line("command=fetch\n")
        + DELIM
        + pkt_line("no-progress\n")
        + pkt_line("ofs-delta\n")
        + pkt_line(f"want {main}\n")
        + pkt_line("done\n")
        + FLUSH
    )
    v2_ls_refs = (
        pkt_line("command=ls-refs\n") + DELIM + pkt_line("peel\n") + pkt_line("symrefs\n") + FLUSH
    )
    adv = "application/x-git-upload-pack-advertisement"
    result = "application/x-git-upload-pack-result"
    return [
        # ---- smart HTTP: advertisements ----
        Scenario(
            "adv-upload-v0", "/git/repo.git/info/refs?service=git-upload-pack", expect_type=adv
        ),
        Scenario(
            "adv-upload-v1",
            "/git/repo.git/info/refs?service=git-upload-pack",
            headers={"Git-Protocol": "version=1"},
            expect_type=adv,
        ),
        Scenario(
            "adv-upload-v2",
            "/git/repo.git/info/refs?service=git-upload-pack",
            headers=V2,
            expect_type=adv,
        ),
        Scenario(
            "adv-receive",
            "/git/repo.git/info/refs?service=git-receive-pack",
            expect_type="application/x-git-receive-pack-advertisement",
        ),
        Scenario("adv-empty-repo", "/git/empty.git/info/refs?service=git-upload-pack"),
        Scenario("adv-extra-query", "/git/repo.git/info/refs?foo=bar&service=git-upload-pack"),
        Scenario(
            "adv-unknown-service",
            "/git/repo.git/info/refs?service=git-frobnicate",
            expect_status=403,
            compare_body=False,
        ),
        Scenario(
            "adv-receive-default-off",
            "/git/norecv.git/info/refs?service=git-receive-pack",
            expect_status=403,
            compare_body=False,
        ),
        Scenario(
            "adv-upload-disabled",
            "/git/noupload.git/info/refs?service=git-upload-pack",
            expect_status=403,
            compare_body=False,
        ),
        # ---- smart HTTP: RPC ----
        Scenario(
            "rpc-v0-fetch",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": UPLOAD_REQ},
            v0_want,
            pack_response=True,
            expect_type=result,
        ),
        Scenario(
            "rpc-v0-fetch-gzip",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": UPLOAD_REQ, "Content-Encoding": "gzip"},
            gzip.compress(v0_want, mtime=0),
            pack_response=True,
            expect_type=result,
        ),
        Scenario(
            "rpc-v2-ls-refs",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": UPLOAD_REQ, **V2},
            v2_ls_refs,
            expect_type=result,
        ),
        Scenario(
            "rpc-v2-fetch",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": UPLOAD_REQ, **V2},
            v2_fetch,
            pack_response=True,
            expect_type=result,
        ),
        Scenario(
            "rpc-v2-fetch-chunked",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": UPLOAD_REQ, **V2},
            v2_fetch,
            chunked=True,
            pack_response=True,
            expect_type=result,
        ),
        Scenario(
            "rpc-receive-noop",
            "/git/repo.git/git-receive-pack",
            "POST",
            {"Content-Type": RECEIVE_REQ},
            FLUSH,
            expect_type="application/x-git-receive-pack-result",
        ),
        Scenario(
            "rpc-wrong-content-type",
            "/git/repo.git/git-upload-pack",
            "POST",
            {"Content-Type": "application/octet-stream"},
            v0_want,
            expect_status=415,
            compare_body=False,
        ),
        Scenario(
            "rpc-get-not-allowed",
            "/git/repo.git/git-upload-pack",
            expect_status=405,
            compare_body=False,
        ),
        Scenario(
            "refs-post-not-allowed",
            "/git/repo.git/info/refs",
            "POST",
            {"Content-Type": UPLOAD_REQ},
            b"",
            expect_status=405,
            compare_body=False,
        ),
        # ---- dumb HTTP ----
        Scenario("dumb-head-file", "/git/repo.git/HEAD", expect_type="text/plain"),
        # The server itself answers HTTP HEAD on Git paths with 400, for every backend.
        Scenario(
            "http-head-method-rejected",
            "/git/repo.git/HEAD",
            "HEAD",
            expect_status=400,
            compare_body=False,
        ),
        Scenario("dumb-info-refs", "/git/repo.git/info/refs"),
        Scenario("dumb-info-packs", "/git/repo.git/objects/info/packs"),
        Scenario(
            "dumb-loose-object",
            f"/git/repo.git/objects/{loose[:2]}/{loose[2:]}",
            expect_type="application/x-git-loose-object",
        ),
        Scenario(
            "dumb-pack",
            f"/git/repo.git/objects/pack/{pack}",
            expect_type="application/x-git-packed-objects",
        ),
        Scenario(
            "dumb-idx",
            f"/git/repo.git/objects/pack/{pack[:-5]}.idx",
            expect_type="application/x-git-packed-objects-toc",
        ),
        Scenario(
            "dumb-missing-alternates",
            "/git/repo.git/objects/info/alternates",
            expect_status=404,
            compare_body=False,
        ),
        Scenario(
            "dumb-missing-object",
            "/git/repo.git/objects/00/" + "0" * 38,
            expect_status=404,
            compare_body=False,
        ),
        Scenario(
            "dumb-getanyfile-off",
            "/git/noany.git/HEAD",
            expect_status=403,
            compare_body=False,
        ),
        Scenario(
            "smart-ok-when-getanyfile-off",
            "/git/noany.git/info/refs?service=git-upload-pack",
        ),
        # ---- repository layouts and isolation ----
        Scenario("layout-owner-dotgit", "/git/team/proj.git/info/refs?service=git-upload-pack"),
        Scenario("layout-owner-plain", "/git/team/proj/info/refs?service=git-upload-pack"),
        Scenario("layout-flat-no-suffix", "/git/repo/info/refs?service=git-upload-pack"),
        Scenario("layout-non-bare", "/git/plain.git/info/refs?service=git-upload-pack"),
        Scenario(
            "missing-repo",
            "/git/missing.git/info/refs?service=git-upload-pack",
            expect_status=404,
            compare_body=False,
        ),
        Scenario(
            "config-not-served", "/git/repo.git/config", expect_status=404, compare_body=False
        ),
        # git-http-backend answers 500 here; the Python backend answers 404. Both refuse.
        Scenario(
            "traversal",
            "/git/repo.git/../../../etc/passwd",
            expect_status=(404, 500),
            compare_body=False,
            status_may_differ=True,
        ),
    ]


@dataclass
class Record:
    status: int
    headers: dict[str, str]
    body: bytes


IGNORED_HEADERS = {"date"}
EXPIRES_FORMAT = re.compile(r"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000$")


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace time-dependent cache headers with a checked placeholder."""
    expires = headers.get("expires")
    if expires and "1980" not in expires:
        assert EXPIRES_FORMAT.match(expires), expires
        stamp = email.utils.parsedate_to_datetime(expires).timestamp()
        assert abs(stamp - time.time() - 31536000) < 300, expires
        headers["expires"] = "<now + 1 year>"
    return headers


def split_sideband(body: bytes) -> tuple[list[bytes], bytes]:
    """Split a pkt-line response into protocol lines and side-band 1 pack data."""
    lines: list[bytes] = []
    pack = bytearray()
    pos = 0
    while pos + 4 <= len(body):
        size = int(body[pos : pos + 4], 16)
        if size < 4:
            lines.append(body[pos : pos + 4])
            pos += 4
            continue
        payload = body[pos + 4 : pos + size]
        pos += size
        if payload[:1] == b"\x01":
            pack.extend(payload[1:])
        else:
            lines.append(payload)
    assert pos == len(body), "trailing bytes after pkt-lines"
    return lines, bytes(pack)


def pack_object_ids(pack: bytes) -> list[str]:
    """Validate a pack with git index-pack and return its sorted object ids."""
    with tempfile.TemporaryDirectory(prefix="pack-check-") as tmp:
        pack_path = Path(tmp) / "check.pack"
        pack_path.write_bytes(pack)
        subprocess.run(["git", "index-pack", str(pack_path)], check=True, capture_output=True)
        with open(pack_path.with_suffix(".idx"), "rb") as idx:
            listing = subprocess.run(
                ["git", "show-index"], stdin=idx, check=True, capture_output=True, text=True
            ).stdout
    return sorted(line.split()[1] for line in listing.splitlines())


def normalize_pack_body(body: bytes) -> bytes:
    lines, pack = split_sideband(body)
    assert pack.startswith(b"PACK"), "no pack in response"
    objects = pack_object_ids(pack)
    return b"\n".join([*lines, b"PACK objects: " + ",".join(objects).encode()])


def send(port: int, scenario: Scenario) -> Record:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        if scenario.chunked:
            conn.putrequest(scenario.method, scenario.path)
            for name, value in scenario.headers.items():
                conn.putheader(name, value)
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            body = scenario.body or b""
            for start in range(0, len(body), 7):
                piece = body[start : start + 7]
                conn.send(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            conn.send(b"0\r\n\r\n")
        else:
            conn.request(
                scenario.method, scenario.path, body=scenario.body, headers=scenario.headers
            )
        response = conn.getresponse()
        body = response.read()
        headers = {
            name.lower(): value
            for name, value in response.getheaders()
            if name.lower() not in IGNORED_HEADERS
        }
        if scenario.pack_response and response.status == 200:
            body = normalize_pack_body(body)
        return Record(response.status, normalize_headers(headers), body)
    finally:
        conn.close()


def available_backends() -> dict[str, str]:
    return {name: path for name, path in BACKENDS.items() if path}


@unittest.skipUnless(_which_git(), "git not found in PATH")
class WireConformanceTests(unittest.TestCase):
    records: dict[str, dict[str, Record]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="git-conformance-"))
        root = cls.tmp / "root"
        root.mkdir()
        cls.facts = build_project_root(root)
        cls.matrix = scenarios(cls.facts)
        cls.records = {}
        for name, backend in available_backends().items():
            with ServerRunner(
                project_root=str(root), backend_path=backend, access_log=False
            ) as srv:
                cls.records[name] = {sc.name: send(srv.port, sc) for sc in cls.matrix}

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_each_backend_meets_expectations(self) -> None:
        for backend, records in self.records.items():
            for sc in self.matrix:
                with self.subTest(backend=backend, scenario=sc.name):
                    record = records[sc.name]
                    allowed = (
                        sc.expect_status
                        if isinstance(sc.expect_status, tuple)
                        else (sc.expect_status,)
                    )
                    self.assertIn(record.status, allowed, record.body[:300])
                    if sc.expect_type:
                        self.assertEqual(record.headers.get("content-type"), sc.expect_type)
                    if record.status == 200 and "advertisement" in record.headers.get(
                        "content-type", ""
                    ):
                        self.assertIn("no-cache", record.headers.get("cache-control", ""))

    def test_protocol_specific_content(self) -> None:
        main = self.facts["main"].encode()
        for backend, records in self.records.items():
            with self.subTest(backend=backend):
                self.assertTrue(
                    records["adv-upload-v0"].body.startswith(
                        pkt_line("# service=git-upload-pack\n") + FLUSH
                    )
                )
                self.assertNotIn(b"# service=", records["adv-upload-v2"].body)
                self.assertIn(b"version 2", records["adv-upload-v2"].body)
                self.assertIn(main + b" refs/heads/main", records["rpc-v2-ls-refs"].body)
                self.assertIn(b"symref-target:refs/heads/main", records["rpc-v2-ls-refs"].body)
                self.assertIn(b"peeled:", records["rpc-v2-ls-refs"].body)
                for name in ("rpc-v0-fetch", "rpc-v0-fetch-gzip", "rpc-v2-fetch"):
                    # Normalised to the validated object list: commits, trees, blobs and tags.
                    self.assertIn(b"PACK objects: ", records[name].body, name)
                    self.assertIn(main, records[name].body, name)
                self.assertEqual(records["rpc-v2-fetch"].body, records["rpc-v2-fetch-chunked"].body)
                self.assertEqual(records["dumb-head-file"].body, b"ref: refs/heads/main\n")
                self.assertIn(main + b"\trefs/heads/main\n", records["dumb-info-refs"].body)
                self.assertIn(b"refs/tags/v1.0^{}\n", records["dumb-info-refs"].body)
                self.assertEqual(
                    records["dumb-info-packs"].body,
                    f"P {self.facts['pack']}\n\n".encode(),
                )
                self.assertTrue(records["dumb-pack"].body.startswith(b"PACK"))
                self.assertEqual(
                    records["layout-owner-dotgit"].body, records["layout-owner-plain"].body
                )

    def test_backends_match_reference_on_the_wire(self) -> None:
        if REFERENCE_BACKEND not in self.records:
            self.skipTest("reference git-http-backend not installed")
        reference = self.records[REFERENCE_BACKEND]
        for backend, records in self.records.items():
            if backend == REFERENCE_BACKEND:
                continue
            for sc in self.matrix:
                with self.subTest(backend=backend, scenario=sc.name):
                    ours, theirs = records[sc.name], reference[sc.name]
                    if sc.status_may_differ:
                        self.assertGreaterEqual(ours.status, 400)
                        self.assertGreaterEqual(theirs.status, 400)
                        continue
                    self.assertEqual(ours.status, theirs.status)
                    if ours.status == 200:
                        self.assertEqual(ours.headers, theirs.headers)
                    if sc.compare_body and ours.status == 200:
                        self.assertEqual(ours.body, theirs.body)


class ClientBehaviorMixin:
    """Real git client workflows; subclasses set BACKEND."""

    BACKEND: str = ""
    assertEqual: object
    assertIn: object

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix=f"git-client-{self.BACKEND}-"))
        self.root = self.tmp / "root"
        self.root.mkdir()
        self.source = make_source(self.tmp / "source")
        self.bare = bare_clone(self.source, self.root / "repo.git", http_receivepack="true")
        git("--git-dir", self.bare, "config", "uploadpack.allowFilter", "true")
        self.env = git_env()
        self.backend_path = BACKENDS[self.BACKEND]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def server(self, **kwargs: object) -> ServerRunner:
        return ServerRunner(
            project_root=str(self.root), backend_path=self.backend_path, access_log=False, **kwargs
        )

    def url(self, srv: ServerRunner, repo: str = "repo.git", auth: str = "") -> str:
        return f"http://{auth}127.0.0.1:{srv.port}/git/{repo}"

    def clone(self, url: str, name: str, *args: str) -> Path:
        target = self.tmp / name
        git("clone", "-q", *args, url, target, env=self.env)
        return target

    def commit(self, work: Path, name: str, content: str | bytes = "x\n") -> str:
        path = work / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        git("-C", work, "add", name, env=self.env)
        git("-C", work, "commit", "-q", "-m", f"Add {name}", env=self.env)
        return git("-C", work, "rev-parse", "HEAD", env=self.env).strip()

    def push(
        self, work: Path, *refspecs: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(work), "push", "-q", "origin", *refspecs],
            env=self.env,
            capture_output=True,
            text=True,
            check=check,
            timeout=120,
        )

    def ref(self, name: str) -> str:
        """Object id of *name* in the server repository, or "" when it does not exist."""
        result = subprocess.run(
            ["git", "--git-dir", str(self.bare), "rev-parse", "--verify", "-q", name],
            capture_output=True,
            text=True,
            env=self.env,
        )
        return result.stdout.strip()

    def fsck(self) -> None:
        git("--git-dir", self.bare, "fsck", "--strict", "--no-progress")

    # ---------------- read paths ----------------
    def test_ls_remote_lists_heads_tags_and_peeled(self) -> None:
        with self.server() as srv:
            out = git("ls-remote", self.url(srv), env=self.env)
        self.assertIn("\tHEAD", out)
        self.assertIn("\trefs/heads/main", out)
        self.assertIn("\trefs/heads/feature", out)
        self.assertIn("\trefs/tags/v1.0^{}", out)
        self.assertIn("\trefs/tags/light", out)

    def test_clone_over_each_protocol_version(self) -> None:
        with self.server() as srv:
            for version in ("0", "1", "2"):
                work = self.clone(self.url(srv), f"v{version}", "-c", f"protocol.version={version}")
                self.assertEqual(git("-C", work, "rev-parse", "HEAD").strip(), self.ref("main"))
                self.assertEqual(git("-C", work, "tag").split(), ["light", "v1.0"])

    def test_shallow_clone_then_deepen(self) -> None:
        with self.server() as srv:
            work = self.clone(self.url(srv), "shallow", "--depth", "1")
            self.assertEqual(git("-C", work, "rev-list", "--count", "HEAD").strip(), "1")
            git("-C", work, "fetch", "-q", "--deepen", "1", env=self.env)
            self.assertEqual(git("-C", work, "rev-list", "--count", "HEAD").strip(), "2")
            git("-C", work, "fetch", "-q", "--unshallow", env=self.env)
            self.assertEqual(git("-C", work, "rev-list", "--count", "HEAD").strip(), "3")

    def test_partial_blobless_clone_fetches_blobs_on_demand(self) -> None:
        with self.server() as srv:
            work = self.clone(self.url(srv), "partial", "--filter=blob:none")
            self.assertEqual(git("-C", work, "config", "remote.origin.promisor").strip(), "true")
            self.assertEqual((work / "file2.txt").read_text(), "content 2\n" * 3)
            git("-C", work, "log", "-p", "-q", "--all", env=self.env)

    def test_fetch_picks_up_new_commits_and_tags(self) -> None:
        with self.server() as srv:
            reader = self.clone(self.url(srv), "reader")
            writer = self.clone(self.url(srv), "writer")
            head = self.commit(writer, "new.txt")
            git("-C", writer, "tag", "-a", "v2.0", "-m", "two", env=self.env)
            self.push(writer, "HEAD:main", "refs/tags/v2.0")
            git("-C", reader, "fetch", "-q", "--tags", env=self.env)
            self.assertEqual(git("-C", reader, "rev-parse", "origin/main").strip(), head)
            self.assertIn("v2.0", git("-C", reader, "tag"))
            # No-op fetch is quiet and succeeds.
            git("-C", reader, "fetch", "-q", env=self.env)

    def test_empty_repository_clone_and_first_push(self) -> None:
        git("init", "--bare", "-q", "-b", "main", self.root / "fresh.git")
        git("--git-dir", self.root / "fresh.git", "config", "http.receivepack", "true")
        with self.server() as srv:
            work = self.clone(self.url(srv, "fresh.git"), "fresh")
            head = self.commit(work, "first.txt")
            self.push(work, "HEAD:main")
        self.assertEqual(
            git("--git-dir", self.root / "fresh.git", "rev-parse", "main").strip(), head
        )

    def test_owner_and_non_bare_layouts(self) -> None:
        (self.root / "team").mkdir()
        bare_clone(self.source, self.root / "team" / "proj.git")
        git("clone", "-q", self.source, self.root / "plain")
        with self.server() as srv:
            for repo in ("team/proj.git", "team/proj", "plain.git", "plain"):
                work = self.clone(self.url(srv, repo), repo.replace("/", "-") + "-clone")
                self.assertTrue((work / "file0.txt").is_file(), repo)

    # ---------------- write paths ----------------
    def test_push_branch_tags_and_delete(self) -> None:
        with self.server() as srv:
            work = self.clone(self.url(srv), "work")
            git("-C", work, "checkout", "-q", "-b", "topic", env=self.env)
            head = self.commit(work, "topic.txt")
            git("-C", work, "tag", "topic-tag", env=self.env)
            self.push(work, "topic", "refs/tags/topic-tag")
            self.assertEqual(self.ref("refs/heads/topic"), head)
            self.assertEqual(self.ref("refs/tags/topic-tag"), head)
            self.push(work, ":topic", ":refs/tags/topic-tag")
        self.assertEqual(self.ref("refs/heads/topic"), "")
        self.assertEqual(self.ref("refs/tags/topic-tag"), "")
        self.fsck()

    def test_non_fast_forward_rejected_until_forced(self) -> None:
        with self.server() as srv:
            first = self.clone(self.url(srv), "first")
            second = self.clone(self.url(srv), "second")
            self.commit(first, "a.txt")
            self.push(first, "HEAD:main")
            diverged = self.commit(second, "b.txt")
            rejected = self.push(second, "HEAD:main", check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("rejected", rejected.stderr)
            self.push(second, "+HEAD:main")
        self.assertEqual(self.ref("main"), diverged)

    def test_atomic_multi_ref_push_is_all_or_nothing(self) -> None:
        with self.server() as srv:
            work = self.clone(self.url(srv), "atomic")
            other = self.clone(self.url(srv), "other")
            self.commit(other, "o.txt")
            self.push(other, "HEAD:feature", "--force")
            before_feature = self.ref("feature")
            head = self.commit(work, "atomic.txt")
            # feature moved on the server, so this ref fails and main must not move.
            result = self.push(work, "--atomic", "HEAD:main", "HEAD~1:feature", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(self.ref("main"), head)
            self.assertEqual(self.ref("feature"), before_feature)
            self.push(work, "--atomic", "HEAD:main", "HEAD:refs/heads/atomic-branch")
        self.assertEqual(self.ref("main"), head)
        self.assertEqual(self.ref("atomic-branch"), head)

    def test_large_push_and_clone_round_trip(self) -> None:
        payload = os.urandom(6 * 1024 * 1024)
        with self.server() as srv:
            work = self.clone(self.url(srv), "big")
            head = self.commit(work, "big.bin", payload)
            self.push(work, "HEAD:main")
            copy = self.clone(self.url(srv), "big-copy")
        self.assertEqual(self.ref("main"), head)
        self.assertEqual((copy / "big.bin").read_bytes(), payload)
        self.fsck()

    def test_branch_protection_rejects_direct_push(self) -> None:
        protected = commit_legacy_config(
            self.bare, validate_config({"block_direct_pushes": True, "protected_branches": "main"})
        )
        with self.server() as srv:
            work = self.clone(self.url(srv), "protected")
            self.commit(work, "p.txt")
            rejected = self.push(work, "HEAD:main", check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("protected branch main", rejected.stderr)
            self.push(work, "HEAD:refs/heads/side")
        self.assertEqual(self.ref("main"), protected)

    def test_auth_scopes_and_authenticated_receive_pack_default(self) -> None:
        # norecv.git has no http.receivepack: authenticated users may still push.
        bare_clone(self.source, self.root / "norecv.git")
        with self.server(require_auth=True) as srv:
            conn = database._db_connect()
            try:
                user = conn.execute(
                    "INSERT INTO users(username,pass_salt,pass_hash,is_admin) VALUES(?,?,?,0)",
                    ("alice", b"x", b"x"),
                ).lastrowid
            finally:
                conn.close()
            reader = database.db_create_token(user, "reader", "read")
            writer = database.db_create_token(user, "writer", "read,write")
            anonymous = subprocess.run(
                ["git", "ls-remote", self.url(srv)], env=self.env, capture_output=True, text=True
            )
            self.assertNotEqual(anonymous.returncode, 0)
            work = self.clone(self.url(srv, "norecv.git", f"alice:{reader}@"), "auth-read")
            self.commit(work, "auth.txt")
            denied = self.push(work, "HEAD:main", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("403", denied.stderr)
            git(
                "-C",
                work,
                "remote",
                "set-url",
                "origin",
                self.url(srv, "norecv.git", f"alice:{writer}@"),
            )
            self.push(work, "HEAD:main")
        pushed = git("--git-dir", self.root / "norecv.git", "log", "-1", "--format=%s", "main")
        self.assertEqual(pushed.strip(), "Add auth.txt")

    # ---------------- concurrency and robustness ----------------
    def test_concurrent_clones(self) -> None:
        errors: list[BaseException] = []
        with self.server() as srv:

            def worker(index: int) -> None:
                try:
                    work = self.clone(self.url(srv), f"parallel-{index}")
                    assert (work / "file0.txt").is_file()
                except BaseException as exc:  # noqa: BLE001 - surface in the main thread
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=120)
        self.assertEqual(errors, [])

    def test_concurrent_pushes_to_different_branches(self) -> None:
        errors: list[BaseException] = []
        heads: dict[int, str] = {}
        with self.server() as srv:
            works = [self.clone(self.url(srv), f"pusher-{i}") for i in range(5)]

            def worker(index: int) -> None:
                try:
                    heads[index] = self.commit(works[index], f"p{index}.txt")
                    self.push(works[index], f"HEAD:refs/heads/branch-{index}")
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=120)
        self.assertEqual(errors, [])
        for index, head in heads.items():
            self.assertEqual(self.ref(f"branch-{index}"), head)
        self.fsck()

    def test_expect_100_continue(self) -> None:
        body = FLUSH
        with self.server() as srv:
            with socket.create_connection(("127.0.0.1", srv.port), timeout=30) as sock:
                sock.sendall(
                    (
                        "POST /git/repo.git/git-receive-pack HTTP/1.1\r\n"
                        "Host: localhost\r\n"
                        f"Content-Type: {RECEIVE_REQ}\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Expect: 100-continue\r\n\r\n"
                    ).encode()
                )
                interim = sock.recv(64)
                self.assertTrue(interim.startswith(b"HTTP/1.1 100 Continue"), interim)
                sock.sendall(body)
                response = b""
                while chunk := sock.recv(65536):
                    response += chunk
            self.assertIn(b"200 OK", response.split(b"\r\n", 1)[0])
            self.assertIn(b"application/x-git-receive-pack-result", response)

    def test_client_disconnect_mid_response_keeps_server_healthy(self) -> None:
        big = self.tmp / "big-src"
        make_source(big, commits=1, blob_bytes=4 * 1024 * 1024)
        bare_clone(big, self.root / "big.git")
        main = git("--git-dir", self.root / "big.git", "rev-parse", "main").strip()
        request = (
            pkt_line(f"want {main} side-band-64k ofs-delta no-progress\n")
            + FLUSH
            + pkt_line("done\n")
        )
        with self.server() as srv:
            for _ in range(3):
                with socket.create_connection(("127.0.0.1", srv.port), timeout=30) as sock:
                    sock.sendall(
                        (
                            "POST /git/big.git/git-upload-pack HTTP/1.1\r\nHost: x\r\n"
                            f"Content-Type: {UPLOAD_REQ}\r\nContent-Length: {len(request)}\r\n\r\n"
                        ).encode()
                        + request
                    )
                    self.assertTrue(sock.recv(4096))
                # Socket closed after the first bytes of a ~4 MB pack.
            work = self.clone(self.url(srv), "after-disconnect")
        self.assertTrue((work / "file0.txt").is_file())

    @unittest.skipIf(os.name == "nt", "shell hook fixture")
    def test_basic_auth_header_is_not_forwarded_to_hooks(self) -> None:
        # The backend must not leak Authorization into the git environment.
        hook = self.bare / "hooks" / "pre-receive"
        hook.write_text('#!/bin/sh\nenv > "$GIT_DIR/hook-env.txt"\ncat >/dev/null\n')
        hook.chmod(0o755)
        with self.server() as srv:
            work = self.clone(self.url(srv), "hooked")
            self.commit(work, "h.txt")
            token = base64.b64encode(b"user:secret-value").decode()
            git("-C", work, "config", "http.extraHeader", f"Authorization: Basic {token}")
            self.push(work, "HEAD:main")
        captured = (self.bare / "hook-env.txt").read_text()
        self.assertNotIn("secret-value", captured)
        self.assertNotIn(token, captured)
        self.assertNotIn("HTTP_AUTHORIZATION", captured)


for _name, _path in BACKENDS.items():
    _cls = type(
        f"ClientBehavior_{_name.replace('-', '_')}",
        (ClientBehaviorMixin, unittest.TestCase),
        {"BACKEND": _name, "__module__": __name__},
    )
    if not _which_git():
        _cls = unittest.skip("git not found in PATH")(_cls)
    elif not _path:
        _cls = unittest.skip(f"{_name} backend not available")(_cls)
    globals()[_cls.__name__] = _cls
del _name, _path, _cls


def setUpModule() -> None:
    isolate_git_config()


def tearDownModule() -> None:
    restore_git_config()


if __name__ == "__main__":
    unittest.main()
