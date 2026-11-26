"""OpenAPI 3.1 contract for the implemented read and safe-write endpoints."""

from collections.abc import Collection, Sequence
from typing import Any

from ..discussion_rules import CATEGORIES
from ..repo_templates import GITIGNORE_TEMPLATES, LICENSES
from .types import DynamicJSONObject


def specification() -> DynamicJSONObject:
    def ref(name: str) -> DynamicJSONObject:
        return {"$ref": "#/components/schemas/" + name}

    def obj(properties: dict[str, Any]) -> DynamicJSONObject:
        return {"type": "object", "properties": properties, "required": list(properties)}

    string: DynamicJSONObject = {"type": "string"}
    nullable_string: DynamicJSONObject = {"type": ["string", "null"]}
    integer: DynamicJSONObject = {"type": "integer"}
    nullable_date: DynamicJSONObject = {"type": ["string", "null"], "format": "date-time"}
    date: DynamicJSONObject = {"type": "string", "format": "date-time"}
    schemas: DynamicJSONObject = {
        "Error": obj({"message": string, "code": string, "request_id": string}),
        "User": obj(
            {
                "id": integer,
                "login": string,
                "is_admin": {"type": "boolean"},
                "scopes": {"type": "array", "items": string},
                "repository": {
                    "type": ["string", "null"],
                    "description": "owner/repo the token is bound to; null for a legacy "
                    "token that is valid for every repository.",
                },
            }
        ),
        "Author": obj({"id": integer, "login": {"type": ["string", "null"]}}),
        "Repository": obj(
            {
                "name": string,
                "full_name": string,
                "owner": obj({"login": string}),
                "url": string,
                "html_url": string,
            }
        ),
        "RepositoryDetail": {
            "allOf": [ref("Repository"), obj({"default_branch": nullable_string})]
        },
        "Branch": obj({"name": string, "commit": obj({"sha": string})}),
        "Commit": obj(
            {
                "sha": string,
                "parents": {"type": "array", "items": obj({"sha": string})},
                "commit": obj(
                    {
                        "message": string,
                        "author": obj({"name": string, "email": string, "date": date}),
                    }
                ),
            }
        ),
        "Issue": obj(
            {
                "id": integer,
                "title": string,
                "body": string,
                "user": {"anyOf": [ref("Author"), {"type": "null"}]},
                "state": {"enum": ["open", "closed"]},
                "created_at": date,
                "updated_at": nullable_date,
                "closed_at": nullable_date,
                "revision": string,
            }
        ),
        "Pull": obj(
            {
                "id": integer,
                "title": string,
                "body": string,
                "user": {"anyOf": [ref("Author"), {"type": "null"}]},
                "state": {"enum": ["open", "closed", "merged"]},
                "created_at": date,
                "closed_at": nullable_date,
                "merged_at": nullable_date,
                "head": obj({"ref": string}),
                "base": obj({"ref": string}),
                "merge_method": nullable_string,
                "merge_commit_sha": nullable_string,
                "draft": {"type": "boolean"},
                "revision": string,
            }
        ),
        "Comment": obj(
            {
                "id": integer,
                "body": string,
                "user": {"anyOf": [ref("Author"), {"type": "null"}]},
                "created_at": date,
                "edited_at": nullable_date,
                "revision": string,
            }
        ),
        "Pipeline": obj(
            {
                "name": string,
                "runner": string,
                "timeout_seconds": integer,
                "repository_file": nullable_string,
            }
        ),
        "Run": obj(
            {
                "id": integer,
                "event": string,
                "branch": string,
                "head_sha": string,
                "status": {
                    "enum": [
                        "queued",
                        "running",
                        "success",
                        "failed",
                        "timed_out",
                        "cancelled",
                        "interrupted",
                    ]
                },
                "return_code": {"type": ["integer", "null"]},
                "created_at": date,
                "started_at": nullable_date,
                "finished_at": nullable_date,
                "pipeline": string,
            }
        ),
        "Discovery": obj(
            {
                "version": string,
                "read_only": {"type": "boolean"},
                "documentation_url": string,
                "openapi_url": string,
                "repositories_url": string,
            }
        ),
        "FileContent": obj(
            {
                "path": string,
                "sha": string,
                "commit_sha": string,
                "branch": string,
                "encoding": {"const": "base64"},
                "content": string,
                "size": integer,
            }
        ),
        "FileChange": obj(
            {"path": string, "commit": obj({"sha": string}), "deleted": {"type": "boolean"}}
        ),
        "Merge": obj(
            {"merged": {"const": True}, "sha": string, "merge_method": {"const": "ff-only"}}
        ),
        "LogChunk": obj(
            {
                "run_id": integer,
                "encoding": {"const": "utf-8"},
                "content": string,
                "offset": integer,
                "next_offset": integer,
                "size_in_bytes": integer,
                "has_more": {"type": "boolean"},
                "truncated": {"type": "boolean"},
                "status": string,
                "complete": {"type": "boolean"},
                "phase": string,
                "reason": string,
            }
        ),
        "Artifact": obj(
            {
                "id": integer,
                "run_id": integer,
                "name": string,
                "size_in_bytes": integer,
                "created_at": date,
                "expires_at": nullable_date,
                "downloadable": {"type": "boolean"},
                "download_url": string,
            }
        ),
        "TreeEntry": obj(
            {
                "path": string,
                "name": string,
                "mode": string,
                "type": {"enum": ["blob", "tree", "commit"]},
                "sha": string,
                "size": {"type": ["integer", "null"]},
            }
        ),
        "SearchMatch": obj(
            {"path": string, "line_number": integer, "text": string, "commit_sha": string}
        ),
        "ChangedFile": obj(
            {
                "path": string,
                "status": string,
                "additions": {"type": ["integer", "null"]},
                "deletions": {"type": ["integer", "null"]},
            }
        ),
        "Diff": obj({"base_sha": nullable_string, "head_sha": string, "patch": string}),
        "DiscussionCategory": obj(
            {"name": {"enum": list(CATEGORIES)}, "accepts_answers": {"type": "boolean"}}
        ),
        "Discussion": obj(
            {
                "id": integer,
                "category": {"enum": list(CATEGORIES)},
                "title": string,
                "body": string,
                "user": {"anyOf": [ref("Author"), {"type": "null"}]},
                "locked": {"type": "boolean"},
                "locked_by": {"type": ["integer", "null"]},
                "answered_comment_id": {"type": ["integer", "null"]},
                "created_at": date,
                "updated_at": nullable_date,
                "revision": string,
            }
        ),
    }
    paths: DynamicJSONObject = {}

    def parameter(
        name: str,
        schema: Any,
        location: str = "query",
        required: bool = False,
    ) -> DynamicJSONObject:
        return {"name": name, "in": location, "required": required, "schema": schema}

    def endpoint(
        path: str,
        name: str,
        schema: Any,
        *,
        listing: bool = False,
        filters: Sequence[DynamicJSONObject] = (),
    ) -> None:
        parameters = [
            parameter(p, string, "path", True)
            for p in ("owner", "repo", "branch", "ref", "path")
            if "{" + p + "}" in path
        ]
        if "{id}" in path:
            parameters.append(parameter("id", {"type": "integer", "minimum": 1}, "path", True))
        for key in ("comment_id", "review_id", "thread_id"):
            if "{" + key + "}" in path:
                parameters.append(parameter(key, {"type": "integer", "minimum": 1}, "path", True))
        if listing:
            parameters += [
                parameter(
                    "page", {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1}
                ),
                parameter(
                    "per_page", {"type": "integer", "minimum": 1, "maximum": 100, "default": 30}
                ),
            ]
        parameters += list(filters)
        response_schema = {"type": "array", "items": schema} if listing else schema
        responses: DynamicJSONObject = {
            "200": {
                "description": "Success",
                "content": {"application/json": {"schema": response_schema}},
            }
        }
        if listing:
            responses["200"]["headers"] = {
                "Link": {"description": "Relative next/prev pagination URLs.", "schema": string},
                "X-Page": {"schema": integer},
                "X-Per-Page": {"schema": integer},
            }
        for status, description in (
            ("400", "Invalid query or unexpected request body"),
            ("401", "Missing, invalid, expired or revoked bearer token"),
            ("403", "Insufficient scope or IP not allowed"),
            ("404", "Unknown endpoint or inaccessible resource"),
            ("405", "Method not supported at this endpoint"),
            ("409", "Revision, state, merge or idempotency conflict"),
            ("413", "Output exceeds response limit"),
            ("415", "Mutation body must use application/json"),
            ("422", "Invalid fields or missing idempotency key"),
            ("429", "Rate limit exceeded; observe Retry-After"),
            ("500", "Internal server error"),
            ("503", "Repository unavailable"),
            ("504", "Operation timed out"),
        ):
            responses[status] = {
                "description": description,
                "content": {"application/json": {"schema": ref("Error")}},
            }
        operation = {"operationId": name, "parameters": parameters, "responses": responses}
        head_responses = {
            key: {k: v for k, v in value.items() if k != "content"}
            for key, value in responses.items()
        }
        paths[path] = {
            "get": operation,
            "head": {
                **operation,
                "operationId": name + "Head",
                "responses": head_responses,
                "description": "Same status and headers as GET, without a response body.",
            },
        }

    endpoint("", "discovery", ref("Discovery"))
    endpoint("/user", "currentUser", ref("User"))
    endpoint("/openapi.json", "openAPISpecification", {"type": "object"})
    endpoint("/repos", "listRepositories", ref("Repository"), listing=True)
    base = "/repos/{owner}/{repo}"
    endpoint(base, "getRepository", ref("RepositoryDetail"))
    endpoint(base + "/branches", "listBranches", ref("Branch"), listing=True)
    endpoint(base + "/branches/{branch}", "getBranch", ref("Branch"))
    endpoint(
        base + "/commits",
        "listCommits",
        ref("Commit"),
        listing=True,
        filters=[parameter("ref", string)],
    )
    endpoint(base + "/commits/{ref}", "getCommit", ref("Commit"))
    for resource, name in (("issues", "Issue"), ("pulls", "Pull")):
        states = ["open", "closed", "all"] + (["merged"] if resource == "pulls" else [])
        endpoint(
            base + "/" + resource,
            "list" + name + "s",
            ref(name),
            listing=True,
            filters=[parameter("state", {"type": "string", "enum": states, "default": "open"})],
        )
        endpoint(base + "/" + resource + "/{id}", "get" + name, ref(name))
        endpoint(
            base + "/" + resource + "/{id}/comments",
            "list" + name + "Comments",
            ref("Comment"),
            listing=True,
        )
        endpoint(
            base + "/" + resource + "/{id}/comments/{comment_id}",
            "get" + name + "Comment",
            ref("Comment"),
        )
    endpoint(base + "/ci/pipelines", "listPipelines", ref("Pipeline"), listing=True)
    endpoint(
        base + "/ci/runs",
        "listRuns",
        ref("Run"),
        listing=True,
        filters=[
            parameter("status", schemas["Run"]["properties"]["status"]),
            parameter("branch", string),
        ],
    )
    endpoint(base + "/ci/runs/{id}", "getRun", ref("Run"))
    endpoint(
        base + "/ci/runs/{id}/logs",
        "getRunLogs",
        ref("LogChunk"),
        filters=[
            parameter(
                "offset",
                {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2147483647,
                    "default": 0,
                    "description": "UTF-8 byte offset; use next_offset from the previous chunk.",
                },
            ),
            parameter(
                "limit", {"type": "integer", "minimum": 4, "maximum": 65536, "default": 16384}
            ),
        ],
    )
    endpoint(base + "/ci/artifacts", "listArtifacts", ref("Artifact"), listing=True)
    endpoint(base + "/ci/runs/{id}/artifacts", "listRunArtifacts", ref("Artifact"), listing=True)
    download = base + "/ci/runs/{id}/artifacts/download"
    endpoint(download, "downloadRunArtifacts", {"type": "string", "format": "binary"})
    paths[download]["get"]["responses"]["200"] = {
        "description": "Original ZIP archive, bounded by the run's configured artifact limit (32 MiB for legacy runs). No redirects, extraction or range downloads.",
        "headers": {
            "Content-Disposition": {"schema": string},
            "Content-Length": {"schema": integer},
        },
        "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}},
    }
    paths[download]["head"]["responses"]["200"] = {
        "description": "ZIP metadata without loading or returning the archive body.",
        "headers": {
            "Content-Disposition": {"schema": string},
            "Content-Length": {"schema": integer},
        },
    }
    endpoint(
        base + "/contents/{path}",
        "getFileContent",
        ref("FileContent"),
        filters=[parameter("branch", string)],
    )
    endpoint(
        base + "/tree",
        "listTree",
        ref("TreeEntry"),
        listing=True,
        filters=[
            parameter("ref", string),
            parameter("path", string),
            parameter("recursive", {"type": "boolean", "default": False}),
        ],
    )
    endpoint(
        base + "/ci/settings",
        "getCISettings",
        obj(
            {
                "configuration": {"type": "object"},
                "revision": string,
                "source_commit": {"type": ["string", "null"]},
                "source_path": string,
                "status": {"enum": ["valid", "missing", "invalid", "blocked", "unavailable"]},
                "error": {"type": ["string", "null"]},
            }
        ),
    )
    deployment = obj(
        {
            "id": integer,
            "run_id": integer,
            "commit_sha": string,
            "status": string,
            "started_at": date,
            "finished_at": nullable_date,
            "notification": nullable_string,
            "name": string,
            "pipeline": string,
            "branch": nullable_string,
            "run_retained": {"type": "boolean"},
            "log_size_in_bytes": integer,
        }
    )
    endpoint(base + "/deployments", "listDeployments", deployment, listing=True)
    endpoint(base + "/deployments/{id}", "getDeployment", deployment)
    endpoint(
        base + "/deployments/{id}/steps",
        "listDeploymentSteps",
        obj({"index": integer, "name": string, "status": string, "log_size_in_bytes": integer}),
        listing=True,
    )
    deployment_log = obj(
        {
            "deployment_id": integer,
            "step_index": {"type": ["integer", "null"]},
            "status": string,
            "encoding": {"const": "utf-8"},
            "content": string,
            "offset": integer,
            "next_offset": integer,
            "size_in_bytes": integer,
            "has_more": {"type": "boolean"},
            "complete": {"type": "boolean"},
        }
    )
    for suffix, operation in (
        ("/logs", "getDeploymentLog"),
        ("/steps/{step_index}/logs", "getDeploymentStepLog"),
    ):
        endpoint(
            base + "/deployments/{id}" + suffix,
            operation,
            deployment_log,
            filters=[
                parameter("offset", {"type": "integer", "minimum": 0, "default": 0}),
                parameter(
                    "limit", {"type": "integer", "minimum": 4, "maximum": 65536, "default": 16384}
                ),
            ],
        )
    endpoint(
        base + "/deployments/preflight",
        "deploymentPreflight",
        obj(
            {
                "revision": string,
                "ok": {"type": "boolean"},
                "advisory": {"const": True},
                "targets": {"type": "array", "items": {"type": "object"}},
            }
        ),
    )
    paths[base + "/deployments/preflight"]["get"]["description"] = (
        "Administrator-only, read-only checks of enabled deployment prerequisites. "
        "Does not execute scripts or validate arbitrary commands, credentials or remote services."
    )
    endpoint(
        base + "/search",
        "searchRepository",
        ref("SearchMatch"),
        listing=True,
        filters=[
            parameter("q", {"type": "string", "minLength": 1, "maxLength": 256}, required=True),
            parameter("ref", string),
            parameter("path", string),
            parameter("ignore_case", {"type": "boolean", "default": False}),
        ],
    )
    for view, schema in (("files", ref("ChangedFile")), ("diff", ref("Diff"))):
        endpoint(
            base + "/compare/" + view,
            "compare" + view.title(),
            schema,
            listing=view == "files",
            filters=[
                parameter("base", string, required=True),
                parameter("head", string, required=True),
            ],
        )
        endpoint(
            base + "/commits/{ref}/" + view,
            "getCommit" + view.title(),
            schema,
            listing=view == "files",
        )
        endpoint(
            base + "/pulls/{id}/" + view,
            "getPull" + view.title(),
            schema,
            listing=view == "files",
            filters=[parameter("ignore_whitespace", {"type": "boolean", "default": False})]
            if view == "diff"
            else [],
        )
    endpoint(base + "/pulls/{id}/commits", "listPullCommits", ref("Commit"), listing=True)
    endpoint(
        base + "/archive",
        "downloadSourceArchive",
        {"type": "string", "format": "binary"},
        filters=[parameter("ref", string)],
    )
    paths[base + "/archive"]["get"]["responses"]["200"] = {
        "description": "Generated ZIP of the pinned commit, at most 32 MiB; shares artifact download permits.",
        "headers": {
            "Content-Disposition": {"schema": string},
            "Content-Length": {"schema": integer},
        },
        "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}},
    }
    paths[base + "/archive"]["head"]["responses"]["200"] = {
        "description": "Generate the same bounded ZIP to determine its length, but return no body.",
        "headers": {
            "Content-Disposition": {"schema": string},
            "Content-Length": {"schema": integer},
        },
    }
    for view in ("tree", "search", "compare/files", "commits/{ref}/files", "pulls/{id}/files"):
        headers = paths[base + "/" + view]["get"]["responses"]["200"]["headers"]
        headers["X-Commit-SHA"] = {
            "description": "Resolved immutable head commit.",
            "schema": string,
        }
        if view.endswith("/files"):
            headers["X-Base-SHA"] = {
                "description": "Comparison base; empty for a root commit.",
                "schema": string,
            }
    endpoint(
        base + "/discussions/categories",
        "listDiscussionCategories",
        ref("DiscussionCategory"),
        listing=True,
    )
    endpoint(
        base + "/discussions",
        "listDiscussions",
        ref("Discussion"),
        listing=True,
        filters=[
            parameter("category", {"type": "string", "enum": list(CATEGORIES)}),
            parameter("locked", {"type": "boolean"}),
        ],
    )
    endpoint(base + "/discussions/{id}", "getDiscussion", ref("Discussion"))
    endpoint(
        base + "/discussions/{id}/comments", "listDiscussionComments", ref("Comment"), listing=True
    )
    endpoint(
        base + "/discussions/{id}/comments/{comment_id}", "getDiscussionComment", ref("Comment")
    )

    def mutation(
        path: str,
        method: str,
        operation_id: str,
        properties: dict[str, Any],
        required: Collection[str],
        response: Any,
        status: int = 200,
    ) -> None:
        parameters = [
            parameter(
                "Idempotency-Key",
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9._:-]+$",
                },
                "header",
                True,
            )
        ]
        numeric = ("id", "comment_id", "review_id", "thread_id")
        for key in ("owner", "repo", "branch", "path", *numeric):
            if "{" + key + "}" in path:
                parameters.append(
                    parameter(key, integer if key in numeric else string, "path", True)
                )
        responses: DynamicJSONObject = {
            key: value for key, value in paths["/user"]["get"]["responses"].items() if key != "200"
        }
        responses[str(status)] = {
            "description": "Mutation accepted; replaying the same idempotency key returns this result.",
            "headers": {
                "X-Idempotent-Replay": {
                    "schema": {"type": "boolean"},
                    "description": "true when replaying a completed operation",
                }
            },
            "content": {"application/json": {"schema": response}},
        }
        paths.setdefault(path, {})[method] = {
            "operationId": operation_id,
            "description": "Requires write scope and repository access. Use a new idempotency key for a different operation. "
            "After a timeout, retry the identical request with the same key; pending claims are never re-executed.",
            "parameters": parameters,
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": properties,
                            "required": list(required),
                            "additionalProperties": False,
                        }
                    }
                },
            },
            "responses": responses,
        }

    commit_sha = {"type": "string", "pattern": "^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"}
    revision = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    title = {"type": "string", "minLength": 1, "maxLength": 256}
    body = {"type": "string", "maxLength": 65536}
    mutation(
        "/user/repos",
        "post",
        "createRepository",
        {
            "name": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"},
            "default_branch": string,
            "auto_init": {"type": "boolean"},
            "gitignore_template": {"type": "string", "enum": ["", *GITIGNORE_TEMPLATES]},
            "license_template": {"type": "string", "enum": ["", *LICENSES]},
        },
        {"name"},
        ref("RepositoryDetail"),
        201,
    )
    mutation(
        base + "/branches",
        "post",
        "createBranch",
        {"name": string, "sha": commit_sha},
        {"name", "sha"},
        ref("Branch"),
        201,
    )
    mutation(
        base + "/branches/{branch}",
        "delete",
        "deleteBranch",
        {"expected_head": commit_sha},
        {"expected_head"},
        obj({"deleted": {"const": True}, "name": string}),
    )
    file_props = {
        "branch": string,
        "expected_head": commit_sha,
        "message": {"type": "string", "minLength": 1, "maxLength": 4000},
    }
    mutation(
        base + "/contents/{path}",
        "put",
        "putFile",
        {
            **file_props,
            "content": {
                "type": "string",
                "maxLength": 1400000,
                "description": "Base64-encoded UTF-8 text, at most 1 MiB decoded.",
            },
        },
        {*file_props, "content"},
        ref("FileChange"),
    )
    paths[base + "/contents/{path}"]["put"]["responses"]["201"] = {
        "description": "New file created",
        "content": {"application/json": {"schema": ref("FileChange")}},
    }
    mutation(
        base + "/contents/{path}",
        "delete",
        "deleteFile",
        file_props,
        set(file_props),
        ref("FileChange"),
    )
    for resource, label in (("issues", "Issue"), ("pulls", "Pull")):
        props = {"title": title, "body": body}
        required = {"title"}
        if resource == "pulls":
            props.update(head=string, base=string, draft={"type": "boolean"})
            required.update({"head", "base"})
        mutation(base + "/" + resource, "post", "create" + label, props, required, ref(label), 201)
        mutation(
            base + "/" + resource + "/{id}",
            "patch",
            "update" + label,
            {
                "title": title,
                "body": body,
                "state": {"enum": ["open", "closed"]},
                "expected_revision": revision,
            },
            {"expected_revision"},
            ref(label),
        )
        comments = base + "/" + resource + "/{id}/comments"
        mutation(
            comments,
            "post",
            "create" + label + "Comment",
            {"body": {**body, "minLength": 1}},
            {"body"},
            ref("Comment"),
            201,
        )
        mutation(
            comments + "/{comment_id}",
            "patch",
            "update" + label + "Comment",
            {"body": {**body, "minLength": 1}, "expected_revision": revision},
            {"body", "expected_revision"},
            ref("Comment"),
        )
        mutation(
            comments + "/{comment_id}",
            "delete",
            "delete" + label + "Comment",
            {"expected_revision": revision},
            {"expected_revision"},
            obj({"deleted": {"const": True}, "id": integer}),
        )
    mutation(
        base + "/pulls/{id}/merge",
        "put",
        "mergePull",
        {
            "merge_method": {"enum": ["merge", "squash", "rebase", "ff"]},
            "sha": commit_sha,
            "expected_base_sha": commit_sha,
            "commit_title": title,
            "commit_message": {"type": "string", "maxLength": 4000},
            "delete_branch": {"type": "boolean"},
        },
        (),
        ref("Merge"),
    )
    _review_endpoints(base, endpoint, mutation, obj, ref, string, integer, commit_sha, body)
    # PATCH /pulls/{id} also takes draft and base (without expected_revision).
    pull_patch = paths[base + "/pulls/{id}"]["patch"]["requestBody"]["content"]["application/json"]
    pull_patch["schema"]["properties"].update(draft={"type": "boolean"}, base=string)
    pull_patch["schema"]["required"] = []
    pull_patch["schema"]["description"] = (
        "Either draft and/or base alone, or title/body/state with expected_revision."
    )
    mutation(
        base + "/ci/runs",
        "post",
        "triggerRun",
        {
            "branch": string,
            "pipeline": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
            "sha": commit_sha,
        },
        {"branch", "pipeline"},
        ref("Run"),
        202,
    )
    mutation(base + "/ci/runs/{id}/cancel", "post", "cancelRun", {}, set(), ref("Run"))
    mutation(base + "/ci/runs/{id}/rerun", "post", "rerunRun", {}, set(), ref("Run"), 202)
    paths[base + "/ci/settings"]["get"]["description"] = (
        "Administrator-only read-only repository CI configuration. Requires read scope. "
        "Commit pipeline and deployment definitions to ci/config.json; replacement "
        "through this API is disabled. Secrets remain managed on the project page. "
        "Does not execute a deployment or provide deployment preflight."
    )
    mutation(
        base + "/discussions",
        "post",
        "createDiscussion",
        {
            "title": title,
            "body": body,
            "category": {"enum": list(CATEGORIES), "default": "General"},
        },
        {"title"},
        ref("Discussion"),
        201,
    )
    mutation(
        base + "/discussions/{id}",
        "patch",
        "updateDiscussion",
        {
            "title": title,
            "body": body,
            "category": {"enum": list(CATEGORIES)},
            "locked": {"type": "boolean"},
            "expected_revision": revision,
            "answered_comment_id": {"type": ["integer", "null"], "minimum": 1},
        },
        {"expected_revision"},
        ref("Discussion"),
    )
    comments = base + "/discussions/{id}/comments"
    mutation(
        comments,
        "post",
        "createDiscussionComment",
        {"body": {**body, "minLength": 1}},
        {"body"},
        ref("Comment"),
        201,
    )
    mutation(
        comments + "/{comment_id}",
        "patch",
        "updateDiscussionComment",
        {"body": {**body, "minLength": 1}, "expected_revision": revision},
        {"body", "expected_revision"},
        ref("Comment"),
    )
    mutation(
        comments + "/{comment_id}",
        "delete",
        "deleteDiscussionComment",
        {"expected_revision": revision},
        {"expected_revision"},
        obj({"deleted": {"const": True}, "id": integer}),
    )
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "PyGitHost API",
            "version": "1.3.0",
            "description": "GitHub-inspired API with repository browsing, discussions, safe writes and CI automation. Not GitHub API compatible. "
            "Owner namespace access; administrators can read all repositories. "
            "A repository-bound token can only reach its own repository. "
            "A read-scoped bearer token is required regardless of web authentication settings.",
        },
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {path or "/": value for path, value in paths.items()},
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Personal access token with read scope, bound to one "
                    "repository.",
                }
            },
            "schemas": schemas,
        },
    }


def _review_endpoints(
    base: str,
    endpoint: Any,
    mutation: Any,
    obj: Any,
    ref: Any,
    string: Any,
    integer: Any,
    commit_sha: Any,
    body: Any,
) -> None:
    """Pull request review, lifecycle and remaining repository endpoints."""
    flag = {"type": "boolean"}
    anything = {"type": "object"}
    pull = base + "/pulls/{id}"
    side = {"enum": ["LEFT", "RIGHT"]}
    line = {"type": "integer", "minimum": 1}
    mode = {"enum": ["single", "review"]}
    review_comment = {
        "type": "object",
        "properties": {
            "path": string,
            "line": line,
            "side": side,
            "start_line": line,
            "body": body,
        },
        "required": ["path", "line", "body"],
    }
    endpoint(pull + "/merge-status", "pullMergeStatus", anything)
    endpoint(pull + "/reviews", "listPullReviews", anything, listing=True)
    endpoint(pull + "/reviews/{review_id}", "getPullReview", anything)
    endpoint(pull + "/threads", "listReviewThreads", anything, listing=True)
    endpoint(pull + "/threads/{thread_id}", "getReviewThread", anything)
    endpoint(pull + "/requested_reviewers", "listRequestedReviewers", anything)
    endpoint(pull + "/events", "listPullEvents", anything, listing=True)
    endpoint(pull + "/timeline", "listPullTimeline", anything, listing=True)
    endpoint(pull + "/viewed-files", "listViewedFiles", anything)
    endpoint(pull + "/conflicts", "getPullConflicts", anything)
    endpoint(base + "/ci/variables", "getCiVariables", anything)
    mutation(
        pull + "/update-branch",
        "put",
        "updatePullBranch",
        {"expected_head_sha": commit_sha},
        (),
        anything,
        202,
    )
    mutation(pull + "/head-branch", "delete", "deletePullHeadBranch", {}, (), anything)
    mutation(pull + "/head-branch/restore", "post", "restorePullHeadBranch", {}, (), anything, 201)
    reviewers = {"reviewers": {"type": "array", "items": string, "minItems": 1, "maxItems": 20}}
    mutation(
        pull + "/requested_reviewers",
        "post",
        "requestReviewers",
        reviewers,
        {"reviewers"},
        anything,
        201,
    )
    mutation(
        pull + "/requested_reviewers",
        "delete",
        "removeRequestedReviewers",
        reviewers,
        {"reviewers"},
        anything,
    )
    mutation(
        pull + "/reviews",
        "post",
        "submitPullReview",
        {
            "event": {"enum": ["APPROVE", "REQUEST_CHANGES", "COMMENT"]},
            "body": body,
            "comments": {"type": "array", "items": review_comment, "maxItems": 100},
            "commit_id": commit_sha,
        },
        (),
        anything,
        201,
    )
    mutation(pull + "/reviews/pending", "delete", "discardPendingReview", {}, (), anything)
    mutation(
        pull + "/reviews/{review_id}/dismissals",
        "put",
        "dismissPullReview",
        {"message": {"type": "string", "minLength": 1, "maxLength": 1000}},
        {"message"},
        anything,
    )
    mutation(
        pull + "/threads",
        "post",
        "createReviewThread",
        {
            "path": string,
            "line": line,
            "side": side,
            "start_line": line,
            "body": body,
            "mode": mode,
        },
        {"path", "line", "body"},
        anything,
        201,
    )
    mutation(
        pull + "/threads/{thread_id}/replies",
        "post",
        "replyToReviewThread",
        {"body": body, "mode": mode},
        {"body"},
        anything,
        201,
    )
    mutation(
        pull + "/threads/{thread_id}/resolution",
        "put",
        "resolveReviewThread",
        {"resolved": flag},
        {"resolved"},
        anything,
    )
    mutation(
        pull + "/review-comments/{comment_id}",
        "patch",
        "updateReviewComment",
        {"body": body},
        {"body"},
        anything,
    )
    mutation(
        pull + "/review-comments/{comment_id}", "delete", "deleteReviewComment", {}, (), anything
    )
    mutation(
        pull + "/review-comments/{comment_id}/apply-suggestion",
        "post",
        "applyReviewSuggestion",
        {"expected_head_sha": commit_sha},
        (),
        anything,
        201,
    )
    mutation(
        pull + "/viewed-files",
        "put",
        "setFileViewed",
        {"path": string, "viewed": flag},
        {"path", "viewed"},
        anything,
    )
    resolution_file = {
        "type": "object",
        "properties": {"path": string, "content": string, "delete": flag},
        "required": ["path"],
    }
    mutation(
        pull + "/conflicts/resolution",
        "post",
        "resolvePullConflicts",
        {
            "files": {"type": "array", "items": resolution_file, "minItems": 1, "maxItems": 40},
            "message": {"type": "string", "maxLength": 4000},
            "expected_head": commit_sha,
            "expected_base": commit_sha,
        },
        {"files"},
        anything,
        201,
    )
    mutation(base, "delete", "deleteRepository", {"confirm": string}, {"confirm"}, anything)
    mutation(
        base + "/commits",
        "post",
        "commitFiles",
        {
            "branch": string,
            "expected_head": commit_sha,
            "message": {"type": "string", "minLength": 1, "maxLength": 4000},
            "changes": {
                "type": "object",
                "description": "Path to base64 UTF-8 content, or null to delete the file.",
                "additionalProperties": {"type": ["string", "null"]},
            },
        },
        {"branch", "expected_head", "message", "changes"},
        anything,
        201,
    )
    variable = {
        "type": "object",
        "properties": {
            "name": string,
            "value": string,
            "pipeline": {"type": ["string", "null"]},
            "scope": {"enum": ["ordinary", "protected", "deployment"]},
        },
        "required": ["name", "value"],
    }
    mutation(
        base + "/ci/variables",
        "put",
        "replaceCiVariables",
        {"variables": {"type": "array", "items": variable, "maxItems": 256}},
        {"variables"},
        anything,
    )
    mutation(base + "/ci/runs/{id}/notify", "post", "notifyRun", {}, (), anything, 202)
