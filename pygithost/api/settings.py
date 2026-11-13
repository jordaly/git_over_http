"""Administrator-only CI/deployment configuration using the UI's save path."""

import asyncio
import json

from .. import database
from ..ci_config import editor_document
from . import data
from .errors import APIError
from .validation import expected_revision, fields


def authorize(api):
    # Configuration contains plaintext environment values and executable host code.
    if not api.identity["is_admin"]:
        raise APIError(403, "forbidden", "Administrator required for CI/deployment settings.")


async def snapshot(api, owner, repo):
    raw = await asyncio.to_thread(database.db_ci_config_get, owner, repo)
    preferences = await asyncio.to_thread(database.db_ci_preferences_get, owner, repo)
    config = await api.handler.server.ci_manager.config(owner, repo)
    return {
        "configuration": editor_document(config),
        "revision": data.revision({"configuration": raw, "preferences": preferences}),
    }


async def read(api, owner, repo):
    authorize(api)
    api.parameters()
    async with api.handler.server.settings_lock:
        return await snapshot(api, owner, repo)


async def update(api, owner, repo):
    authorize(api)
    if api.request.method != "PUT":
        raise APIError(405, "method_not_allowed", "Use PUT to replace CI/deployment configuration.")
    document = api.document
    fields(document, {"configuration", "expected_revision"}, {"configuration", "expected_revision"})
    expected_revision(document)
    if not isinstance(document["configuration"], dict):
        raise APIError(422, "validation_error", "configuration must be a JSON object.")
    if len(json.dumps(document["configuration"], ensure_ascii=False).encode("utf-8")) > 262144:
        raise APIError(413, "request_too_large", "Configuration exceeds 256 KiB.")
    async with api.handler.server.settings_lock:
        current = await snapshot(api, owner, repo)
        if current["revision"] != document["expected_revision"]:
            raise APIError(409, "revision_conflict", "Settings changed. Fetch the current revision.")
        try:
            await api.handler.server.ci_manager.save_document(
                owner, repo, document["configuration"], preserve_page_settings=True)
        except (ValueError, RecursionError):
            # Do not echo scripts, paths or environment values in error/audit output.
            raise APIError(422, "validation_error", "Invalid CI/deployment configuration. See the configuration JSON reference.") from None
        saved = await snapshot(api, owner, repo)
        # Durable idempotency caches responses: never copy configuration secrets
        # or executable payloads into the mutation audit table.
        return 200, {"revision": saved["revision"]}
