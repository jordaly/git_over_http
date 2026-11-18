"""Administrator-only, read-only CI/deployment configuration from the repository."""

from ..repository_ci import CONFIG_FILE
from . import data
from .errors import APIError
from .types import APIContext, SettingsSnapshot


def authorize(api: APIContext) -> None:
    # Configuration contains plaintext environment values and executable host code.
    if not api.identity["is_admin"]:
        raise APIError(403, "forbidden", "Administrator required for CI/deployment settings.")


async def snapshot(api: APIContext, owner: str, repo: str) -> SettingsSnapshot:
    config = await api.handler.server.ci_manager.config(owner, repo, include_secrets=False)
    commit = config.get("_configuration_commit")
    document = config.get("_configuration_document")
    return {
        "configuration": document if isinstance(document, dict) else {},
        "revision": data.revision({"commit": commit, "path": CONFIG_FILE}),
        "source_commit": commit,
        "source_path": CONFIG_FILE,
        "status": config.get("_configuration_status", "unavailable"),
        "error": config.get("_configuration_error"),
    }


async def read(api: APIContext, owner: str, repo: str) -> object:
    authorize(api)
    api.parameters()
    async with api.handler.server.settings_lock:
        return await snapshot(api, owner, repo)


async def update(api: APIContext, owner: str, repo: str) -> tuple[int, dict[str, str]]:
    authorize(api)
    if api.request.method != "PUT":
        raise APIError(405, "method_not_allowed", "Use GET to read CI/deployment settings.")
    raise APIError(
        410,
        "gone",
        "CI configuration is repository-owned. Commit project pipeline definitions to "
        "ci/config.json; this API only reads configuration and cannot replace it.",
    )
