# Independent pipelines and deployments

[Every option](ci-options.md) · [Recipes](pipeline-examples.md) · [Migration](ci-migration.md)

AI assistants: see [Guidance for AI agents](ci-options.md#guidance-for-ai-agents)
before editing configuration or triggering runs.

Open **CI → Settings → Configuration JSON** and **Save configuration**. The same
manual and complete JSON examples appear directly in **CI → Documentation**.

For a repository without saved settings, you can instead commit
**`ci/config.json`** with `version` and named `steps`: CI discovers it by default
using the Docker runner. Without that file no automatic runs are created.
See [Automatic repository CI](ci-options.md#automatic-repository-ci) for a complete
example, enabled triggers and safety limits. Existing saved settings take priority.
The Settings JSON editor uses Monaco; **Format JSON** formats the document before
saving. Its syntax checks do not replace the server's configuration validation.

## Repository CI directory

Keep repository-owned pipeline JSON and helper scripts together under `ci/`:

```text
ci/
  config.json       # automatically discovered pipeline
  tests.json        # optional additional pipeline, explicitly referenced in Settings
  test.sh           # optional helper script
```

Create the directory with `mkdir -p ci`, then save the
[repository pipeline example](examples/ci/repository-pipeline.json) as
`ci/config.json` and commit it. The file contains steps, not the Settings reference
`{"version":1,"file":"ci/config.json"}`. No `ci/config.json` means no automatic run
for a repository without saved settings. Other JSON files are not auto-discovered.

All file references are relative to the **repository root**. Steps also start at
the checkout root, so invoke a helper with `sh ci/test.sh`, not `sh test.sh`.
Putting the JSON under `ci/` does not change the command's working directory.
See [multiple Git-managed pipelines](pipeline-examples.md#multiple-git-managed-pipelines)
for separate checks and [migration](ci-migration.md#move-root-files-into-ci)
for existing root files.

This layout covers repository-owned files only. Execution settings, triggers and
policies remain in Settings JSON; variables, secrets and retention remain in their
page controls. Do not commit secrets or trusted host deployment scripts under `ci/`.

## Two lists, explicit names

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}},
      "steps": [
        {"name": "Python version", "run": "python --version"},
        {"name": "Tests", "run": "python -m unittest discover -v"}
      ]
    },
    {
      "name": "compile",
      "execution": {"runner": "docker", "image": "python:3.14-slim", "timeout_seconds": 120},
      "steps": [{"name": "Compile", "run": "python -m compileall -q ."}]
    }
  ],
  "deployments": [
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh"}
  ]
}
```

Prepare the Python Docker image locally. `checks` runs on pushes to `main`; `compile`
has no automatic triggers, but both pipelines can always be queued manually with
write access. Host CI is trusted-code-only if you explicitly select it. Install the
trusted deployment script outside repositories before enabling the example target.
Manual runs test CI only; deployment requires a qualifying successful branch update.

## No shared configuration

Each pipeline independently defines its execution, triggers, cancellation,
artifacts and notifications. There is **no `defaults` object** or
top-level notification policy. An omitted field never uses
another pipeline's value. Repeat values deliberately when pipelines need the same
configuration. Changing one pipeline does not change any other pipeline. Omitted
execution values use built-in defaults.
Environment variables and retention are configured separately in page controls
under **CI → Settings**, with server defaults under **Admin → Settings**.

Each deployment is also a separate named object. `pipeline` references the CI
pipeline whose passing branch update gates it; script, branch, timeout and email
settings belong to the deployment itself. Multiple deployment targets may reference
the same pipeline. They have separate attempts, logs, results and notification state.
Deployment notifications do not inherit pipeline email settings.

Deployments can use [named host steps](automatic-deployment.md#named-deployment-steps)
instead of a script. Their individual status and output, plus combined output,
refresh every two seconds on **CI → Deployments**. These are host steps in a fresh
temporary directory, not CI steps in the checkout or Docker image.

The **CI → Runs** page has compact, wrapping filter and manual-run toolbars.
Choose a pipeline and branch to queue a manual CI run; filters narrow run history
without affecting execution. Run results refresh every five seconds.

Repository-wide protection (`policies`) stays at the document root. Variables and
storage limits use separate page controls, with server defaults and repository
overrides. Artifact retention applies across the repository, not per pipeline.

## Names and execution

Every pipeline and deployment object requires a unique `name` within its own list.
Names use 1–64 ASCII letters, digits, underscores or hyphens, beginning alphanumeric.
Keep them stable: names identify runs, target references and deployment attempts.
Up to 16 pipelines and 32 deployments are supported. Empty lists are valid.

Steps contain exactly `name` and `run`. Steps run in order; failure skips later
steps. Each starts a fresh shell in the checkout root. Files persist, not `cd`,
exported variables or shell state. Checkout, PR preparation and all steps share
that pipeline's timeout. Jobs and deployments remain sequential per repository;
independent configurations do not imply parallel execution or cross-pipeline dependencies.

## Saving and compatibility

Saving replaces the pipeline/deployment document. Invalid input is preserved but
not saved. Retain existing policies when adapting examples. Page-managed variables
and retention persist independently; retention changes require confirmation on
their own form and can permanently delete existing data.

Existing keyed or shared-default configurations remain readable. Opening the editor
converts them into named lists, materializes inherited values into each pipeline,
and moves inline deployment blocks to the deployment list. The prior pipeline ID
becomes its name; its legacy target receives the same name, preserving deployment
deduplication. Shared email values are copied explicitly rather than inherited.
See [Migration](ci-migration.md) for details.
