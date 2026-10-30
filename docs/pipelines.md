# Independent pipelines and deployments

[Every option](ci-options.md) · [Recipes](pipeline-examples.md) · [Migration](ci-migration.md)

Open **CI → Settings → Configuration JSON** and **Save configuration**. The same
manual and complete JSON examples appear directly in **CI → Documentation**.

## Two lists, explicit names

```json
{
  "version": 1,
  "pipelines": [
    {
      "name": "checks",
      "execution": {"runner": "host", "timeout_seconds": 600},
      "triggers": {"push": {"enabled": true, "branches": ["main"]}, "manual": {"enabled": true}},
      "steps": [
        {"name": "Python version", "run": "python --version"},
        {"name": "Tests", "run": "python -m unittest discover -v"}
      ]
    },
    {
      "name": "compile",
      "execution": {"runner": "host", "timeout_seconds": 120},
      "triggers": {"manual": {"enabled": true}},
      "steps": [{"name": "Compile", "run": "python -m compileall -q ."}]
    }
  ],
  "deployments": [
    {"name": "production", "pipeline": "checks", "enabled": false, "branch": "main", "script": "/opt/deploy/production.sh"}
  ]
}
```

Commands assume Python is installed. Host CI is trusted-code-only. Install the
trusted deployment script outside repositories before enabling the example target.
Manual runs test CI only; deployment requires a qualifying successful branch update.

## No shared configuration

Each pipeline independently defines its execution, triggers, cancellation,
environment, artifacts and notifications. There is **no `defaults` object** or
top-level notification policy. An omitted field uses the built-in default, never
another pipeline's value. Repeat values deliberately when pipelines need the same
configuration. Changing one pipeline does not change any other pipeline.

Each deployment is also a separate named object. `pipeline` references the CI
pipeline whose passing branch update gates it; script, branch, timeout and email
settings belong to the deployment itself. Multiple deployment targets may reference
the same pipeline. They have separate attempts, logs, results and notification state.
Deployment notifications do not inherit pipeline email settings.

Only repository-wide protection (`policies`) and storage limits (`retention`) stay
at the document root. They are administrator/storage controls, not inherited execution
configuration. Artifact retention applies across the repository, not per pipeline.

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

Saving replaces the entire document. Invalid input is preserved but not saved.
Retain existing policies/storage limits when adapting examples; omission restores
built-in defaults and retention changes can delete existing data immediately.

Existing keyed or shared-default configurations remain readable. Opening the editor
converts them into named lists, materializes inherited values into each pipeline,
and moves inline deployment blocks to the deployment list. The prior pipeline ID
becomes its name; its legacy target receives the same name, preserving deployment
deduplication. Shared email values are copied explicitly rather than inherited.
See [Migration](ci-migration.md) for details.
