# git_over_http

A dependency-free asynchronous Git Smart HTTP server with a web interface,
authentication, repository browsing, branches, tokens, users, and pull requests.

## Requirements

- Python 3.14 or newer (the UI renderer uses Python t-strings)
- Git and `git-http-backend`

## Configuration and startup

Generate a platform-specific configuration file:

```sh
python server.py generate-config --platform Linux
```

Review `pygithost.config.json`, particularly `git_project_root`,
`git_http_backend`, `db_path`, and the allowed client IPs, then run:

```sh
python server.py run --config pygithost.config.json
```

The package entry point is equivalent:

```sh
python -m pygithost run --config pygithost.config.json
```

## Project structure

- `server.py` is the backward-compatible executable and import facade.
- `pygithost/config.py` owns immutable configuration loading and validation.
- `pygithost/context.py` defines the dependencies passed into a server instance.
- `pygithost/rendering.py` owns safe HTML and t-string rendering.
- `pygithost/database.py` owns users, sessions, tokens, and pull requests.
- `pygithost/cli.py` owns command parsing and startup commands.
- `pygithost/application.py` contains the HTTP protocol, Git backend, and current
  feature handlers. New infrastructure modules should be kept free of
  request-handler state and added to `AppContext` when they need dependencies.

Programmatic startup uses explicit configuration instead of patching globals:

```python
from pygithost import AppConfig, AppContext, AsyncGitServer

config = AppConfig.from_file("pygithost.config.json")
app = AsyncGitServer(AppContext(config))
```

## Tests

Run the suite with the project virtual environment:

```sh
.venv/bin/python -m unittest discover -v
```

The integration tests use the real `git-http-backend` and bind a loopback port.
