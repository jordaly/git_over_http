# git_over_http
A simple http server with no dependencies other that git to use the git-http-backend as a cgi with basic security for local git colaboration over http.

## requirements
Need to have git install so the http-backend its abilable in the expected route

```py
if CURRENT_PLATFORM == "Windows":
    GIT_PROJECT_ROOT = r"C:\Servidor_Git"
    GIT_HTTP_BACKEND = r"C:\Program Files\Git\mingw64\libexec\git-core\git-http-backend.exe"
    TRACE_LOG = r"C:\temp\git-http-backend.log"
    DB_PATH = r"C:\temp\pygithost.db"

elif CURRENT_PLATFORM == "Linux":
    GIT_PROJECT_ROOT = "/home/jordaly/git_repos"
    GIT_HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
    TRACE_LOG = None
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")

elif CURRENT_PLATFORM == "Darwin":
    git_project_path = Path.home() / "git"
    git_project_path.mkdir(exist_ok=True)
    GIT_PROJECT_ROOT = str(git_project_path)
    GIT_HTTP_BACKEND = "/opt/homebrew/opt/git/libexec/git-core/git-http-backend"
    TRACE_LOG = "/tmp/git-http-backend.log"
    DB_PATH = str(Path.home() / ".local/share/pygithost/pygithost.db")
```
