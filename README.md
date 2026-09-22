# Checkmarx One Scan Automation

`scan_runner.py` batch-orchestrates the Checkmarx One CLI (`cx`) for a list of repositories defined in a CSV file. Point it at a CSV, and it will:

- Install the official Windows `cx` CLI automatically if it isn't already available
- Authenticate to your Checkmarx One tenant via browser login
- Run SAST, SCA, Secret Detection, and/or API Security scans for every repository in the CSV, sequentially or in parallel
- Write a per-repository log and report, plus a combined run-level manifest (JSON + CSV) summarizing every result

This repository is tenant-agnostic — it ships with example defaults that must be replaced with your own tenant's values before use. See [Required configuration](#required-configuration-before-your-first-run) below.

## Prerequisites

- Python 3.11 or newer (standard library only — no `pip install` needed, see `requirements.txt`)
- A Checkmarx One tenant you have access to, and permission to create/scan projects in it
- Repository access configured for your Git provider when private repositories are scanned (see [Private repositories](#private-repositories))
- Internet access on first run, to download `ast-cli_windows_x64.zip` (unless you pre-install `cx` yourself and pass `--no-auto-install`)

## Required configuration before your first run

This project was originally set up against one specific tenant and region. Before running it against **your** tenant, replace the following:

| What | Where it's used | How to set it |
|---|---|---|
| Tenant name | Checkmarx login (`cx auth login --tenant ...`) | `--tenant <name>` flag, or `CXONE_TENANT` env var. The built-in fallback (`cx_ps_sharma_a`, at [scan_runner.py:23](scan_runner.py#L23)) is just an example — set your own. |
| Base auth URI | Checkmarx login (`cx auth login --base-auth-uri ...`) | `--base-auth-uri <url>` flag, or `CXONE_BASE_AUTH_URI` env var. The built-in fallback (`https://ind.ast.checkmarx.net/`, at [scan_runner.py:24](scan_runner.py#L24)) is the India region — use the base URI for **your** Checkmarx region/instance. |
| Your project list | Which repos get scanned | Create your own CSV (copy `projects.example.csv` as a starting point) — see [CSV format](#csv-format). Do **not** rely on `projects.example.csv` or `sample-projects.csv` for real scans; both are documentation/demo fixtures. |
| Secret Detection token | `--scs-repo-token` | `CXONE_SCS_REPO_TOKEN` env var (or `--scs-repo-token`) — only needed if you include `scs` in `--scanners` (it's in the default scanner list). |
| Private repo tokens | `--file-source` (cloning) | One env var per private repo, referenced by name in the CSV's `repo_token_env` column — see [Private repositories](#private-repositories). |
| Tenant concurrency/license limit | Parallel mode batching | `--concurrency-limit <n>` flag, or `CXONE_CONCURRENCY_LIMIT` env var, if your tenant's limit isn't `10` — see [Parallel mode and concurrency limits](#parallel-mode-and-concurrency-limits). |
| Corporate proxy | Auth + scan commands | `--proxy` / `--proxy-auth-type`, or `CXONE_PROXY` / `CXONE_PROXY_AUTH_TYPE` env vars — only if your network requires one. |

Everything above can be supplied via flags or environment variables at run time — you do not need to edit `scan_runner.py` itself, except optionally to change the *default* tenant/base-auth-uri constants at the top of the file if you don't want to pass them on every run.

## CSV format

Required columns: `project_name`, `repository_url`, `branch`.
Optional columns: `api_spec_path` (relative path to an OpenAPI/Swagger spec, only used when `--scanners` includes `api`), `repo_token_env` (name of an environment variable holding a private-repo access token — see below).

```csv
project_name,repository_url,branch,api_spec_path,repo_token_env
payments-api,https://github.com/company/payments-api.git,main,,
customer-portal,https://github.com/company/customer-portal.git,main,docs/openapi.yaml,
```

Each `(project_name, branch)` pair must be unique in the CSV; the script validates this and fails fast if duplicated or if any required column/value is missing.

## Private repositories

For a private repository, add a `repo_token_env` value naming an environment variable that holds a GitHub personal access token — **never put the token itself in the CSV**. At run time, the script reads that environment variable and clones with the token embedded in the URL (`https://<token>@github.com/org/repo.git`). Each row can reference a different variable, so different repositories can use different tokens.

```csv
project_name,repository_url,branch,api_spec_path,repo_token_env
payments-api,https://github.com/company/payments-api.git,main,,PAYMENTS_API_TOKEN
```

```powershell
$env:PAYMENTS_API_TOKEN = "ghp_xxx"
python .\scan_runner.py --csv .\projects.csv
```

If a referenced environment variable is not set, the script fails **before starting any scans**, rather than partway through a run. The token is also masked (`<redacted>`) wherever the command is recorded in `run-manifest.json`, so it never leaks into the output.

This is unrelated to `CXONE_SCS_REPO_TOKEN`, which is a separate credential used only by the Secret Detection engine's own repository API calls (needed only when `scs` is one of the selected scanners).

## Authentication (browser login)

```powershell
python .\scan_runner.py --login --csv .\projects.csv --tenant <your-tenant> --base-auth-uri <your-base-auth-uri>
```

`--login` opens a browser for `cx auth login` before scanning starts, using whichever `--tenant`/`--base-auth-uri` are in effect. The Checkmarx CLI persists the resulting session locally, so subsequent runs typically don't need `--login` again until that session expires — omit it once you're already authenticated:

```powershell
python .\scan_runner.py --csv .\projects.csv --tenant <your-tenant> --base-auth-uri <your-base-auth-uri>
```

If a scan fails with an authentication error (visible in that project's `cli.log` and as `"status": "failed"` in the manifest), re-run with `--login`.

When `cx` isn't already installed or on `PATH`, the script downloads it automatically into `.tools/checkmarx` (gitignored) before doing anything else — this happens regardless of `--login`. Use `--no-auto-install` to require a pre-installed CLI instead, and `--cli-download-url` to point at an approved internal mirror.

## Choosing scanners

`--scanners` takes a comma-separated list. Default: `sast,sca,scs`.

| Scanner | CLI scan type | Notes |
|---|---|---|
| `sast` | `sast` | Static code analysis. `--preset <name>` selects a SAST preset; omitted means the Checkmarx project/account default. |
| `sca` | `sca` | Software composition analysis (dependencies). |
| `scs` | `scs` | Secret Detection only, via a hardcoded `--scs-engines secret-detection`. Requires `CXONE_SCS_REPO_TOKEN` (or `--scs-repo-token`); the script refuses to start if it's missing. Add `--git-commit-history` to scan Git history for secrets too. |
| `api` | `api-security` | Opt-in only — not in the default list. Requires an `api_spec_path` in the CSV row (maps to `--apisec-swagger-filter`). |

## Report formats

`--report` (default `summaryHTML`) accepts the CLI's actual supported formats: `summaryHTML`, `summaryConsole`, `markdown`, `json`, `json-v2`, `sarif`, `gl-sast`, `gl-sca`, `sbom`, `pdf`. PDF is not supported when `scs` is one of the selected scanners — the script rejects that combination up front.

## Running scans: sequential vs parallel

Sequential (default) — one project at a time, simplest to debug:

```powershell
python .\scan_runner.py --csv .\projects.csv --scanners sast,sca --mode sequential
```

Parallel — multiple projects at once:

```powershell
python .\scan_runner.py --csv .\projects.csv --scanners sast,sca --mode parallel --workers 3
```

### Parallel mode and concurrency limits

Your Checkmarx license controls how many scans can run **simultaneously** (`--concurrency-limit`, default `10`, or `CXONE_CONCURRENCY_LIMIT`). This is independent of how many repositories are in your CSV.

- If `--workers` exceeds `--concurrency-limit`, the script warns and caps `--workers` down to the limit — it will not knowingly start more concurrent scans than your license allows.
- If your CSV has **more projects than the concurrency limit**, the script does not error out or try to run them all at once. It automatically splits the project list into successive batches of at most `--workers` (≤ the limit), running one batch fully to completion before starting the next:

```
25 projects, --workers 10  ->  batch 1: projects 1-10 (parallel)
                               batch 2: projects 11-20 (parallel)
                               batch 3: projects 21-25 (parallel)
```

The script prints the effective worker count and each batch as it starts, so you can see this happening. If a different tenant has a different license limit than the default `10`, set it explicitly:

```powershell
python .\scan_runner.py --csv .\projects.csv --mode parallel --workers 20 --concurrency-limit 5
```

This example requests 20 workers but only 5 will actually run at once, in 5 batches of 5. Checkmarx may additionally queue scans server-side, but the script's own batching means it never *intentionally* exceeds the configured limit client-side.

## Proxy configuration

If your network requires a proxy, the same settings are forwarded to both the authentication and scan commands:

```powershell
$env:CXONE_PROXY = "http://proxy-host:proxy-port"
$env:CXONE_PROXY_AUTH_TYPE = "ntlm"
python .\scan_runner.py --login --csv .\projects.csv
```

Or pass them directly: `--proxy <url>` and `--proxy-auth-type` (one of `basic`, `ntlm`, `kerberos`, `kerberos-native`). Do not place passwords in source files or committed command history.

## Outputs

Everything is written under `--output-dir` (default `reports/`):

- `reports/<project_name>/cli.log` — combined stdout/stderr of that project's `cx scan create` call
- `reports/<project_name>/<project_name>.<ext>` — the CLI report in whichever `--report` format was requested
- `reports/run-manifest.json` — one entry per project: status (`completed`/`failed`), return code, report file path, the executed command (with secrets redacted), and any error text. Written once, after every project has finished.
- `reports/run-manifest.csv` — the same data flattened for spreadsheet use (omits the command column)

The script's own exit code is `0` only if every project in the run completed successfully; otherwise `1`. A malformed CSV, invalid flags, or a missing required token cause an early exit with code `2` before any scan starts.

## Full flag reference

| Flag | Env var fallback | Default | Purpose |
|---|---|---|---|
| `--csv` (required) | — | — | Path to the CSV of projects to scan |
| `--cli` | `CXONE_CLI` | `cx` | Path/name of the Checkmarx CLI executable |
| `--no-auto-install` | — | auto-install enabled | Fail instead of downloading `cx` if it's missing |
| `--cli-dir` | `CXONE_CLI_DIR` | `.tools/checkmarx` | Local install directory for an auto-installed CLI |
| `--cli-download-url` | `CXONE_CLI_DOWNLOAD_URL` | official GitHub release ZIP | Override for an approved internal mirror |
| `--tenant` | `CXONE_TENANT` | example tenant (replace it) | Checkmarx tenant name |
| `--base-auth-uri` | `CXONE_BASE_AUTH_URI` | example region URI (replace it) | Checkmarx IAM base URI for your region |
| `--proxy` | `CXONE_PROXY` | none | Corporate proxy URL |
| `--proxy-auth-type` | `CXONE_PROXY_AUTH_TYPE` | none | `basic` \| `ntlm` \| `kerberos` \| `kerberos-native` |
| `--scanners` | — | `sast,sca,scs` | Comma-separated: `sast`, `sca`, `scs`, `api` |
| `--scs-repo-token` | `CXONE_SCS_REPO_TOKEN` | none | Read-only repo token for Secret Detection |
| `--preset` | — | Checkmarx account default | SAST preset name |
| `--mode` | — | `sequential` | `sequential` \| `parallel` |
| `--workers` | — | `10` | Max concurrent scans this run will start; capped to `--concurrency-limit` |
| `--concurrency-limit` | `CXONE_CONCURRENCY_LIMIT` | `10` | Your tenant's licensed concurrent-scan limit |
| `--report` | — | `summaryHTML` | See [Report formats](#report-formats) |
| `--output-dir` | — | `reports` | Root directory for all output |
| `--login` | — | off | Open browser authentication before scanning |
| `--git-commit-history` | — | off | Include Git history in Secret Detection |
| `--timeout` | — | none | Cancel each scan after this many minutes |

## Notes

- `scs` is configured as Secret Detection only, via a hardcoded `--scs-engines secret-detection` — no other SCS engines are exposed.
- Checkmarx's account license controls concurrent scans server-side; `--workers`/`--concurrency-limit` only control what this script *intentionally* starts client-side (see [Parallel mode and concurrency limits](#parallel-mode-and-concurrency-limits)).
- API Security requires an API specification file present in the repository for that row; the optional `api_spec_path` maps to the CLI's `--apisec-swagger-filter` flag.
- `projects.example.csv` and `sample-projects.csv` are not real project lists — the former documents the CSV schema with fictional URLs, the latter is a working smoke-test fixture against real public GitHub repos. Use your own CSV for real scans.
