# Checkmarx One Scan Automation

This project orchestrates the Checkmarx One CLI. If `cx` is not already available, it downloads the official Windows CLI release into `.tools/checkmarx` and uses it for the current run.

## Prerequisites

- Python 3.11 or newer
- Access to tenant `cx_ps_sharma_a`
- Repository access configured for the Git provider when private repositories are scanned

The first run requires internet access to download the official `ast-cli_windows_x64.zip` release. Use `--no-auto-install` to require a pre-installed CLI instead. The download URL can be overridden with `--cli-download-url` for an approved internal mirror.

If the corporate network requires a proxy, provide the proxy URL and optional authentication type. The script forwards these settings to both authentication and scan commands:

```powershell
$env:CXONE_PROXY = "http://proxy-host:proxy-port"
$env:CXONE_PROXY_AUTH_TYPE = "ntlm"
python .\scan_runner.py --login --csv .\projects.csv
```

The same settings can be passed directly with `--proxy` and `--proxy-auth-type`. Do not place passwords in source files or committed command history.

## CSV format

Required columns are `project_name`, `repository_url`, and `branch`. `api_spec_path` is optional and is relative to the repository root when API Security is selected. `repo_token_env` is optional and only needed for private repositories.

```csv
project_name,repository_url,branch,api_spec_path
payments-api,https://github.com/company/payments-api.git,main,
customer-portal,https://github.com/company/customer-portal.git,main,docs/openapi.yaml
```

## Private repositories

For a private repository, add a `repo_token_env` column with the **name** of an environment variable that holds a GitHub personal access token — never put the token itself in the CSV. The script reads that environment variable at run time and clones with `https://<token>@github.com/...`. Each row can reference a different variable, so different repositories can use different tokens.

```csv
project_name,repository_url,branch,api_spec_path,repo_token_env
payments-api,https://github.com/company/payments-api.git,main,,PAYMENTS_API_TOKEN
```

```powershell
$env:PAYMENTS_API_TOKEN = "ghp_xxx"
python .\scan_runner.py --csv .\projects.csv
```

If a referenced environment variable is not set, the script fails before starting any scans rather than partway through a run. This is unrelated to `CXONE_SCS_REPO_TOKEN`, which is a separate credential used only by the Secret Detection engine's own repository API calls.

## Browser login and scan

```powershell
python .\scan_runner.py --login --csv .\projects.example.csv
```

When `cx` is missing, the script installs it locally and then opens the browser login. The installed executable is kept under `.tools/checkmarx`, which is excluded from source control.

Browser login uses the existing CLI command:

```powershell
cx auth login --base-auth-uri https://ind.ast.checkmarx.net/ --tenant cx_ps_sharma_a
```

After login, the script submits scans directly from repository URLs. A project name that does not yet exist is handled by the CLI scan flow.

## Examples

Run SAST, SCA, and Secret Detection sequentially and produce HTML summaries:

```powershell
$env:CXONE_SCS_REPO_TOKEN = "your-read-only-repository-token"
python .\scan_runner.py --csv .\projects.example.csv --scanners sast,sca,scs --mode sequential --report summaryHTML
```

Run projects in parallel with JSON reports:

```powershell
python .\scan_runner.py --csv .\projects.example.csv --scanners sast,sca,scs --mode parallel --workers 3 --report json
```

The configured tenant concurrency limit defaults to `10`. Parallel runs are submitted in batches and never start more than that many project scans at once. The script displays the effective limit before starting. If another tenant has a different license limit, set it explicitly:

```powershell
python .\scan_runner.py --csv .\projects.csv --mode parallel --workers 20 --concurrency-limit 5
```

The command will warn and cap execution at 5 workers. You can also set `CXONE_CONCURRENCY_LIMIT`. Checkmarx may queue scans server-side as well, but the script avoids intentionally exceeding the configured tenant limit.

Secret Detection requires a repository token with read permission. Store it in `CXONE_SCS_REPO_TOKEN`; the token is passed to the CLI at runtime and redacted from the generated manifest. API Security is currently opt-in with `--scanners api` and remains excluded from the default scanner list.

If `--preset` is omitted, the Checkmarx project/account default is used. To select a SAST preset:

```powershell
python .\scan_runner.py --csv .\projects.example.csv --preset MyPreset --report json
```

Outputs are written under `reports/<project-name>/`. Each project directory contains the CLI report and `cli.log`; the run root contains `run-manifest.json` and `run-manifest.csv`.

Supported report values are the Checkmarx CLI formats: `summaryHTML`, `summaryConsole`, `markdown`, `json`, `json-v2`, `sarif`, `gl-sast`, `gl-sca`, `sbom`, and `pdf`. PDF is not supported for SCS scans.

## Notes

- `scs` is configured as Secret Detection only through `--scs-engines secret-detection`.
- Checkmarx's account license controls concurrent scans. The `--workers` value controls how many repository scan commands this script starts at once.
- API Security requires an API specification in the repository for the relevant row. The optional `api_spec_path` maps to the CLI's `--apisec-swagger-filter` flag.


# In order to run the script
# python .\scan_runner.py --login --csv .\sample-projects.csv --scanners sast,sca
# python .\scan_runner.py --login --csv .\sample-projects.csv --scanners sast,sca --mode parallel --workers 3
