"""Batch orchestration for the installed Checkmarx One CLI."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit

TENANT = "cx_ps_sharma_a"
DEFAULT_BASE_AUTH_URI = "https://ind.ast.checkmarx.net/"
DEFAULT_CLI_DOWNLOAD_URL = "https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_windows_x64.zip"
DEFAULT_CLI_DIR = Path(".tools") / "checkmarx"
DEFAULT_CONCURRENCY_LIMIT = 10
SUPPORTED_SCANNERS = {"sast", "sca", "api", "scs"}
SCANNER_TYPES = {
    "sast": "sast",
    "sca": "sca",
    "api": "api-security",
    "scs": "scs",
}
SUPPORTED_REPORTS = {
    "summaryHTML",
    "summaryConsole",
    "markdown",
    "json",
    "json-v2",
    "sarif",
    "gl-sast",
    "gl-sca",
    "sbom",
    "pdf",
}


@dataclass(frozen=True)
class Project:
    project_name: str
    repository_url: str
    branch: str
    api_spec_path: str = ""
    repo_token_env: str = ""


@dataclass
class Result:
    project_name: str
    repository_url: str
    branch: str
    status: str
    return_code: int | None = None
    report_file: str = ""
    command: list[str] | None = None
    error: str = ""


def parse_csv(path: Path) -> list[Project]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required = {"project_name", "repository_url", "branch"}
        fields = set(reader.fieldnames or [])
        missing = required - fields
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")

        projects: list[Project] = []
        seen: set[tuple[str, str]] = set()
        for line_number, row in enumerate(reader, start=2):
            project = Project(
                project_name=(row.get("project_name") or "").strip(),
                repository_url=(row.get("repository_url") or "").strip(),
                branch=(row.get("branch") or "").strip(),
                api_spec_path=(row.get("api_spec_path") or "").strip(),
                repo_token_env=(row.get("repo_token_env") or "").strip(),
            )
            if not all((project.project_name, project.repository_url, project.branch)):
                raise ValueError(f"CSV row {line_number} must contain project_name, repository_url, and branch")
            key = (project.project_name.casefold(), project.branch.casefold())
            if key in seen:
                raise ValueError(f"Duplicate project_name and branch in CSV row {line_number}")
            seen.add(key)
            projects.append(project)

    if not projects:
        raise ValueError("CSV does not contain any projects")
    return projects


def parse_scanners(value: str) -> list[str]:
    scanners = [item.strip().lower() for item in value.split(",") if item.strip()]
    invalid = set(scanners) - SUPPORTED_SCANNERS
    if not scanners or invalid:
        choices = ", ".join(sorted(SUPPORTED_SCANNERS))
        raise ValueError(f"Unsupported scanner(s): {', '.join(sorted(invalid))}. Choose from: {choices}")
    return list(dict.fromkeys(scanners))


def validate_repo_tokens(projects: list[Project]) -> None:
    missing = sorted({
        project.repo_token_env
        for project in projects
        if project.repo_token_env and not os.environ.get(project.repo_token_env)
    })
    if missing:
        raise ValueError(f"Missing environment variable(s) referenced by repo_token_env: {', '.join(missing)}")


def mask_url_credentials(url: str) -> str:
    parsed = urlsplit(url)
    if "@" not in parsed.netloc:
        return url
    _, _, host = parsed.netloc.rpartition("@")
    return urlunsplit(parsed._replace(netloc=f"<redacted>@{host}"))


def inject_repo_token(url: str, token: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError(f"repo_token_env requires an https:// repository_url, got: {url}")
    return urlunsplit(parsed._replace(netloc=f"{token}@{parsed.netloc}"))


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    mask_next_url = False
    for item in command:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
        elif mask_next_url:
            redacted.append(mask_url_credentials(item))
            mask_next_url = False
        else:
            redacted.append(item)
        if item == "--scs-repo-token":
            redact_next = True
        elif item == "--file-source":
            mask_next_url = True
    return redacted


def run_command(command: Sequence[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def ensure_cli(args: argparse.Namespace) -> str:
    """Return an available CLI path, installing the official Windows build if needed."""
    requested = Path(args.cli)
    if requested.exists():
        return str(requested)
    discovered = shutil.which(args.cli)
    if discovered:
        return discovered
    if not args.auto_install:
        raise FileNotFoundError(
            f"Checkmarx CLI '{args.cli}' was not found. Install it or remove --no-auto-install."
        )
    if sys.platform != "win32":
        raise RuntimeError("Automatic CLI installation currently supports Windows only")

    install_dir = args.cli_dir.resolve()
    install_dir.mkdir(parents=True, exist_ok=True)
    executable = install_dir / "cx.exe"
    if not executable.exists():
        print(f"Downloading Checkmarx CLI to {install_dir}...")
        with tempfile.TemporaryDirectory() as temporary_dir:
            archive = Path(temporary_dir) / "ast-cli_windows_x64.zip"
            try:
                urllib.request.urlretrieve(args.cli_download_url, archive)
                with zipfile.ZipFile(archive) as package:
                    package.extractall(install_dir)
            except (OSError, urllib.error.URLError, zipfile.BadZipFile) as error:
                raise RuntimeError(f"Could not download or extract the Checkmarx CLI: {error}") from error
        candidates = list(install_dir.rglob("cx.exe"))
        if not candidates:
            raise RuntimeError(f"The downloaded archive did not contain cx.exe: {args.cli_download_url}")
        if candidates[0] != executable:
            shutil.copy2(candidates[0], executable)
    return str(executable)


def authenticate(args: argparse.Namespace) -> None:
    command = [
        args.cli,
        "auth",
        "login",
        "--base-auth-uri",
        args.base_auth_uri,
        "--tenant",
        args.tenant,
    ]
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    if args.proxy_auth_type:
        command.extend(["--proxy-auth-type", args.proxy_auth_type])
    print("Opening the Checkmarx browser login...")
    completed = subprocess.run(command, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Authentication failed with exit code {completed.returncode}")


def build_scan_command(
    args: argparse.Namespace,
    project: Project,
    scanners: list[str],
    report_dir: Path,
) -> list[str]:
    file_source = project.repository_url
    if project.repo_token_env:
        token = os.environ.get(project.repo_token_env)
        if not token:
            raise ValueError(
                f"Environment variable '{project.repo_token_env}' referenced by project "
                f"'{project.project_name}' is not set"
            )
        file_source = inject_repo_token(file_source, token)
    command = [
        args.cli,
        "scan",
        "create",
        "--project-name",
        project.project_name,
        "--branch",
        project.branch,
        "--file-source",
        file_source,
        "--scan-types",
        ",".join(SCANNER_TYPES[item] for item in scanners),
        "--report-format",
        args.report,
        "--output-path",
        str(report_dir),
        "--output-name",
        project.project_name,
    ]
    if args.preset:
        command.extend(["--sast-preset-name", args.preset])
    if "scs" in scanners:
        command.extend([
            "--scs-engines",
            "secret-detection",
            "--scs-repo-url",
            project.repository_url,
            "--scs-repo-token",
            args.scs_repo_token,
        ])
        if args.git_commit_history:
            command.extend(["--git-commit-history", "true"])
    if "api" in scanners and project.api_spec_path:
        command.extend(["--apisec-swagger-filter", project.api_spec_path])
    if args.timeout:
        command.extend(["--scan-timeout", str(args.timeout)])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    if args.proxy_auth_type:
        command.extend(["--proxy-auth-type", args.proxy_auth_type])
    return command


def run_project(args: argparse.Namespace, project: Project, scanners: list[str], output_dir: Path) -> Result:
    project_dir = output_dir / project.project_name
    project_dir.mkdir(parents=True, exist_ok=True)
    command = build_scan_command(args, project, scanners, project_dir)
    completed = run_command(command)
    combined_output = (completed.stdout + "\n" + completed.stderr).strip()
    (project_dir / "cli.log").write_text(combined_output + "\n", encoding="utf-8")
    report_files = [path for path in project_dir.iterdir() if path.name != "cli.log"]
    report_file = str(report_files[0]) if len(report_files) == 1 else ""
    return Result(
        project_name=project.project_name,
        repository_url=project.repository_url,
        branch=project.branch,
        status="completed" if completed.returncode == 0 else "failed",
        return_code=completed.returncode,
        report_file=report_file,
        command=redact_command(command),
        error=completed.stderr.strip() if completed.returncode else "",
    )


def write_manifest(results: list[Result], output_dir: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [asdict(result) for result in results],
    }
    (output_dir / "run-manifest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    with (output_dir / "run-manifest.csv").open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=["project_name", "repository_url", "branch", "status", "return_code", "report_file", "error"])
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row.pop("command", None)
            writer.writerow(row)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Checkmarx One CLI scans for repositories listed in a CSV file.")
    parser.add_argument("--csv", type=Path, required=True, help="CSV containing project_name, repository_url, and branch")
    parser.add_argument("--cli", default=os.environ.get("CXONE_CLI", "cx"), help="Installed Checkmarx CLI executable")
    parser.add_argument("--no-auto-install", dest="auto_install", action="store_false", help="Fail instead of downloading the CLI when it is missing")
    parser.add_argument("--cli-dir", type=Path, default=Path(os.environ.get("CXONE_CLI_DIR", DEFAULT_CLI_DIR)), help="Local directory for an automatically installed CLI")
    parser.add_argument("--cli-download-url", default=os.environ.get("CXONE_CLI_DOWNLOAD_URL", DEFAULT_CLI_DOWNLOAD_URL), help="Official CLI ZIP URL")
    parser.add_argument("--tenant", default=os.environ.get("CXONE_TENANT", TENANT))
    parser.add_argument("--base-auth-uri", default=os.environ.get("CXONE_BASE_AUTH_URI", DEFAULT_BASE_AUTH_URI))
    parser.add_argument("--proxy", default=os.environ.get("CXONE_PROXY"), help="Optional corporate proxy URL")
    parser.add_argument("--proxy-auth-type", choices=("basic", "ntlm", "kerberos", "kerberos-native"), default=os.environ.get("CXONE_PROXY_AUTH_TYPE"), help="Optional proxy authentication type")
    parser.add_argument("--scanners", default="sast,sca,scs", help="Comma-separated list: sast, sca, scs (api is available as an opt-in)")
    parser.add_argument("--scs-repo-token", default=os.environ.get("CXONE_SCS_REPO_TOKEN"), help="Read-only repository token for Secret Detection; prefer CXONE_SCS_REPO_TOKEN")
    parser.add_argument("--preset", help="SAST preset name; omitted means the configured Checkmarx default")
    parser.add_argument("--mode", choices=("sequential", "parallel"), default="sequential")
    parser.add_argument("--workers", type=int, default=10, help="Maximum concurrent project scans; never exceeds --concurrency-limit")
    parser.add_argument("--concurrency-limit", type=int, default=int(os.environ.get("CXONE_CONCURRENCY_LIMIT", DEFAULT_CONCURRENCY_LIMIT)), help="Tenant license concurrency limit (default: 10)")
    parser.add_argument("--report", default="summaryHTML", choices=sorted(SUPPORTED_REPORTS))
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--login", action="store_true", help="Open browser authentication before scanning")
    parser.add_argument("--git-commit-history", action="store_true", help="Include Git history in Secret Detection")
    parser.add_argument("--timeout", type=int, help="Cancel each scan after this many minutes")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        projects = parse_csv(args.csv)
        scanners = parse_scanners(args.scanners)
        validate_repo_tokens(projects)
        if "scs" in scanners and not args.scs_repo_token:
            raise ValueError("Secret Detection requires CXONE_SCS_REPO_TOKEN or --scs-repo-token")
        if args.report == "pdf" and "scs" in scanners:
            raise ValueError("The Checkmarx CLI does not support PDF reports for SCS scans")
        if args.concurrency_limit < 1:
            raise ValueError("--concurrency-limit must be at least 1")
        if args.workers < 1:
            raise ValueError("--workers must be at least 1")
        if args.workers > args.concurrency_limit:
            print(
                f"Requested {args.workers} workers, but the configured tenant limit is "
                f"{args.concurrency_limit}; using {args.concurrency_limit}.",
                file=sys.stderr,
            )
            args.workers = args.concurrency_limit
        if args.mode == "parallel" and args.workers > len(projects):
            args.workers = len(projects)
        if args.mode == "parallel":
            print(f"Parallel mode: at most {args.workers} project scans will run at once (tenant limit: {args.concurrency_limit}).")
        args.cli = ensure_cli(args)
        if args.login:
            authenticate(args)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        results: list[Result] = []
        if args.mode == "parallel":
            for batch_start in range(0, len(projects), args.workers):
                batch = projects[batch_start:batch_start + args.workers]
                batch_number = batch_start // args.workers + 1
                print(f"Starting scan batch {batch_number} with {len(batch)} project(s).")
                with ThreadPoolExecutor(max_workers=args.workers) as executor:
                    futures = [executor.submit(run_project, args, project, scanners, args.output_dir) for project in batch]
                    for future in as_completed(futures):
                        result = future.result()
                        results.append(result)
                        print(f"[{result.status}] {result.project_name}")
        else:
            for project in projects:
                result = run_project(args, project, scanners, args.output_dir)
                results.append(result)
                print(f"[{result.status}] {result.project_name}")
        results.sort(key=lambda result: result.project_name.casefold())
        write_manifest(results, args.output_dir)
    except (OSError, ValueError, RuntimeError, FileNotFoundError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0 if all(result.status == "completed" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
