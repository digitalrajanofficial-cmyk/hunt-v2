import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scope import ScopeError, ScopePolicy


class ReconToolError(RuntimeError):
    pass


def recon_roots(policy: ScopePolicy) -> list[str]:
    roots = []
    for host in policy.allowed_hosts:
        value = host[2:] if host.startswith("*.") else host
        if "." in value and value not in roots:
            roots.append(value)
    if not roots:
        raise ReconToolError("scope contains no domain root for passive enumeration")
    return roots


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ReconToolError(f"required recon tool is not installed: {name}")
    return path


def run_command(command: list[str], output_path: Path | None = None) -> None:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:500]
        raise ReconToolError(f"{command[0]} failed: {detail}")
    if output_path is not None and output_path.exists():
        return
    if output_path is not None and completed.stdout:
        output_path.write_text(completed.stdout, encoding="utf-8")


def write_filtered_subfinder(policy: ScopePolicy, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = output_dir / "subfinder.raw.txt"
    filtered = output_dir / "subfinder.txt"
    roots = recon_roots(policy)
    tool = require_tool("subfinder")
    collected = []
    for root in roots:
        run_command([tool, "-d", root, "-silent"], raw)
        if raw.exists():
            collected.extend(line.strip().lower() for line in raw.read_text(encoding="utf-8").splitlines() if line.strip())
    hosts = []
    for host in collected:
        host = host.rstrip(".")
        if policy.host_allowed(host) and host not in hosts:
            hosts.append(host)
    filtered.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    raw.unlink(missing_ok=True)
    return len(hosts)


def run_dnsx(input_path: Path, output_path: Path) -> int:
    tool = require_tool("dnsx")
    run_command(
        [
            tool,
            "-l",
            str(input_path),
            "-silent",
            "-json",
            "-rate-limit",
            "1",
            "-retry",
            "1",
            "-o",
            str(output_path),
        ]
    )
    return sum(1 for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()) if output_path.exists() else 0


def run_httpx(input_path: Path, output_path: Path) -> int:
    tool = require_tool("httpx")
    run_command(
        [
            tool,
            "-l",
            str(input_path),
            "-silent",
            "-json",
            "-rate-limit",
            "1",
            "-threads",
            "1",
            "-retries",
            "1",
            "-timeout",
            "10",
            "-o",
            str(output_path),
        ]
    )
    return sum(1 for line in output_path.read_text(encoding="utf-8").splitlines() if line.strip()) if output_path.exists() else 0


def write_passive_urls(policy: ScopePolicy, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    urls = []
    roots = recon_roots(policy)

    def add_urls(lines: list[str]) -> None:
        for line in lines:
            url = line.strip()
            if not url:
                continue
            try:
                policy.validate_url(url)
            except ScopeError:
                continue
            if url not in urls:
                urls.append(url)

    for name, command in (("gau", [require_tool("gau"), "--subs"]), ("waybackurls", [require_tool("waybackurls")])):
        completed = subprocess.run(command, input="\n".join(roots), text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[:500]
            raise ReconToolError(f"{name} failed: {detail}")
        add_urls(completed.stdout.splitlines())

    waymore = require_tool("waymore")
    for root in roots:
        raw = output_dir / f"waymore.{root}.raw.txt"
        raw.unlink(missing_ok=True)
        run_command([waymore, "-i", root, "-mode", "U", "-oU", str(raw)], raw)
        if raw.exists():
            add_urls(raw.read_text(encoding="utf-8").splitlines())
        raw.unlink(missing_ok=True)

    (output_dir / "urls.txt").write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return len(urls)


def run_safe_recon(policy: ScopePolicy, output_dir: str, run_dns: bool = True, run_http: bool = True, run_urls: bool = False) -> dict[str, Any]:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    subfinder_count = write_filtered_subfinder(policy, root)
    host_file = root / "subfinder.txt"
    dnsx_count = 0
    httpx_count = 0
    passive_url_count = 0
    if run_dns and subfinder_count:
        dnsx_count = run_dnsx(host_file, root / "dnsx.jsonl")
    if run_http and subfinder_count:
        httpx_count = run_httpx(host_file, root / "httpx.jsonl")
    if run_urls:
        passive_url_count = write_passive_urls(policy, root)
    summary = {
        "program": policy.program,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": recon_roots(policy),
        "scope_filtered_subdomains": subfinder_count,
        "dnsx_records": dnsx_count,
        "httpx_records": httpx_count,
        "passive_urls": passive_url_count,
        "tools": {"subfinder": True, "dnsx": run_dns, "httpx": run_http, "gau": run_urls, "waybackurls": run_urls, "waymore": run_urls},
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
