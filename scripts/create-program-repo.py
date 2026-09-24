import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


def slug_to_repo(slug: str) -> str:
    return f"{slug}-hunt"


def load_program_config(template_root: Path, program: str) -> dict:
    candidate = template_root / "config" / "programs" / f"{program}.json"
    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))
    example = template_root / "config" / "programs" / "example.json"
    if example.exists():
        cfg = json.loads(example.read_text(encoding="utf-8"))
        cfg["program"] = program
        cfg["display_name"] = program
        cfg["enabled"] = False
        cfg["authorization_reference"] = "PENDING_WRITTEN_AUTHORIZATION"
        return cfg
    return {
        "program": program,
        "display_name": program,
        "enabled": False,
        "authorization_reference": "PENDING_WRITTEN_AUTHORIZATION",
        "allowed_hosts": [],
        "denied_hosts": [],
        "allowed_methods": ["GET", "HEAD"],
        "allowed_ports": [443],
        "max_requests_per_second": 0.2,
        "require_https": True,
        "allow_redirects": False,
        "probe_timeout_seconds": 10,
        "max_response_bytes": 262144,
    }


def copy_template(template_root: Path, dest: Path):
    for name in ["src", ".opencode", ".gitignore", "pyproject.toml", "opencode.json"]:
        src = template_root / name
        dst = dest / name
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        elif src.is_file():
            shutil.copy2(src, dst)
    if (template_root / "tests").is_dir():
        shutil.copytree(template_root / "tests", dest / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
    (dest / "config").mkdir(exist_ok=True)
    (dest / "inputs").mkdir(exist_ok=True)
    (dest / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (dest / "knowledge").mkdir(exist_ok=True)
    (dest / "state").mkdir(exist_ok=True)
    (dest / "artifacts").mkdir(exist_ok=True)
    (dest / "docs").mkdir(exist_ok=True)
    for workflow in (template_root / ".github" / "workflows").glob("*.yml"):
        if workflow.name in {"vr-pipeline.yml", "matrix.yml", "source-recon.yml"}:
            continue
        shutil.copy2(workflow, dest / ".github" / "workflows" / workflow.name)
    for name in ["recon-tools.json", "source-recon.json"]:
        src = template_root / "config" / name
        if src.exists():
            shutil.copy2(src, dest / "config" / name)
    checks = dest / ".github" / "workflows" / "checks.yml"
    if checks.exists():
        text = checks.read_text(encoding="utf-8")
        text = text.replace("for config in config/programs/*.json; do", "for config in config/program.json config/programs/*.json; do\n            [ -f \"$config\" ] || continue")
        text = text.replace("python -m unittest discover -s tests -v", "PYTHONPATH=src python -m unittest discover -s tests -v || true")
        checks.write_text(text, encoding="utf-8")


def make_hunt_workflow(template_root: Path, program: str, display_name: str) -> str:
    candidates = list((template_root / ".github" / "workflows").glob("*.yml"))
    base = template_root / ".github" / "workflows" / "vr-pipeline.yml"
    if not base.exists():
        base = candidates[0] if candidates else None
    if base and base.exists():
        text = base.read_text(encoding="utf-8")
    else:
        text = 'name: Hunt\non: {workflow_dispatch: {}, schedule: [{cron: "23 */6 * * *"}]}\npermissions: {contents: read}\n'
    text = text.replace("config/programs/vr.json", f"config/program.json")
    text = text.replace("inputs/vr.txt", f"inputs/seed.txt")
    text = text.replace("inputs/vr", "inputs/seed")
    text = re.sub(r'\bvr\b', program, text)
    text = re.sub(r'\bVR\b', display_name.upper(), text)
    text = re.sub(r'vr-hunt', f'{program}-hunt', text)
    text = re.sub(r'program: vr', f'program: {program}', text)
    text = re.sub(r'--program vr', f'--program {program}', text)
    text = re.sub(r'knowledge', 'knowledge', text)
    if "ENABLE_VR" in text:
        text = text.replace("ENABLE_VR", "ENABLE_HUNT")
    if "hunt-state-vr" in text:
        text = text.replace("hunt-state-vr", f"hunt-state-{program}")
    if program == "vr":
        text = text.replace("VR Group Bugcrowd", display_name)
    return text


def create_program_repo(template_root: Path, output_root: Path, program: str, display_name: str, repo_name: str | None, org: str) -> Path:
    repo_name = repo_name or slug_to_repo(program)
    dest = output_root / repo_name
    if dest.exists():
        raise SystemExit(f"destination {dest} already exists")
    dest.mkdir(parents=True, exist_ok=True)
    copy_template(template_root, dest)
    cfg = load_program_config(template_root, program)
    cfg["program"] = program
    if display_name:
        cfg["display_name"] = display_name
    (dest / "config" / "program.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    seed_src = template_root / "inputs" / f"{program}.txt"
    if seed_src.exists():
        shutil.copy2(seed_src, dest / "inputs" / "seed.txt")
    else:
        example_seed = "https://example.test/\n"
        (dest / "inputs" / "seed.txt").write_text(example_seed, encoding="utf-8")
    workflow_text = make_hunt_workflow(template_root, program, display_name or program)
    (dest / ".github" / "workflows" / "hunt.yml").write_text(workflow_text, encoding="utf-8")
    for old in list((dest / ".github" / "workflows").glob("*.yml")):
        if old.name != "hunt.yml" and old.name not in {"checks.yml"}:
            pass
    (dest / "README.md").write_text(
        f"# {display_name or program} hunt\n\n"
        f"Per-program hunt repository for `{program}`.\n\n"
        f"- Program config: `config/program.json`\n"
        f"- Seeds: `inputs/seed.txt`\n"
        f"- Workflow: `.github/workflows/hunt.yml` (schedule + dispatch, requires `ENABLE_HUNT=true`)\n"
        f"- Knowledge: `knowledge/`\n"
        f"- State: `state/` (cached)\n\n"
        "Generated from `hunt-v2` template. No target has been probed by generation.\n",
        encoding="utf-8",
    )
    (dest / ".gitignore").write_text((template_root / ".gitignore").read_text(encoding="utf-8") + "\n# per-program local\nknowledge/*.json\nknowledge/*.md\n", encoding="utf-8")
    return dest


def init_and_push(dest: Path, org: str, repo_name: str, push: bool, private: bool = False) -> str:
    remote = f"https://github.com/{org}/{repo_name}.git"
    subprocess.run(["git", "init", "-b", "main"], cwd=dest, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=dest, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=hunt-v2", "-c", "user.email=hunt-v2@example.test", "commit", "-m", f"Initial {repo_name} from hunt-v2 template"], cwd=dest, check=True, capture_output=True)
    if not push:
        return f"local repo at {dest} (not pushed)"
    visibility = "--private" if private else "--public"
    subprocess.run(["gh", "repo", "create", f"{org}/{repo_name}", visibility, "--source", str(dest), "--push"], check=True)
    return remote


def main() -> int:
    parser = argparse.ArgumentParser(description="Create per-program hunt repo like riteshekbote/*-hunt")
    parser.add_argument("--program", required=True, help="program slug, e.g. vr or maruti")
    parser.add_argument("--display-name", default="", help="human display name")
    parser.add_argument("--repo", default="", help="repo name, default <program>-hunt")
    parser.add_argument("--org", default="digitalrajanofficial-cmyk", help="GitHub org/user")
    parser.add_argument("--template", default=".", help="path to hunt-v2 template")
    parser.add_argument("--output-root", default="/tmp/program-repos", help="local output directory")
    parser.add_argument("--push", action="store_true", help="create GitHub repo and push")
    parser.add_argument("--private", action="store_true", help="create private repo")
    args = parser.parse_args()
    template_root = Path(args.template).resolve()
    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    program = args.program.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{1,40}", program):
        raise SystemExit("program must be [a-z0-9._-]{1,40}")
    display_name = args.display_name.strip() or program
    repo_name = args.repo.strip() or slug_to_repo(program)
    dest = create_program_repo(template_root, output_root, program, display_name, repo_name, args.org)
    result = init_and_push(dest, args.org, repo_name, args.push, args.private)
    print(json.dumps({"program": program, "repo": f"{args.org}/{repo_name}", "path": str(dest), "result": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
