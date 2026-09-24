import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _valid_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    results = data.get("results", [])
    if isinstance(results, list):
        valid = [r for r in results if isinstance(r, dict) and r.get("verdict") == "VALID"]
        if valid:
            return valid
    findings = data.get("findings", [])
    if isinstance(findings, list):
        return [f for f in findings if isinstance(f, dict) and f.get("report_candidate") and f.get("classification") != "NOISE"]
    return []


def build_discord_payload(program: str, findings: list[dict[str, Any]], run_url: str = "") -> dict[str, Any] | None:
    if not findings:
        return None
    description_lines = []
    for item in findings[:5]:
        identifier = str(item.get("lead_id") or item.get("finding_id") or item.get("id", ""))[:120]
        reason = str(item.get("reason", ""))[:300]
        impact = str(item.get("impact", "") or item.get("classification", ""))[:200]
        klass = str(item.get("class") or item.get("classification") or "")[:40]
        header = f"**{identifier}**" + (f" `{klass}`" if klass else "")
        description_lines.append(f"{header}\n{reason}\n*Impact: {impact}*")
    description = "\n\n".join(description_lines)
    if len(findings) > 5:
        description += f"\n\n*+{len(findings) - 5} more*"
    embed: dict[str, Any] = {
        "title": f"VALID finding — {program} ({len(findings)} hit{'s' if len(findings) != 1 else ''})",
        "description": description[:4000],
        "color": 0x00FF7F,
        "fields": [
            {"name": "Program", "value": program, "inline": True},
            {"name": "Valid", "value": str(len(findings)), "inline": True},
        ],
    }
    if run_url:
        embed["fields"].append({"name": "Run", "value": run_url, "inline": False})
        embed["url"] = run_url
    return {"embeds": [embed], "username": "hunt-v2"}


def send_discord(webhook_url: str, payload: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    if not webhook_url or not webhook_url.startswith("https://"):
        raise ValueError("webhook_url must be https://")
    data = json.dumps(payload).encode("utf-8")
    request = Request(webhook_url, data=data, headers={"Content-Type": "application/json", "User-Agent": "hunt-v2-notifier/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return {"status": response.status, "body": body[:500]}
    except HTTPError as exc:
        raise RuntimeError(f"Discord webhook HTTP {exc.code}: {exc.read().decode('utf-8', errors='ignore')[:300]}") from exc
    except (URLError, OSError) as exc:
        raise RuntimeError(f"Discord webhook failed: {type(exc).__name__}") from exc


def notify_from_file(webhook_url: str, program: str, input_path: str, run_url: str = "") -> dict[str, Any]:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    findings = _valid_findings(data)
    if not findings:
        return {"skipped": True, "reason": "no VALID findings"}
    payload = build_discord_payload(program, findings, run_url)
    if not payload:
        return {"skipped": True, "reason": "no payload"}
    return send_discord(webhook_url, payload)


def main_cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Send VALID findings to Discord")
    parser.add_argument("--program", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--run-url", default="")
    parser.add_argument("--webhook-url", default=os.environ.get("DISCORD_WEBHOOK_URL", ""))
    args = parser.parse_args()
    webhook_url = args.webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
    if not webhook_url:
        print(json.dumps({"skipped": True, "reason": "no webhook url"}))
        return
    result = notify_from_file(webhook_url, args.program, args.input, args.run_url)
    print(json.dumps(result, indent=2))
