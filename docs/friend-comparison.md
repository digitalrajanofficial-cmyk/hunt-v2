# Friend Repository Cross-Reference

Reference implementation: [riteshekbote/threema-hunt](https://github.com/riteshekbote/threema-hunt) and [riteshekbote/gladia-hunt](https://github.com/riteshekbote/gladia-hunt), reviewed as public repositories.

## Parity retained

- Scheduled GitHub Actions execution
- Passive inventory and endpoint collection
- Delta-oriented repeat runs
- Model-generated candidate leads
- Independent triage before reporting
- Human review before submission
- Artifact-based evidence review

## Improvements over the reference

| Area | Reference workflow | Hunt-v2 decision |
|---|---|---|
| Authorization | Scope text and environment allowlists | Per-program JSON policy with exact hosts, methods, ports, rate limits, and HTTPS requirements |
| State | Git commits and Markdown files | SQLite ledger plus Actions cache and downloadable artifacts |
| Model output | Regex parsing of Markdown blocks | Strict JSON validation with failure-triggered model fallback |
| Model reliability | Rotating model configuration | Rotational free-model pool, health cooldowns, timeout handling, and distinct second model |
| SSRF resistance | Host allowlist probing | Scope validation, public-IP resolution, pinned connection address, private/metadata blocking, and redirect denial |
| Repeat efficiency | Full context is repeatedly processed | Meaningful delta detection ignores observation timestamps and skips unchanged model calls |
| Publication | Automated issue synchronization | Model output cannot publish; only explicitly approved JSON can create an issue |
| Target breadth | Many per-program repositories | One reusable pipeline with per-program configuration |

## Deliberate trade-offs

- The reference has more deployed targets and longer operational history.
- Hunt-v2 initially uses explicit seed URLs and passive tool-file adapters; it does not silently expand scope.
- A free-model pool reduces cost but does not guarantee unlimited availability. Paid Zen models can be added to the same pool.
- TLS errors are recorded and surfaced; certificate verification is never disabled.

## Remaining parity work

- Add passive subfinder, dnsx, httpx, and URL export producers.
- Add authenticated test-account workflows with secret-backed session handling.
- Add OOB evidence adapters for approved test cases.
- Add report quality metrics and payout feedback loops.
- Add multi-program matrix execution from one configuration set.
