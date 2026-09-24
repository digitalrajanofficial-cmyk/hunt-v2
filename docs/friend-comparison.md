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
| Recon execution | Recon jobs and public-repository scans | Opt-in subfinder → scope filter → rate-limited dnsx/httpx producer plus allowlisted, sanitized GitHub source-recon workflow |
| Publication | Automated issue synchronization | Model output cannot publish; only explicitly approved JSON can create an issue |
| RAG context | Ad-hoc prior hypothesis text | Structured `knowledge/<program>.json` + keyword retrieval into prompts |
| Hypothesis verification | Passive GET/HEAD probes | Scope-checked verifier with rate limiting, auth-aware, OOB-aware |
| State | Implicit phase via git history | Explicit state machine persisted in `state/<program>-state.json` |
| Authenticated evidence | No standardized auth handling | `auth.py` provider reads secret env vars only for `AUTH_HELPED` leads |
| OOB validation | No OOB harness | `oob.py` token lifecycle with Interactsh poll support |
| Feedback | Manual triage count | `feedback.py` metrics + automatic knowledge updates |
| Target breadth | Many per-program repositories | One reusable pipeline with per-program configuration |

## Public-source recon parity

- `source-recon.yml` provides an opt-in scheduled/manual workflow for explicitly allowlisted GitHub organizations and repositories.
- The scanner enumerates public repositories, applies size/language/archive/fork limits, performs bounded shallow clones, and scans source/config files for secret and endpoint indicators.
- Secret matches are represented only by a SHA-256 digest and `[REDACTED]`; URL query strings, fragments, and embedded credentials are removed before artifacts or model prompts.
- `source` model analysis is schema-validated and cannot publish findings directly.
- The checked-in configuration is disabled until an authorized organization or repository list is supplied; set `ENABLE_SOURCE_RECON=true` only after that configuration is reviewed.

## Deliberate trade-offs

- The reference has more deployed targets and longer operational history.
- Hunt-v2 initially uses explicit seed URLs and passive tool-file adapters; it does not silently expand scope.
- A free-model pool reduces cost but does not guarantee unlimited availability. Paid Zen models can be added to the same pool.
- TLS errors are recorded and surfaced; certificate verification is never disabled.

## Methodology hardening

The reference prompt describes an eight-step analyst loop and a seven-question triage gate, but stores the result as model-generated Markdown. Hunt-v2 now makes the important parts executable:

- Model-generated leads require priority scores, evidence needs, a read-only next action, and testability classification.
- `VALID` triage requires all seven gate decisions: request ready, scope confirmed, reachable, impact proven, novelty checked, not rejected, and triager-acceptable.
- Missing or false gate decisions are rejected by schema validation rather than being silently accepted.
- The model pool retries invalid output and failed free models before the lead is discarded.

## Recently implemented (2026-09)

- RAG context via `knowledge.py` — persistent learnings/rejected store, keyword retrieval, injected into hypothesis prompt as `<knowledge>`.
- Hypothesis verification via `verifier.py` — scope-checked, rate-limited, read-only probes with optional authenticated headers and OOB token generation.
- State machine via `state_machine.py` — `INIT → RECON → SURFACE → HYPOTHESIS → VERIFY → TRIAGE → LEARN` with `state/<program>-state.json`.
- Authenticated evidence via `auth.py` — per-program `config/auth/<program>.json` referencing a secret env var, only used for `AUTH_HELPED` leads.
- OOB validation via `oob.py` — token generation, `state/<program>-oob.json` store, Interactsh poll support, 72h TTL cleanup.
- Feedback loop via `feedback.py` — ledger metrics, `feedback-report` markdown, automatic knowledge updates for repeated INVALID and high HOLD rates.

## Remaining parity work

- Add multi-program matrix execution from one configuration set.
- Add JS/source-map analysis to source recon.
- Add OOB-fed verification (auto-inject OOB URL into SSRF probe parameters).
