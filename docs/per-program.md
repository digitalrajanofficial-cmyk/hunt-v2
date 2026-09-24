# Per-program hunt repositories

Each authorized program gets its own repository, like `vr-hunt` and `maruti-hunt`.
This mirrors `riteshekbote/*-hunt` and keeps scope, state, and knowledge isolated per program.

## Template

`hunt-v2` is the template. All hunting logic lives in `src/hunt_pipeline/` and is copied verbatim into per-program repos.

## Create a new program repo

```bash
# from hunt-v2 root
python scripts/create-program-repo.py \
  --program maruti \
  --display-name "Maruti Suzuki" \
  --org digitalrajanofficial-cmyk \
  --template . \
  --output-root /tmp/program-repos \
  --push
```

This creates `digitalrajanofficial-cmyk/maruti-hunt`:

- `config/program.json` — single-program policy (edit `allowed_hosts`, `authorization_reference`, `enabled`)
- `inputs/seed.txt` — one seed URL per line (`https://.../`)
- `.github/workflows/hunt.yml` — schedule + dispatch, gated by `ENABLE_HUNT=true`

For `vr` the seed and hosts are already filled from `config/programs/vr.json`:

```bash
python scripts/create-program-repo.py --program vr --display-name "VR Group" --push
# -> digitalrajanofficial-cmyk/vr-hunt
```

## Configure the new repo

1. Edit `config/program.json`:
   - `allowed_hosts` — exact hosts (e.g. `["www.maruti.example"]`)
   - `authorization_reference` — official scope URL
   - `enabled: true` only after written authorization is confirmed
2. Edit `inputs/seed.txt` — one in-scope URL per line
3. Push to `main`

## Enable the workflow

In the new repo `Settings → Actions → Variables`:

- `ENABLE_HUNT=true`
- `OPENCODE_VERSION=latest`
- `FREE_MODEL_POOL=opencode/big-pickle,opencode/space-bunny-free,...` (copy from hunt-v2)

And `Settings → Secrets → Actions`:

- `OPENCODE_API_KEY` — your Zen API key (same as hunt-v2)
- Optional: `VR_AUTH_TOKEN` / `MARUTI_AUTH_TOKEN` if `config/auth/<program>.json` is used
- Optional: `OOB_DOMAIN` / `INTERACTSH_TOKEN` for OOB

## Dry-run locally

```bash
gh repo clone digitalrajanofficial-cmyk/vr-hunt /tmp/vr-hunt
cd /tmp/vr-hunt
PYTHONPATH=src python -m hunt_pipeline collect --config config/program.json --input inputs/seed.txt --output /tmp/inv.json --method HEAD --limit 1
PYTHONPATH=src python -m hunt_pipeline enrich --inventory /tmp/inv.json --output /tmp/inv.json
```

## Existing per-program repos

- `hunt-v2` — template + `vr` (active) + `example` (disabled)
- `vr-hunt` — created 2026-09-24, `main`, public, from `vr` program
- `maruti-hunt` — create with the command above when Maruti scope is confirmed

Do not create a repo until you have written authorization for that program.
