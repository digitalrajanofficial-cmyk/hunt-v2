# Auth configs

Place per-program auth configs here, e.g. `vr.json`:

```json
{
  "auth": {
    "type": "bearer",
    "env_var": "VR_AUTH_TOKEN",
    "header_name": "Authorization"
  }
}
```

Supported types: `bearer` (Authorization: Bearer), `basic`, `header` (custom header), `cookie`.

Never commit real tokens. The workflow reads the token from an Actions secret whose name matches `env_var` (e.g. `VR_AUTH_TOKEN`).

The verifier only sends auth headers when a lead has `testability: AUTH_HELPED` and the env var is present.
