import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthConfig:
    type: str
    env_var: str
    header_name: str | None = None
    cookie_name: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> "AuthConfig | None":
        if not value:
            return None
        if not isinstance(value, dict):
            raise ValueError("auth must be an object")
        auth_type = str(value.get("type", "")).strip().lower()
        env_var = str(value.get("env_var", "")).strip()
        if auth_type not in {"bearer", "header", "cookie", "basic"}:
            raise ValueError("auth.type must be bearer, header, cookie, or basic")
        if not env_var:
            raise ValueError("auth.env_var is required")
        return cls(
            type=auth_type,
            env_var=env_var,
            header_name=str(value.get("header_name", "")).strip() or None,
            cookie_name=str(value.get("cookie_name", "")).strip() or None,
        )


class AuthProvider:
    def __init__(self, config: AuthConfig | None):
        self.config = config

    def is_available(self) -> bool:
        if not self.config:
            return False
        value = os.environ.get(self.config.env_var, "")
        return bool(value.strip())

    def headers(self) -> dict[str, str]:
        if not self.config or not self.is_available():
            return {}
        raw = os.environ.get(self.config.env_var, "").strip()
        if not raw:
            return {}
        if self.config.type == "bearer":
            return {"Authorization": f"Bearer {raw}"}
        if self.config.type == "basic":
            return {"Authorization": f"Basic {raw}"}
        if self.config.type == "header":
            name = self.config.header_name or "X-Auth-Token"
            return {name: raw}
        if self.config.type == "cookie":
            name = self.config.cookie_name or "session"
            return {"Cookie": f"{name}={raw}"}
        return {}

    def redacted(self) -> str:
        if not self.config:
            return "no-auth"
        return f"{self.config.type}:{self.config.env_var}:{'available' if self.is_available() else 'missing'}"
