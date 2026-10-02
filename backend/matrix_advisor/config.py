"""Configuration loading and saving.

The configuration lives in a YAML file (``config.yaml``). Secrets are never written
to that file: they are referenced as ``${ENV_VAR}`` placeholders and resolved from
the environment, or from a ``secrets.json`` file (mode 0600) when an operator
enters them through the web UI. Environment variables always win.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

SECRET_MASK = "********"

# Dotted path of every secret field -> environment variable that can provide it.
SECRET_FIELDS: dict[str, str] = {
    "llm.api_key": "MA_LLM_API_KEY",
    "ise.openapi.password": "MA_ISE_PASSWORD",
    "ise.pxgrid.password": "MA_PXGRID_PASSWORD",
    "server.admin_password": "MA_ADMIN_PASSWORD",
    "server.session_secret": "MA_SESSION_SECRET",
}

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


class LLMConfig(BaseModel):
    provider: Literal["ollama", "openai", "anthropic", "azure"] = "ollama"
    endpoint: str = "http://ollama:11434"
    model: str = "qwen2.5:14b"
    api_key: str = ""
    api_version: str = "2024-06-01"  # Azure OpenAI only
    temperature: float = Field(0.1, ge=0, le=2)
    timeout_s: int = Field(60, ge=1, le=600)
    trigger: Literal["event", "scheduled"] = "event"
    scheduled_minutes: int = Field(60, ge=5, le=1440)
    learning_days: int = Field(14, ge=0, le=90)
    language: str = "fr"
    # Not configurable on purpose: the model only ever sees SGT names, ports and volumes.
    send_ip_addresses: Literal[False] = False

    @property
    def is_cloud(self) -> bool:
        return self.provider in ("anthropic", "azure")


class OpenAPIConfig(BaseModel):
    # Override for labs and the simulator, e.g. "http://ise-sim:9060". Default: https://<pan>:<port>
    base_url: str = ""
    username: str = "matrix-advisor"
    password: str = ""
    port: int = 443
    verify_tls: bool = True
    ca_cert: str = ""


class PxGridConfig(BaseModel):
    node: str = ""
    # Override for labs and the simulator. Default: https://<node>:<port>
    base_url: str = ""
    client_name: str = "matrix-advisor"
    auth: Literal["certificate", "password"] = "certificate"
    client_cert: str = ""
    client_key: str = ""
    ca_cert: str = ""
    password: str = ""
    port: int = 8910
    verify_tls: bool = True
    subscribe: bool = True  # websocket subscription; falls back to polling
    poll_seconds: int = Field(60, ge=10, le=3600)


class ISEConfig(BaseModel):
    pan: str = "ise-pan.lab.local"
    openapi: OpenAPIConfig = OpenAPIConfig()
    pxgrid: PxGridConfig = PxGridConfig()
    # monitor: approved cells are written with status MONITOR (logged, not enforced)
    # enforce: approved cells are written with status ENABLED
    write_mode: Literal["monitor", "enforce"] = "monitor"
    sgacl_prefix: str = "MA_"
    reconcile_minutes: int = Field(15, ge=1, le=1440)
    # What the matrix does for a pair with no cell. Default-deny is the target state.
    matrix_default: Literal["deny", "permit"] = "deny"
    # Static IP -> SGT bindings (CIDR -> SGT name), merged with pxGrid sessions.
    static_bindings: dict[str, str] = {}

    @field_validator("sgacl_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", v):
            raise ValueError("letters, digits and _ only, starting with a letter")
        return v


class CollectorConfig(BaseModel):
    type: Literal["goflow2"] = "goflow2"
    input_file: str = "/flows/goflow2.ndjson"
    listen: str = "0.0.0.0"
    ipfix_port: int = Field(4739, ge=1, le=65535)
    netflow_v9_port: int = Field(2055, ge=1, le=65535)
    allowed_exporters: list[str] = ["10.0.0.0/8"]
    parquet_dir: str = "/data/parquet"
    duckdb_path: str = "/data/matrix-advisor.duckdb"
    rotate_minutes: int = Field(60, ge=1, le=1440)
    retention_days: int = Field(30, ge=1, le=365)
    aggregation_seconds: int = Field(60, ge=5, le=3600)
    stale_after_seconds: int = Field(300, ge=30)


class ServerConfig(BaseModel):
    admin_password: str = ""
    session_secret: str = ""
    session_hours: int = 12
    cors_origins: list[str] = []


class Settings(BaseModel):
    llm: LLMConfig = LLMConfig()
    ise: ISEConfig = ISEConfig()
    collector: CollectorConfig = CollectorConfig()
    server: ServerConfig = ServerConfig()


# ---------------------------------------------------------------- helpers

def _get(d: dict, dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(d: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _expand_env(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_env(v) for v in node]
    if isinstance(node, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), node)
    return node


class ConfigStore:
    """Thread-safe holder for the live configuration."""

    def __init__(self, path: str | Path, secrets_path: str | Path | None = None):
        self.path = Path(path)
        self.secrets_path = Path(secrets_path) if secrets_path else self.path.with_name("secrets.json")
        self._lock = threading.RLock()
        self._listeners: list = []
        self.settings = self._load()

    # -- loading
    def _read_secrets(self) -> dict[str, str]:
        if self.secrets_path.exists():
            try:
                return json.loads(self.secrets_path.read_text())
            except (OSError, json.JSONDecodeError):
                return {}
        return {}

    def _load(self) -> Settings:
        raw: dict = {}
        if self.path.exists():
            raw = yaml.safe_load(self.path.read_text()) or {}
        data = _expand_env(raw)
        stored = self._read_secrets()
        for dotted, env in SECRET_FIELDS.items():
            if os.environ.get(env):
                _set(data, dotted, os.environ[env])
            elif not _get(data, dotted) and stored.get(dotted):
                _set(data, dotted, stored[dotted])
        return Settings.model_validate(data)

    def reload(self) -> Settings:
        with self._lock:
            self.settings = self._load()
            return self.settings

    def on_change(self, fn) -> None:
        self._listeners.append(fn)

    # -- public views
    def masked(self) -> dict:
        """Configuration as JSON for the UI, secrets replaced by a mask (or '')."""
        with self._lock:
            data = self.settings.model_dump()
        for dotted, env in SECRET_FIELDS.items():
            value = _get(data, dotted)
            _set(data, dotted, SECRET_MASK if value else "")
            _set(data, dotted + "_from_env", bool(os.environ.get(env)))
        data["server"].pop("session_secret", None)
        data["server"].pop("session_secret_from_env", None)
        return data

    # -- saving
    def preview(self, incoming: dict) -> Settings:
        """Settings that ``incoming`` (as sent by the UI) would produce, without saving.

        ``incoming`` is deep-merged over the current settings; secret fields that are empty
        or equal to the mask keep their current value.
        """
        with self._lock:
            current = self.settings.model_dump()
        merged = _deep_merge(current, json.loads(json.dumps(incoming)))
        for dotted in SECRET_FIELDS:
            parent = _get(merged, dotted.rsplit(".", 1)[0])
            if isinstance(parent, dict):
                parent.pop(dotted.rsplit(".", 1)[1] + "_from_env", None)
            if _get(merged, dotted) in (None, "", SECRET_MASK):
                _set(merged, dotted, _get(current, dotted) or "")
        merged["server"]["session_secret"] = current["server"]["session_secret"]
        return Settings.model_validate(merged)

    def save(self, incoming: dict) -> Settings:
        """Validate and persist settings coming from the UI.

        New secret values go to secrets.json (0600); the YAML keeps ``${ENV}`` placeholders.
        """
        new = self.preview(incoming)
        with self._lock:
            secrets = self._read_secrets()
            yaml_data = new.model_dump()
            for dotted, env in SECRET_FIELDS.items():
                value = _get(yaml_data, dotted)
                if value and not os.environ.get(env):
                    secrets[dotted] = value
                _set(yaml_data, dotted, "${" + env + "}")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(yaml.safe_dump(yaml_data, sort_keys=False, allow_unicode=True))
            tmp.replace(self.path)
            self._write_secrets(secrets)
            old, self.settings = self.settings, new
        for fn in self._listeners:
            fn(old, new)
        return new

    def _write_secrets(self, secrets: dict) -> None:
        self.secrets_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.secrets_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(secrets, fh)

    def ensure_secret(self, dotted: str, value: str) -> None:
        """Persist a generated secret (first run) unless one is already configured."""
        with self._lock:
            if _get(self.settings.model_dump(), dotted):
                return
            secrets = self._read_secrets()
            secrets[dotted] = value
            self._write_secrets(secrets)
            self.settings = self._load()


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def default_config_path() -> str:
    return os.environ.get("MA_CONFIG", "/data/config.yaml")
