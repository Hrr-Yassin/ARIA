"""
PentestAI v10 — Configuration
"""
from typing import List, Optional, Literal
from pydantic import Field, field_validator
from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "PentestAI Platform"
    APP_VERSION: str = "10.0.0"
    DEBUG: bool = False

    # ── Security ────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(min_length=32, repr=False)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    # ── Database ────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(repr=False)

    # ── Redis ───────────────────────────────────────────────────────────
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_SESSION_TTL: int = 86400 * 7

    # ── LLM defaults (users manage their own keys) ──────────────────────
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GEMINI_MODEL: str = "gemini-3.5-flash-lite"
    OPENROUTER_MODEL: str = "anthropic/claude-sonnet-4-5"
    LLM_TEMPERATURE: float = 0.1
    LLM_COOLDOWN_SECONDS: int = 300

    # ── Kali Agent ──────────────────────────────────────────────────────
    KALI_AGENT_URL: str = ""
    KALI_WORKER_PROTOCOL: Literal["jobs-v1", "legacy-execute"] = "jobs-v1"
    KALI_AGENT_TOKEN: str = Field(min_length=32, repr=False)

    BURP_COMMUNITY_ENABLED: bool = False
    BURP_CONNECTOR_USER_ID: str = ""
    BURP_CONNECTOR_URL: str = "http://127.0.0.1:17777"
    BURP_CONNECTOR_TOKEN: str = Field(default="", repr=False)

    # ── Reports ─────────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = "./reports"

    # ── API ─────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    WEB_PORT: int = 7000
    ALLOWED_ORIGINS: List[str] = ["http://127.0.0.1:7000", "http://localhost:7000"]

    # ── Encryption ──────────────────────────────────────────────────────
    FERNET_KEY: str = Field(repr=False)
    FERNET_PREVIOUS_KEYS: List[str] = Field(default_factory=list, repr=False)

    # ── v10: CVE enrichment ─────────────────────────────────────────────
    NVD_API_KEY: str = Field(default="", env="NVD_API_KEY")
    # ^ Optional. Without it you get 5 req/30s. With it: 50 req/30s.

    # ── v10: Autonomous engine limits ───────────────────────────────────
    AUTONOMOUS_MAX_STEPS: int = Field(default=12, env="AUTONOMOUS_MAX_STEPS")
    AUTONOMOUS_MAX_DEPTH: int = Field(default=6, env="AUTONOMOUS_MAX_DEPTH")

    # Risk threshold for auto-execution:
    #   "green_only"    → only green commands auto-execute; orange + red prompt
    #   "green_orange"  → green + orange auto-execute; red prompts (default — matches academic brief)
    #   "all"           → disabled for safety (reserved; treated as green_orange)
    AUTO_RISK_THRESHOLD: str = Field(default="green_orange", env="AUTO_RISK_THRESHOLD")

    # Seconds between autonomous steps (rate limit)
    AUTONOMOUS_STEP_DELAY_SECONDS: float = Field(default=1.5, env="AUTONOMOUS_STEP_DELAY_SECONDS")

    # Timeout for a single autonomous step
    AUTONOMOUS_STEP_TIMEOUT_SECONDS: int = Field(default=120, env="AUTONOMOUS_STEP_TIMEOUT_SECONDS")

    # ── v10: Decision-log traceability ──────────────────────────────────
    # Academic-brief requirement: "traçabilité complète des décisions".
    # When true, every autonomous step + LLM call + approval is persisted to the
    # DecisionLog DB table. Set false only for local development.
    DECISION_LOG_ENABLED: bool = Field(default=True, env="DECISION_LOG_ENABLED")

    # ── Logging ─────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    @field_validator("SECRET_KEY", "KALI_AGENT_TOKEN")
    @classmethod
    def reject_placeholder_secrets(cls, value: str) -> str:
        lowered = value.lower()
        if any(word in lowered for word in ("pentestai", "change-me", "change-this", "placeholder")):
            raise ValueError("A unique deployment secret is required")
        if len(set(value)) < 8:
            raise ValueError("A randomly generated deployment secret is required")
        return value

    @field_validator("FERNET_KEY")
    @classmethod
    def valid_encryption_key(cls, value: str) -> str:
        try:
            Fernet(value.encode())
        except Exception:
            raise ValueError("A persistent valid encryption key is required") from None
        return value

    @field_validator("KALI_AGENT_URL")
    @classmethod
    def validate_worker_url(cls, value):
        from urllib.parse import urlsplit
        if not value:
            return value
        try:
            parsed = urlsplit(value)
            parsed.port
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError()
        except ValueError:
            raise ValueError("Worker URL must be HTTP(S), without embedded credentials, query or fragment") from None
        return value

    @field_validator("FERNET_PREVIOUS_KEYS")
    @classmethod
    def valid_previous_keys(cls, values):
        try:
            for value in values:
                Fernet(value.encode())
        except Exception:
            raise ValueError("Invalid previous encryption key") from None
        return values

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
        "hide_input_in_errors": True,
    }


settings = Settings()
