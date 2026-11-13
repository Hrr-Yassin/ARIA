"""
PentestAI v10 — Configuration
"""
from typing import List, Optional, Literal
from zoneinfo import ZoneInfo

from pydantic import Field, field_validator, model_validator
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
    LLM_ROUTING: Literal["cloud", "local"] = "cloud"
    LOCAL_LLM_URL: str = "http://127.0.0.1:11434/v1"
    LOCAL_LLM_MODEL: str = ""
    LLM_TEMPERATURE: float = 0.1
    LLM_COOLDOWN_SECONDS: int = 300

    # ── Kali Agent ──────────────────────────────────────────────────────
    KALI_AGENT_URL: str = ""
    KALI_WORKER_PROTOCOL: Literal["jobs-v1", "legacy-execute"] = "jobs-v1"
    KALI_AGENT_TOKEN: str = Field(min_length=32, repr=False)

    BROWSER_MAPPING_ENABLED: bool = False
    HTTP_REPLAY_KEY: str = Field(default="", repr=False)
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
    AUTONOMOUS_OBJECTIVE_MAX_CHARS: int = Field(default=2000, env="AUTONOMOUS_OBJECTIVE_MAX_CHARS")

    # ── v10: Bounded evidence context ───────────────────────────────────
    # Evidence is selected by relevance before it reaches a model prompt.
    # Limits bound the serialized evidence block; scope and authorization
    # remain in the separate trusted block and are never truncated.
    EVIDENCE_CONTEXT_MAX_ITEMS: int = Field(default=12, env="EVIDENCE_CONTEXT_MAX_ITEMS")
    EVIDENCE_CONTEXT_MAX_CHARS: int = Field(default=6000, env="EVIDENCE_CONTEXT_MAX_CHARS")
    EVIDENCE_CONTEXT_MAX_TOKENS: int = Field(default=1500, env="EVIDENCE_CONTEXT_MAX_TOKENS")
    EVIDENCE_CONTEXT_ITEM_CHARS: int = Field(default=1000, env="EVIDENCE_CONTEXT_ITEM_CHARS")
    EVIDENCE_CONTEXT_COMMAND_CHARS: int = Field(default=200, env="EVIDENCE_CONTEXT_COMMAND_CHARS")

    # Risk threshold for auto-execution:
    #   "green_only"    → only green commands auto-execute; orange + red prompt
    #   "green_orange"  → green + orange auto-execute; red prompts (default — matches academic brief)
    #   "all"           → disabled for safety (reserved; treated as green_orange)
    AUTO_RISK_THRESHOLD: str = Field(default="green_orange", env="AUTO_RISK_THRESHOLD")

    # Seconds between autonomous steps (rate limit)
    AUTONOMOUS_STEP_DELAY_SECONDS: float = Field(default=1.5, env="AUTONOMOUS_STEP_DELAY_SECONDS")

    # Timeout for a single autonomous step
    AUTONOMOUS_STEP_TIMEOUT_SECONDS: int = Field(default=120, env="AUTONOMOUS_STEP_TIMEOUT_SECONDS")

    # ── SPEC-13: evidence-driven specialist investigations ─────────────
    # Specialist review is advisory: tasks never dispatch target traffic and
    # never complete a finding.  The small task count and per-task model
    # budget keep this phase within the existing campaign LLM ledger.
    SPECIALIST_MAX_INVESTIGATIONS: int = Field(
        default=3, ge=1, le=10, env="SPECIALIST_MAX_INVESTIGATIONS")
    SPECIALIST_MAX_TASKS_PER_RUN: int = Field(
        default=3, ge=1, le=10, env="SPECIALIST_MAX_TASKS_PER_RUN")
    SPECIALIST_TASK_MODEL_CALLS: int = Field(
        default=3, ge=1, le=20, env="SPECIALIST_TASK_MODEL_CALLS")
    SPECIALIST_TASK_MAX_TOKENS: int = Field(
        default=20000, ge=1000, le=200000, env="SPECIALIST_TASK_MAX_TOKENS")

    # ── SPEC-12: durable campaign supervisor ────────────────────────────
    # A campaign may run for at most eight hours per local day and only on
    # the configured weekdays (default Monday-Friday). Per-run step and
    # model-call limits remain unchanged; the supervisor never extends them.
    CAMPAIGN_SUPERVISOR_ENABLED: bool = Field(default=True, env="CAMPAIGN_SUPERVISOR_ENABLED")
    CAMPAIGN_TICK_SECONDS: float = Field(default=5.0, ge=1.0, le=300.0,
                                         env="CAMPAIGN_TICK_SECONDS")
    CAMPAIGN_LEASE_SECONDS: int = Field(default=60, ge=15, le=600,
                                        env="CAMPAIGN_LEASE_SECONDS")
    CAMPAIGN_MAX_DAILY_RUNTIME_SECONDS: int = Field(
        default=28800, ge=60, le=28800, env="CAMPAIGN_MAX_DAILY_RUNTIME_SECONDS")
    CAMPAIGN_ALLOWED_WEEKDAYS: str = Field(default="0,1,2,3,4",
                                           env="CAMPAIGN_ALLOWED_WEEKDAYS")
    CAMPAIGN_DEFAULT_TIMEZONE: str = Field(default="UTC",
                                           env="CAMPAIGN_DEFAULT_TIMEZONE")
    CAMPAIGN_MAX_RETRIES: int = Field(default=3, ge=0, le=10,
                                      env="CAMPAIGN_MAX_RETRIES")
    CAMPAIGN_RETRY_BASE_SECONDS: int = Field(default=60, ge=1, le=3600,
                                             env="CAMPAIGN_RETRY_BASE_SECONDS")
    CAMPAIGN_RETRY_MAX_SECONDS: int = Field(default=1800, ge=1, le=86400,
                                            env="CAMPAIGN_RETRY_MAX_SECONDS")
    CAMPAIGN_MAX_TOKENS: int = Field(default=200000, ge=1, le=100000000,
                                     env="CAMPAIGN_MAX_TOKENS")
    CAMPAIGN_MAX_COST_MICROUSD: int = Field(default=2000000, ge=0,
                                            le=1000000000,
                                            env="CAMPAIGN_MAX_COST_MICROUSD")

    # ── SPEC-14: operational observability ──────────────────────────────
    # Monitoring thresholds are read-only: they raise alerts but never grant
    # execution or extend a campaign's budget.  Heartbeats older than the
    # stale threshold mean the supervisor lease can no longer be trusted.
    CAMPAIGN_HEARTBEAT_STALE_SECONDS: int = Field(
        default=120, ge=15, le=3600, env="CAMPAIGN_HEARTBEAT_STALE_SECONDS")
    CAMPAIGN_PROGRESS_STALE_SECONDS: int = Field(
        default=1800, ge=60, le=86400, env="CAMPAIGN_PROGRESS_STALE_SECONDS")

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

    @field_validator("LOCAL_LLM_URL")
    @classmethod
    def local_model_url(cls, value):
        from urllib.parse import urlsplit
        parsed = urlsplit(value)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Local model URL must use HTTP and a numeric loopback address")
        try:
            parsed.port
        except ValueError:
            raise ValueError("Invalid local model port") from None
        return value.rstrip("/")

    @field_validator("FERNET_PREVIOUS_KEYS")
    @classmethod
    def valid_previous_keys(cls, values):
        try:
            for value in values:
                Fernet(value.encode())
        except Exception:
            raise ValueError("Invalid previous encryption key") from None
        return values

    @field_validator("CAMPAIGN_ALLOWED_WEEKDAYS")
    @classmethod
    def valid_campaign_weekdays(cls, value: str) -> str:
        try:
            days = tuple(sorted({int(part.strip()) for part in value.split(",")
                                 if part.strip()}))
        except ValueError:
            raise ValueError("Campaign weekdays must be comma-separated integers") from None
        if not days or any(day < 0 or day > 6 for day in days):
            raise ValueError("Campaign weekdays must be between 0 (Monday) and 6 (Sunday)")
        if len(days) > 5:
            raise ValueError("A campaign may be scheduled on at most five weekdays")
        return ",".join(str(day) for day in days)

    @field_validator("CAMPAIGN_DEFAULT_TIMEZONE")
    @classmethod
    def valid_campaign_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except Exception:
            raise ValueError("Campaign timezone must be a valid IANA timezone") from None
        return value

    @model_validator(mode="after")
    def valid_campaign_retry_bounds(self):
        if self.CAMPAIGN_RETRY_MAX_SECONDS < self.CAMPAIGN_RETRY_BASE_SECONDS:
            raise ValueError("Campaign retry maximum must not be below the base delay")
        return self

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
        "hide_input_in_errors": True,
    }


settings = Settings()
