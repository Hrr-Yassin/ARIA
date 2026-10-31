"""
PentestAI v10 — Configuration
"""
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "PentestAI Platform"
    APP_VERSION: str = "10.0.0"
    DEBUG: bool = False

    # ── Security ────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="pentestai-v10-change-this-in-production-64chars-minimum",
        env="SECRET_KEY"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    # ── Database ────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://ai:ai_password@localhost:5432/pentestai",
        env="DATABASE_URL"
    )

    # ── Redis ───────────────────────────────────────────────────────────
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_SESSION_TTL: int = 86400 * 7

    # ── LLM defaults (users manage their own keys) ──────────────────────
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GEMINI_MODEL: str = "gemini-2.0-flash"
    OPENROUTER_MODEL: str = "anthropic/claude-sonnet-4-5"
    LLM_TEMPERATURE: float = 0.1
    LLM_COOLDOWN_SECONDS: int = 300

    # ── Kali Agent ──────────────────────────────────────────────────────
    KALI_AGENT_URL: str = Field(
        default="http://192.168.57.10:9000",
        env="KALI_AGENT_URL"
    )
    KALI_AGENT_TOKEN: str = Field(
        default="pentestai-kali-secret-v10",
        env="KALI_AGENT_TOKEN"
    )

    # ── Reports ─────────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = "/opt/pentest-ai/reports"

    # ── API ─────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    WEB_PORT: int = 7000
    ALLOWED_ORIGINS: List[str] = ["*"]

    # ── Encryption ──────────────────────────────────────────────────────
    FERNET_KEY: str = Field(default="", env="FERNET_KEY")

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

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()
