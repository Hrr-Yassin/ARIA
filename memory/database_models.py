"""
PentestAI v10 — Database Models
Multi-tenant: users, sessions, findings, audit logs, API keys, playbooks,
and v10 additions: DecisionLog for complete action traceability.
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime, JSON,
    ForeignKey, Enum as SAEnum, Index, UniqueConstraint
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship
import enum

from config.settings import settings


class Base(DeclarativeBase):
    pass


# ── Enums ────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"

class SkillLevel(str, enum.Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"

class SessionStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class PentestPhase(str, enum.Enum):
    SCOPE = "scope"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"

class RiskLevel(str, enum.Enum):
    GREEN = "green"
    ORANGE = "orange"
    RED = "red"

class AuditAction(str, enum.Enum):
    COMMAND_EXECUTE = "command_execute"
    COMMAND_APPROVE = "command_approve"
    COMMAND_REJECT = "command_reject"
    COMMAND_MODIFY = "command_modify"
    ANALYSIS = "analysis"
    FINDING_ADD = "finding_add"
    SCOPE_VIOLATION = "scope_violation"
    LOGIN = "login"
    LOGOUT = "logout"
    API_KEY_ADD = "api_key_add"
    API_KEY_REMOVE = "api_key_remove"
    SESSION_CREATE = "session_create"
    SESSION_DELETE = "session_delete"
    REPORT_GENERATE = "report_generate"
    HUMAN_OVERRIDE = "human_override"
    # v10 additions
    AUTONOMOUS_START = "autonomous_start"
    AUTONOMOUS_STOP = "autonomous_stop"
    AUTO_STEP = "auto_step"
    APPROVAL_REQUESTED = "approval_requested"
    PLAN_UPDATED = "plan_updated"


# ── Users ────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.PENTESTER)
    skill_level = Column(SAEnum(SkillLevel), nullable=False, default=SkillLevel.INTERMEDIATE)
    display_name = Column(String(100), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    preferences = Column(JSON, default=dict)

    api_keys = relationship("UserAPIKey", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("PentestSession", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


# ── API Keys (per-user, encrypted) ──────────────────────────────────────

class UserAPIKey(Base):
    __tablename__ = "user_api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(50), nullable=False)
    encrypted_key = Column(Text, nullable=False)
    label = Column(String(100), default="")
    is_active = Column(Boolean, default=True)
    requests_used = Column(Integer, default=0)
    requests_limit = Column(Integer, default=30)
    last_used = Column(DateTime, nullable=True)
    last_error = Column(String(200), nullable=True)
    cooldown_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("ix_user_api_keys_user_provider", "user_id", "provider"),
    )


# ── Pentest Sessions ────────────────────────────────────────────────────

class PentestSession(Base):
    __tablename__ = "pentest_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    name = Column(String(200), default="")
    target = Column(String(500), nullable=False)
    scope = Column(JSON, default=dict)
    context_type = Column(String(50), default="internal_corporate")
    status = Column(SAEnum(SessionStatus), default=SessionStatus.ACTIVE)
    current_phase = Column(SAEnum(PentestPhase), default=PentestPhase.SCOPE)
    phase_progress = Column(JSON, default=dict)
    tools_run = Column(JSON, default=list)
    open_ports = Column(JSON, default=list)
    attack_surface = Column(JSON, default=dict)
    # v10: attack mode persisted so it survives restarts
    attack_mode = Column(String(30), default="lab")  # lab | red_team | bug_bounty
    # v10: autonomous engine state
    autonomous_active = Column(Boolean, default=False)
    autonomous_goal = Column(String(50), default="")
    autonomous_steps_taken = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata_ = Column("metadata", JSON, default=dict)

    user = relationship("User", back_populates="sessions")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")
    chat_logs = relationship("ChatLog", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_session_user", "user_id"),
        Index("ix_session_target", "target"),
    )


# ── Findings ─────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), default="info")
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    recommendation = Column(Text, default="")
    cve_ids = Column(JSON, default=list)
    vulnerability_type = Column(String(50), default="")
    exploit_complexity = Column(String(20), default="")
    business_impact = Column(Text, default="")
    agent_type = Column(String(50), default="")
    confidence = Column(Float, default=0.5)
    is_validated = Column(Boolean, default=False)
    human_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata_ = Column("metadata", JSON, default=dict)

    session = relationship("PentestSession", back_populates="findings")

    __table_args__ = (
        Index("ix_finding_session", "session_id"),
        Index("ix_finding_severity", "severity"),
    )


# ── Chat Logs ────────────────────────────────────────────────────────────

class ChatLog(Base):
    __tablename__ = "chat_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, default="")
    msg_type = Column(String(30), default="text")
    data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("PentestSession", back_populates="chat_logs")

    __table_args__ = (
        Index("ix_chatlog_session", "session_id"),
    )


# ── Audit Logs ───────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    session_id = Column(String(36), nullable=True)
    action = Column(SAEnum(AuditAction), nullable=False)
    agent = Column(String(50), nullable=True)
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    reasoning = Column(Text, default="")
    human_status = Column(String(20), default="")
    risk_level = Column(SAEnum(RiskLevel), nullable=True)
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_user", "user_id"),
        Index("ix_audit_session", "session_id"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_time", "created_at"),
    )


# ── v10: Decision Log (complete traceability) ───────────────────────────
# Academic-brief requirement: "traçabilité complète des décisions"
# Every autonomous step, LLM decision, approval, KB mutation writes here.

class DecisionLog(Base):
    __tablename__ = "decision_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), nullable=True)
    step_number = Column(Integer, default=0)
    decision_type = Column(String(40), default="")
    # Types: auto_execute | await_approval | plan_generated | finding_validated
    #        replan_triggered | playbook_applied | kb_update | llm_call
    agent = Column(String(50), default="")
    reasoning = Column(Text, default="")   # The "thought" in ReAct traces
    action_taken = Column(Text, default="")
    risk_color = Column(String(10), default="")
    human_involved = Column(Boolean, default=False)
    human_decision = Column(String(20), default="")   # approve|reject|modify|none
    observation = Column(Text, default="")
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_decision_session", "session_id"),
        Index("ix_decision_time", "created_at"),
        Index("ix_decision_type", "decision_type"),
    )


# ── Playbooks (v10 expansion) ────────────────────────────────────────────

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    session_id = Column(String(36), nullable=True)
    name = Column(String(200), nullable=False)
    target_profile = Column(String(100), default="")
    # v10: richer payload — stored inside `phases` JSON for backwards compat:
    #   { service, version_pattern, goal_type, steps, success_rate,
    #     avg_time_seconds, tags, success_count, failure_count }
    phases = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_playbook_user", "user_id"),
        Index("ix_playbook_target", "target_profile"),
    )


# ── Database Engine ──────────────────────────────────────────────────────

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    # Startup verifies schema; operators apply migrations before starting the API.
    from sqlalchemy import text
    async with engine.connect() as conn:
        revision = await conn.scalar(text("SELECT version_num FROM alembic_version"))
        if revision != "0003":
            raise RuntimeError("Database revision unsupported; run python -m alembic upgrade head")


async def get_db():
    async with async_session() as session:
        yield session


class AutonomousRun(Base):
    """Durable run snapshot; commands are never replayed from this record."""
    __tablename__ = "autonomous_runs"
    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    state = Column(String(30), nullable=False)
    snapshot = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WebAction(Base):
    __tablename__ = "web_actions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("pentest_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    evidence_id = Column(String(36), ForeignKey("chat_logs.id"), nullable=False)
    state = Column(String(30), nullable=False, default="pending")
    request_digest = Column(String(64), nullable=False)
    scope_digest = Column(String(64), nullable=False)
    protected_spec = Column(Text, nullable=False)
    protected_response = Column(Text, nullable=True)
    result = Column(JSON, nullable=False, default=dict)
    expires_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
