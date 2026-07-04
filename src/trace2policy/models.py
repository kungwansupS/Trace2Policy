from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "0.1"


class Trace2PolicyError(Exception):
    """Base exception for user-facing failures."""


class TraceValidationError(Trace2PolicyError):
    def __init__(self, path: str, line: int | None, message: str) -> None:
        location = path if line is None else f"{path}:{line}"
        super().__init__(f"{location}: {message}")
        self.path = path
        self.line = line
        self.message = message


class EventType(StrEnum):
    USER_INPUT = "user_input"
    SYSTEM_INSTRUCTION = "system_instruction"
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RETRIEVAL = "retrieval"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_REQUEST = "network_request"
    MCP_TOOL_LIST = "mcp_tool_list"
    MCP_TOOL_CALL = "mcp_tool_call"
    MCP_RESOURCE_READ = "mcp_resource_read"
    HUMAN_APPROVAL = "human_approval"
    POLICY_DECISION = "policy_decision"
    ERROR = "error"


class Actor(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str = "agent"
    id: str = "agent:unknown"


class Operation(BaseModel):
    model_config = ConfigDict(extra="allow")

    system: str = "unknown"
    tool_name: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action")
    @classmethod
    def action_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("operation.action must not be empty")
        return value.strip()


class DataRef(BaseModel):
    model_config = ConfigDict(extra="allow")

    content_ref: str | None = None
    content_preview: str | None = None
    redaction: str = "full"
    labels: list[str] = Field(default_factory=list)
    sensitivity: str = "internal"
    trust_level: str = "untrusted"
    sink: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def labels_must_be_unique(cls, values: list[str]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                unique.append(value)
        return unique


class AuthMeta(BaseModel):
    model_config = ConfigDict(extra="allow")

    principal: str | None = None
    scopes: list[str] = Field(default_factory=list)
    credential_ref: Literal["redacted"] | str | None = None


class RuntimeMeta(BaseModel):
    model_config = ConfigDict(extra="allow")

    framework: str | None = None
    model: str | None = None
    environment: str | None = None


class ObservedDecision(BaseModel):
    model_config = ConfigDict(extra="allow")

    observed: str = "allowed"
    human_approved: bool = False


class ExpectedOutcome(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: Literal["allow", "deny", "requires_approval"]
    reason_contains: str | None = None
    attack: str | None = None


class Event(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = SCHEMA_VERSION
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    session_id: str | None = None
    task_id: str
    timestamp: str | None = None
    event_type: EventType
    actor: Actor = Field(default_factory=Actor)
    operation: Operation
    input: DataRef = Field(default_factory=DataRef)
    output: DataRef = Field(default_factory=DataRef)
    auth: AuthMeta = Field(default_factory=AuthMeta)
    runtime: RuntimeMeta = Field(default_factory=RuntimeMeta)
    decision: ObservedDecision = Field(default_factory=ObservedDecision)
    metadata: dict[str, Any] = Field(default_factory=dict)
    expected: ExpectedOutcome | None = None

    @field_validator("schema_version")
    @classmethod
    def schema_version_must_match(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}; expected {SCHEMA_VERSION!r}")
        return value


class PolicyDefaults(BaseModel):
    decision: Literal["deny"] = "deny"
    require_reason: bool = True
    log_all_decisions: bool = True


class Rule(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    subject: str | None = None
    action: str
    resource: str | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None


class DenyRule(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    when: dict[str, Any]
    reason: str


class PolicyAudit(BaseModel):
    emit_receipts: bool = True
    include_lineage: bool = True
    hash_policy: bool = True


class Policy(BaseModel):
    schema_version: str = SCHEMA_VERSION
    task: str
    subjects: list[dict[str, str]] = Field(default_factory=list)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    allow: list[Rule] = Field(default_factory=list)
    require_human_approval: list[Rule] = Field(default_factory=list)
    deny: list[DenyRule] = Field(default_factory=list)
    egress: dict[str, Any] = Field(default_factory=lambda: {"allowed_domains": []})
    audit: PolicyAudit = Field(default_factory=PolicyAudit)


class DecisionResource(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str | None = None
    id: str | None = None
    repo: str | None = None
    path: str | None = None
    domain: str | None = None
    visibility: str | None = None


class DecisionSink(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str | None = None
    domain: str | None = None
    recipient_domain: str | None = None


class DecisionInput(BaseModel):
    model_config = ConfigDict(extra="allow")

    subject: str
    action: str
    resource: DecisionResource = Field(default_factory=DecisionResource)
    input: DataRef = Field(default_factory=DataRef)
    sink: DecisionSink = Field(default_factory=DecisionSink)
    params: dict[str, Any] = Field(default_factory=dict)
    human_approved: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionResult(BaseModel):
    allow: bool
    requires_approval: bool = False
    deny_reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)

    @property
    def decision(self) -> Literal["allow", "deny", "requires_approval"]:
        if self.allow:
            return "allow"
        if self.requires_approval:
            return "requires_approval"
        return "deny"


class TestCaseResult(BaseModel):
    name: str
    expected: Literal["allow", "deny", "requires_approval"]
    actual: Literal["allow", "deny", "requires_approval"]
    passed: bool
    reasons: list[str] = Field(default_factory=list)
    trace_id: str | None = None
    span_id: str | None = None


class TestResults(BaseModel):
    schema_version: str = SCHEMA_VERSION
    policy_id: str
    policy_hash: str
    positive: list[TestCaseResult] = Field(default_factory=list)
    negative: list[TestCaseResult] = Field(default_factory=list)
    receipts: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(case.passed for case in [*self.positive, *self.negative])


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
