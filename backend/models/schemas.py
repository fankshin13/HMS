"""supabase/migrations 의 핵심 테이블과 1:1 로 대응하는 Pydantic v2 모델.

스키마를 바꾸면 이 파일도 함께 바꾼다. 시각은 timezone-aware datetime(timestamptz)이다.
"""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UserRole(StrEnum):
    OWNER = "owner"
    OPERATOR = "operator"
    VIEWER = "viewer"


class UserStatus(StrEnum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"


class OsFamily(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    PARSING = "parsing"
    SCORING = "scoring"
    RENDERING = "rendering"
    COMPLETED = "completed"
    FAILED = "failed"


class ParsingStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL_ERROR = "partial_error"
    FAILED = "failed"


class ComplianceRiskLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ComplianceCategory(StrEnum):
    ACCOUNT_MANAGEMENT = "account_management"
    DIRECTORY_FILE_MANAGEMENT = "directory_file_management"
    SERVICE_MANAGEMENT = "service_management"
    PATCH_MANAGEMENT = "patch_management"
    LOG_MANAGEMENT = "log_management"


class ItemStatus(StrEnum):
    GOOD = "good"
    VULNERABLE = "vulnerable"
    NA = "na"


class ReportType(StrEnum):
    DETAILED = "detailed"
    SUMMARY = "summary"
    RISK_PLAN = "risk_plan"


class ReportFormat(StrEnum):
    DOCX = "docx"
    PDF = "pdf"


CiaScore = Annotated[int, Field(ge=1, le=3)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Row(BaseModel):
    model_config = ConfigDict(frozen=True, from_attributes=True)


class Tenant(Row):
    id: UUID
    name: str = Field(max_length=100)
    zero_retention_enabled: bool
    created_at: datetime
    updated_at: datetime


class User(Row):
    id: UUID
    tenant_id: UUID
    auth_user_id: UUID | None
    email: str = Field(max_length=255)
    name: str = Field(max_length=100)
    role: UserRole
    status: UserStatus
    created_at: datetime
    updated_at: datetime


class Invitation(Row):
    id: UUID
    token_hash: Sha256Hex
    tenant_id: UUID
    user_id: UUID
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime


class RiskScoringPolicy(Row):
    id: UUID
    tenant_id: UUID
    confidentiality_weight: Decimal = Field(gt=0, max_digits=3, decimal_places=2)
    integrity_weight: Decimal = Field(gt=0, max_digits=3, decimal_places=2)
    availability_weight: Decimal = Field(gt=0, max_digits=3, decimal_places=2)
    critical_threshold: int
    warning_threshold: int
    created_at: datetime
    updated_at: datetime


class Asset(Row):
    id: UUID
    tenant_id: UUID
    hostname: str = Field(max_length=255)
    ip_address: str | None = Field(default=None, max_length=45)
    os_type: OsFamily
    os_version: str | None = Field(default=None, max_length=100)
    confidentiality_score: CiaScore
    integrity_score: CiaScore
    availability_score: CiaScore
    last_assessed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssessmentRun(Row):
    id: UUID
    tenant_id: UUID
    title: str = Field(max_length=200)
    status: AssessmentStatus
    raw_archive_sha256: Sha256Hex | None
    total_assets: int = Field(ge=0)
    vulnerable_items_count: int = Field(ge=0)
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DiagnosticLog(Row):
    id: UUID
    tenant_id: UUID
    assessment_run_id: UUID
    asset_id: UUID | None
    file_name: str = Field(max_length=255)
    file_size_bytes: int = Field(ge=0)
    storage_path: str | None = Field(default=None, max_length=500)
    parse_status: ParsingStatus
    quarantined_error_lines: int = Field(ge=0)
    error_details: dict[str, Any] | list[Any] | None
    created_at: datetime


class ComplianceGuideline(Row):
    item_code: str = Field(pattern=r"^[A-Z]{1,3}-[0-9]{2,3}$")
    category: ComplianceCategory
    name: str = Field(max_length=255)
    risk_level: ComplianceRiskLevel
    standard_criteria: str
    good_condition: str
    vulnerable_condition: str
    remediation_guide: str
    created_at: datetime
    updated_at: datetime


class InspectionItemResult(Row):
    id: UUID
    tenant_id: UUID
    assessment_run_id: UUID
    asset_id: UUID
    item_code: str
    auto_status: ItemStatus
    final_status: ItemStatus
    stdout_snippet: str | None
    raw_log_start_line: int | None = Field(default=None, gt=0)
    raw_log_end_line: int | None
    calculated_risk_score: Decimal = Field(ge=0, max_digits=5, decimal_places=2)
    created_at: datetime
    updated_at: datetime


class OverrideAuditLog(Row):
    id: UUID
    inspection_item_result_id: UUID
    tenant_id: UUID
    actor_user_id: UUID
    previous_status: ItemStatus
    new_status: ItemStatus
    override_reason: str = Field(min_length=5)
    created_at: datetime


class GeneratedReport(Row):
    id: UUID
    tenant_id: UUID
    assessment_run_id: UUID
    report_type: ReportType
    format: ReportFormat
    storage_path: str = Field(max_length=500)
    file_size_bytes: int = Field(ge=0)
    expires_at: datetime
    created_at: datetime
