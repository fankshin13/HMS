"""Pydantic 모델과 데이터베이스 컬럼·열거형이 어긋나지 않는지 확인한다."""

from enum import StrEnum

import psycopg
import pytest
from pydantic import BaseModel

from models import schemas

MODEL_BY_TABLE: dict[str, type[BaseModel]] = {
    "tenants": schemas.Tenant,
    "users": schemas.User,
    "invitations": schemas.Invitation,
    "risk_scoring_policies": schemas.RiskScoringPolicy,
    "assets": schemas.Asset,
    "assessment_runs": schemas.AssessmentRun,
    "diagnostic_logs": schemas.DiagnosticLog,
    "compliance_guidelines": schemas.ComplianceGuideline,
    "inspection_item_results": schemas.InspectionItemResult,
    "override_audit_logs": schemas.OverrideAuditLog,
    "generated_reports": schemas.GeneratedReport,
}
ENUM_BY_TYPE: dict[str, type[StrEnum]] = {
    "user_role": schemas.UserRole,
    "user_status": schemas.UserStatus,
    "os_family": schemas.OsFamily,
    "assessment_status": schemas.AssessmentStatus,
    "parsing_status": schemas.ParsingStatus,
    "compliance_risk_level": schemas.ComplianceRiskLevel,
    "compliance_category": schemas.ComplianceCategory,
    "item_status": schemas.ItemStatus,
    "report_type": schemas.ReportType,
    "report_format": schemas.ReportFormat,
}


@pytest.mark.parametrize("table", sorted(MODEL_BY_TABLE))
def test_model_fields_match_columns(db: psycopg.Connection, table: str) -> None:
    columns = {
        row[0]
        for row in db.execute(
            "select column_name from information_schema.columns "
            "where table_schema = 'public' and table_name = %s",
            (table,),
        )
    }
    assert set(MODEL_BY_TABLE[table].model_fields) == columns


@pytest.mark.parametrize("type_name", sorted(ENUM_BY_TYPE))
def test_enum_values_match_database(db: psycopg.Connection, type_name: str) -> None:
    labels = [
        row[0]
        for row in db.execute(
            "select e.enumlabel from pg_enum e join pg_type t on t.oid = e.enumtypid "
            "where t.typname = %s order by e.enumsortorder",
            (type_name,),
        )
    ]
    assert labels == [member.value for member in ENUM_BY_TYPE[type_name]]


def test_seeded_guidelines_parse_into_model(db: psycopg.Connection) -> None:
    cursor = db.execute("select * from compliance_guidelines")
    names = [column.name for column in cursor.description or []]
    rows = [
        schemas.ComplianceGuideline.model_validate(dict(zip(names, row, strict=True)))
        for row in cursor
    ]
    assert len(rows) > 0
