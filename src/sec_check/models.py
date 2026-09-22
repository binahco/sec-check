from pydantic import BaseModel, Field


class TriageItem(BaseModel):
    type: str
    count: int
    severity: str
    risk_note: str
    remediation: str


class SecFindings(BaseModel):
    summary: str
    risk: str
    leaked_secrets_count: int = 0
    items: list[TriageItem] = Field(default_factory=list)