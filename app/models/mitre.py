from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MITRETactic(StrEnum):
    CREDENTIAL_ACCESS = "credential-access"
    EXECUTION = "execution"


class MITRETechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(min_length=1)
    tactic: MITRETactic


class MITREMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    technique: MITRETechnique
    confidence: int = Field(ge=0, le=100)
    rationale: str = Field(min_length=1)
