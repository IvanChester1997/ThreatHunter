import ipaddress
import re
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class IOC(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: IOCType
    value: str
    source: str
    confidence: int = Field(ge=0, le=100)
    created_at: datetime

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str, info) -> str:
        if not value.strip():
            raise ValueError("IOC value must not be empty")

        ioc_type = info.data.get("type")

        if ioc_type == IOCType.IP:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("invalid IP address") from exc

        elif ioc_type == IOCType.DOMAIN:
            if not re.fullmatch(
                r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"[A-Za-z]{2,63}",
                value,
            ):
                raise ValueError("invalid domain")

        elif ioc_type == IOCType.URL:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("invalid URL")

        elif ioc_type == IOCType.HASH:
            if not re.fullmatch(
                r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}",
                value,
            ):
                raise ValueError("invalid hash")

        elif ioc_type == IOCType.EMAIL:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                raise ValueError("invalid email")

        return value
