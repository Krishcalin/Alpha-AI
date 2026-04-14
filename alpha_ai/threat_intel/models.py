"""Threat intelligence data models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    FILE_HASH = "file_hash"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class ThreatReport(BaseModel):
    """Structured threat intelligence report — SIEM/SOAR ready."""

    ioc: str
    ioc_type: IOCType
    severity: ThreatSeverity
    confidence: int = Field(ge=0, le=100)
    threat_classification: str
    summary: str
    related_malware: list[str] = Field(default_factory=list)
    related_threat_groups: list[str] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    related_iocs: list[str] = Field(default_factory=list)
    investigated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IPReputation(BaseModel):
    ip: str
    country: str = "Unknown"
    city: str = ""
    asn: str = ""
    isp: str = ""
    abuse_confidence_score: int = 0
    total_reports: int = 0
    last_reported: str = ""
    threat_types: list[str] = Field(default_factory=list)
    known_malware_associations: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    is_tor_exit_node: bool = False
    is_known_proxy: bool = False
    first_seen: str = ""
    tags: list[str] = Field(default_factory=list)
    note: str = ""


class FileReputation(BaseModel):
    hash: str
    hash_type: str = ""
    sha256: str = ""
    detections: int = 0
    total_engines: int = 72
    detection_rate: str = ""
    malware_family: str = "Unknown"
    malware_type: str = ""
    severity: str = "unknown"
    file_type: str = ""
    file_size_bytes: int = 0
    file_name: str = ""
    first_seen: str = ""
    last_seen: str = ""
    tags: list[str] = Field(default_factory=list)
    behavior_summary: str = ""
    contacted_ips: list[str] = Field(default_factory=list)
    contacted_domains: list[str] = Field(default_factory=list)
    note: str = ""


class DomainReputation(BaseModel):
    domain: str
    reputation_score: int = 0
    category: str = "unknown"
    subcategory: str = ""
    active: bool | None = None
    registrar: str = ""
    registration_date: str = ""
    registrant_country: str = ""
    hosting_provider: str = ""
    hosting_country: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ssl_issuer: str = ""
    ssl_valid_from: str = ""
    targeted_brand: str = ""
    similar_domains_found: int = 0
    urlhaus_reference: str = ""
    tags: list[str] = Field(default_factory=list)
    associated_ips_with_other_malicious_domains: bool = False
    dns_records: dict[str, Any] = Field(default_factory=dict)
    note: str = ""


class MitreMapping(BaseModel):
    techniques: list[dict[str, str]] = Field(default_factory=list)
    associated_groups: list[str] = Field(default_factory=list)
    detection_suggestions: list[str] = Field(default_factory=list)
    note: str = ""
