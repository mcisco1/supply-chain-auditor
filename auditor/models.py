from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from packaging.version import Version, InvalidVersion


class Ecosystem(Enum):
    PYTHON = "PyPI"
    NODE = "npm"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.NONE


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: Ecosystem
    is_direct: bool = True
    latest_version: Optional[str] = None
    license_type: Optional[str] = None
    description: Optional[str] = None
    children: list = field(default_factory=list)
    depth: int = 0

    @property
    def is_outdated(self) -> bool:
        if not self.latest_version or not self.version:
            return False
        try:
            return Version(self.version) < Version(self.latest_version)
        except InvalidVersion:
            return self.version != self.latest_version

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "is_direct": self.is_direct,
            "latest_version": self.latest_version,
            "license": self.license_type,
            "description": self.description,
            "is_outdated": self.is_outdated,
            "depth": self.depth,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class Vulnerability:
    vuln_id: str
    source: str
    summary: str
    severity: Severity
    cvss_score: float = 0.0
    affected_versions: str = ""
    fixed_version: Optional[str] = None
    references: list = field(default_factory=list)
    published: Optional[str] = None
    cwe_ids: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.vuln_id,
            "source": self.source,
            "summary": self.summary,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "affected_versions": self.affected_versions,
            "fixed_version": self.fixed_version,
            "references": self.references,
            "published": self.published,
            "cwe_ids": self.cwe_ids,
        }


@dataclass
class PackageAudit:
    dependency: Dependency
    vulnerabilities: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: Severity = Severity.NONE

    def to_dict(self) -> dict:
        return {
            "package": self.dependency.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value,
        }


@dataclass
class ScanResult:
    target_path: str
    ecosystems_found: list = field(default_factory=list)
    total_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    audits: list = field(default_factory=list)
    dependency_tree: list = field(default_factory=list)
    scan_duration: float = 0.0
    overall_risk_score: float = 0.0
    overall_risk_level: Severity = Severity.NONE

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(a.vulnerabilities) for a in self.audits)

    @property
    def critical_count(self) -> int:
        return self._count_by_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_by_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_by_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_by_severity(Severity.LOW)

    @property
    def outdated_count(self) -> int:
        return sum(1 for a in self.audits if a.dependency.is_outdated)

    @property
    def vulnerable_packages(self) -> list:
        return [a for a in self.audits if a.vulnerabilities]

    def _count_by_severity(self, sev: Severity) -> int:
        count = 0
        for audit in self.audits:
            for v in audit.vulnerabilities:
                if v.severity == sev:
                    count += 1
        return count

    def to_dict(self) -> dict:
        return {
            "target_path": self.target_path,
            "ecosystems": [e.value for e in self.ecosystems_found],
            "total_dependencies": self.total_dependencies,
            "direct_dependencies": self.direct_dependencies,
            "transitive_dependencies": self.transitive_dependencies,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "outdated_count": self.outdated_count,
            "overall_risk_score": round(self.overall_risk_score, 1),
            "overall_risk_level": self.overall_risk_level.value,
            "scan_duration": round(self.scan_duration, 2),
            "audits": [a.to_dict() for a in self.audits],
            "dependency_tree": [d.to_dict() for d in self.dependency_tree],
        }
