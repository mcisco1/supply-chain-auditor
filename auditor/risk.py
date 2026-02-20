from .models import Dependency, PackageAudit, ScanResult, Severity, Vulnerability

RISKY_LICENSES = {
    "GPL", "AGPL", "SSPL", "EUPL", "OSL",
    "GPL-2.0", "GPL-3.0", "AGPL-3.0",
    "GNU General Public License",
    "GNU Affero General Public License",
}


def _license_risk(dep: Dependency) -> float:
    """Return a small risk bump for restrictive or unknown licenses."""
    if not dep.license_type or dep.license_type == "Unknown":
        return 0.3
    for keyword in RISKY_LICENSES:
        if keyword.lower() in dep.license_type.lower():
            return 0.5
    return 0.0


def score_package(dep: Dependency, vulns: list) -> PackageAudit:
    """
    Calculate a 0-10 risk score for a single package.
    Factors:
      - Number and severity of known vulnerabilities
      - Whether the package is outdated
      - Dependency depth (transitive deps are harder to patch)
      - License risk
    """
    score = 0.0

    severity_weights = {
        Severity.CRITICAL: 3.0,
        Severity.HIGH: 2.0,
        Severity.MEDIUM: 1.0,
        Severity.LOW: 0.4,
        Severity.NONE: 0.1,
    }

    for v in vulns:
        weight = severity_weights.get(v.severity, 0.1)
        cvss_factor = v.cvss_score / 10.0 if v.cvss_score > 0 else 0.3
        score += weight * (0.5 + cvss_factor)

    if dep.is_outdated:
        score += 0.8

    if dep.depth > 0:
        score += min(dep.depth * 0.15, 0.6)

    score += _license_risk(dep)

    score = min(score, 10.0)

    audit = PackageAudit(
        dependency=dep,
        vulnerabilities=vulns,
        risk_score=score,
        risk_level=_score_to_level(score),
    )
    return audit


def _score_to_level(score: float) -> Severity:
    """Map a numeric risk score to a severity level."""
    if score >= 8.0:
        return Severity.CRITICAL
    elif score >= 5.5:
        return Severity.HIGH
    elif score >= 3.0:
        return Severity.MEDIUM
    elif score > 0.5:
        return Severity.LOW
    return Severity.NONE


def compute_overall_risk(scan: ScanResult) -> None:
    """
    Calculate the aggregate risk score for the entire scan.
    Uses a weighted average biased toward the most severe findings.
    """
    if not scan.audits:
        scan.overall_risk_score = 0.0
        scan.overall_risk_level = Severity.NONE
        return

    max_score = max(a.risk_score for a in scan.audits)

    vuln_audits = [a for a in scan.audits if a.vulnerabilities]
    if not vuln_audits:
        avg = sum(a.risk_score for a in scan.audits) / len(scan.audits)
        scan.overall_risk_score = min(avg, 10.0)
        scan.overall_risk_level = _score_to_level(scan.overall_risk_score)
        return

    weighted_sum = sum(a.risk_score ** 1.5 for a in vuln_audits)
    weighted_count = sum(a.risk_score ** 0.5 for a in vuln_audits) or 1
    weighted_avg = weighted_sum / weighted_count

    overall = (0.6 * max_score) + (0.4 * weighted_avg)
    scan.overall_risk_score = min(overall, 10.0)
    scan.overall_risk_level = _score_to_level(scan.overall_risk_score)
