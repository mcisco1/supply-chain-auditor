"""
Tests for the Supply Chain Dependency Auditor.

Covers parsers, risk scoring, deduplication, version comparison,
CVSS calculation, NVD filtering, severity classification, tree
flattening, and overall risk computation.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from auditor.models import Dependency, Ecosystem, PackageAudit, ScanResult, Severity, Vulnerability
from auditor.parsers import (
    _clean_version,
    parse_requirements_txt,
    parse_package_json,
    parse_pyproject_toml,
    scan_directory,
)
from auditor.resolver import flatten_tree
from auditor.risk import score_package, compute_overall_risk, _score_to_level
from auditor.vulnerability import (
    _cvss_v3_base_score,
    _deduplicate,
    _is_nvd_relevant,
    _vuln_map_key,
)


# ---------------------------------------------------------------------------
# 1. Parser: requirements.txt
# ---------------------------------------------------------------------------

class TestParseRequirementsTxt:
    def test_basic_pinned_versions(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.2.0\nrequests==2.28.0\n")
        result = parse_requirements_txt(str(req))
        assert ("flask", "2.2.0") in result
        assert ("requests", "2.28.0") in result

    def test_skips_comments_and_blanks(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n\nflask==1.0\n-r other.txt\n")
        result = parse_requirements_txt(str(req))
        assert len(result) == 1
        assert result[0][0] == "flask"

    def test_gte_and_compatible(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.20.0,<3\nnumpy~=1.23\n")
        result = parse_requirements_txt(str(req))
        names = [n for n, _ in result]
        assert "requests" in names
        assert "numpy" in names


# ---------------------------------------------------------------------------
# 2. Parser: package.json
# ---------------------------------------------------------------------------

class TestParsePackageJson:
    def test_both_dep_sections(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.17.1", "lodash": "4.17.20"},
            "devDependencies": {"mocha": "~9.2.0"},
        }))
        result = parse_package_json(str(pkg))
        names = [n for n, _ in result]
        assert "express" in names
        assert "lodash" in names
        assert "mocha" in names

    def test_empty_package_json(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        assert parse_package_json(str(pkg)) == []


# ---------------------------------------------------------------------------
# 3. Parser: _clean_version
# ---------------------------------------------------------------------------

class TestCleanVersion:
    def test_strips_caret_and_tilde(self):
        assert _clean_version("^4.17.1") == "4.17.1"
        assert _clean_version("~9.2.0") == "9.2.0"

    def test_strips_gte(self):
        assert _clean_version(">=2.20.0") == "2.20.0"

    def test_strips_extras(self):
        assert _clean_version("requests[security]>=2.20") == "2.20"

    def test_empty_string(self):
        assert _clean_version("") == ""


# ---------------------------------------------------------------------------
# 4. Version comparison: is_outdated
# ---------------------------------------------------------------------------

class TestIsOutdated:
    def test_semantic_comparison(self):
        dep = Dependency(name="pkg", version="1.0.0", ecosystem=Ecosystem.PYTHON,
                         latest_version="2.0.0")
        assert dep.is_outdated is True

    def test_same_version_not_outdated(self):
        dep = Dependency(name="pkg", version="2.0.0", ecosystem=Ecosystem.PYTHON,
                         latest_version="2.0.0")
        assert dep.is_outdated is False

    def test_normalised_equal(self):
        """'1.0' and '1.0.0' should be treated as equal (not outdated)."""
        dep = Dependency(name="pkg", version="1.0", ecosystem=Ecosystem.PYTHON,
                         latest_version="1.0.0")
        assert dep.is_outdated is False

    def test_missing_latest_not_outdated(self):
        dep = Dependency(name="pkg", version="1.0.0", ecosystem=Ecosystem.PYTHON,
                         latest_version=None)
        assert dep.is_outdated is False


# ---------------------------------------------------------------------------
# 5. Severity classification
# ---------------------------------------------------------------------------

class TestSeverityFromCvss:
    def test_critical(self):
        assert Severity.from_cvss(9.8) == Severity.CRITICAL

    def test_high(self):
        assert Severity.from_cvss(7.5) == Severity.HIGH

    def test_medium(self):
        assert Severity.from_cvss(5.0) == Severity.MEDIUM

    def test_low(self):
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_none(self):
        assert Severity.from_cvss(0.0) == Severity.NONE


# ---------------------------------------------------------------------------
# 6. CVSS v3 base score calculation
# ---------------------------------------------------------------------------

class TestCvssV3BaseScore:
    def test_critical_vector(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = _cvss_v3_base_score(vector)
        assert score == 9.8

    def test_medium_vector(self):
        """CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N → 3.7"""
        vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
        score = _cvss_v3_base_score(vector)
        assert 3.0 <= score <= 5.0

    def test_invalid_vector_returns_zero(self):
        assert _cvss_v3_base_score("garbage") == 0.0

    def test_scope_changed(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score = _cvss_v3_base_score(vector)
        assert score == 10.0


# ---------------------------------------------------------------------------
# 7. Risk scoring with vulnerabilities
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_high_vuln_gives_high_score(self):
        dep = Dependency(name="vuln-pkg", version="1.0", ecosystem=Ecosystem.PYTHON,
                         latest_version="2.0")
        vulns = [
            Vulnerability(vuln_id="CVE-1", source="NVD", summary="bad",
                          severity=Severity.CRITICAL, cvss_score=9.8),
        ]
        audit = score_package(dep, vulns)
        assert audit.risk_score >= 4.0
        assert audit.risk_level in (Severity.HIGH, Severity.CRITICAL)

    def test_no_vulns_low_score(self):
        dep = Dependency(name="safe", version="1.0", ecosystem=Ecosystem.PYTHON,
                         latest_version="1.0")
        audit = score_package(dep, [])
        assert audit.risk_score < 2.0


# ---------------------------------------------------------------------------
# 8. Deduplication logic
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_removes_duplicate_ids(self):
        v1 = Vulnerability(vuln_id="CVE-2023-001", source="OSV", summary="a",
                           severity=Severity.HIGH, cvss_score=7.0)
        v2 = Vulnerability(vuln_id="CVE-2023-001", source="NVD", summary="a",
                           severity=Severity.HIGH, cvss_score=7.0)
        v3 = Vulnerability(vuln_id="CVE-2023-002", source="NVD", summary="b",
                           severity=Severity.MEDIUM, cvss_score=5.0)
        result = _deduplicate([v1, v2, v3])
        assert len(result) == 2

    def test_keeps_empty_id_vulns(self):
        v1 = Vulnerability(vuln_id="", source="OSV", summary="a",
                           severity=Severity.LOW, cvss_score=2.0)
        v2 = Vulnerability(vuln_id="", source="NVD", summary="b",
                           severity=Severity.LOW, cvss_score=2.0)
        result = _deduplicate([v1, v2])
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 9. NVD relevance filter
# ---------------------------------------------------------------------------

class TestNvdRelevanceFilter:
    def test_matches_description(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "A flaw in flask allows XSS."}],
        }
        assert _is_nvd_relevant("flask", Ecosystem.PYTHON, cve) is True

    def test_rejects_unrelated(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "Bug in unrelated software."}],
        }
        assert _is_nvd_relevant("flask", Ecosystem.PYTHON, cve) is False

    def test_matches_cpe(self):
        cve = {
            "descriptions": [{"lang": "en", "value": "Vulnerability found."}],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{"criteria": "cpe:2.3:a:palletsprojects:flask:*"}]
                }]
            }],
        }
        assert _is_nvd_relevant("flask", Ecosystem.PYTHON, cve) is True


# ---------------------------------------------------------------------------
# 10. Flatten dependency tree
# ---------------------------------------------------------------------------

class TestFlattenTree:
    def test_deduplicates_by_name_and_ecosystem(self):
        child = Dependency(name="shared", version="1.0", ecosystem=Ecosystem.PYTHON)
        dep1 = Dependency(name="pkg1", version="1.0", ecosystem=Ecosystem.PYTHON,
                          children=[child])
        dep2 = Dependency(name="pkg2", version="1.0", ecosystem=Ecosystem.PYTHON,
                          children=[
                              Dependency(name="shared", version="1.0",
                                         ecosystem=Ecosystem.PYTHON)
                          ])
        flat = flatten_tree([dep1, dep2])
        names = [d.name for d in flat]
        assert names.count("shared") == 1

    def test_keeps_different_ecosystems(self):
        py = Dependency(name="debug", version="1.0", ecosystem=Ecosystem.PYTHON)
        node = Dependency(name="debug", version="2.0", ecosystem=Ecosystem.NODE)
        flat = flatten_tree([py, node])
        assert len(flat) == 2


# ---------------------------------------------------------------------------
# 11. Overall risk computation
# ---------------------------------------------------------------------------

class TestOverallRisk:
    def test_no_audits_zero_risk(self):
        scan = ScanResult(target_path="/tmp")
        compute_overall_risk(scan)
        assert scan.overall_risk_score == 0.0
        assert scan.overall_risk_level == Severity.NONE

    def test_high_vuln_raises_overall(self):
        dep = Dependency(name="bad", version="1.0", ecosystem=Ecosystem.PYTHON)
        audit = PackageAudit(
            dependency=dep,
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-1", source="NVD", summary="x",
                              severity=Severity.CRITICAL, cvss_score=9.8),
            ],
            risk_score=9.0,
            risk_level=Severity.CRITICAL,
        )
        scan = ScanResult(target_path="/tmp", audits=[audit])
        compute_overall_risk(scan)
        assert scan.overall_risk_score >= 5.0


# ---------------------------------------------------------------------------
# 12. Vuln map key avoids name collisions
# ---------------------------------------------------------------------------

class TestVulnMapKey:
    def test_different_ecosystems_different_keys(self):
        py = Dependency(name="debug", version="1.0", ecosystem=Ecosystem.PYTHON)
        node = Dependency(name="debug", version="2.0", ecosystem=Ecosystem.NODE)
        assert _vuln_map_key(py) != _vuln_map_key(node)

    def test_key_format(self):
        dep = Dependency(name="flask", version="2.0", ecosystem=Ecosystem.PYTHON)
        assert _vuln_map_key(dep) == "PyPI:flask"


# ---------------------------------------------------------------------------
# 13. scan_directory integration
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_finds_deps_in_sample_project(self):
        sample = Path(__file__).resolve().parent.parent / "sample_project"
        if not sample.exists():
            pytest.skip("sample_project not found")
        py_deps, node_deps = scan_directory(str(sample))
        py_names = [n for n, _ in py_deps]
        node_names = [n for n, _ in node_deps]
        assert "flask" in py_names
        assert "express" in node_names

    def test_missing_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_directory("/nonexistent/path/xyz")


# ---------------------------------------------------------------------------
# 14. Score-to-level mapping
# ---------------------------------------------------------------------------

class TestScoreToLevel:
    def test_boundaries(self):
        assert _score_to_level(10.0) == Severity.CRITICAL
        assert _score_to_level(8.0) == Severity.CRITICAL
        assert _score_to_level(7.9) == Severity.HIGH
        assert _score_to_level(5.5) == Severity.HIGH
        assert _score_to_level(5.4) == Severity.MEDIUM
        assert _score_to_level(3.0) == Severity.MEDIUM
        assert _score_to_level(2.9) == Severity.LOW
        assert _score_to_level(0.6) == Severity.LOW
        assert _score_to_level(0.5) == Severity.NONE
        assert _score_to_level(0.0) == Severity.NONE


# ---------------------------------------------------------------------------
# 15. pyproject.toml parsing
# ---------------------------------------------------------------------------

class TestParsePyprojectToml:
    def test_pep621_dependencies(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text(
            '[project]\nname = "example"\ndependencies = [\n'
            '  "flask>=2.0",\n  "requests==2.28.0",\n]\n'
        )
        result = parse_pyproject_toml(str(toml_file))
        names = [n for n, _ in result]
        assert "flask" in names
        assert "requests" in names
