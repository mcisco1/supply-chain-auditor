import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def generate_html_report(scan: ScanResult, output_path: str) -> str:
    """
    Render an interactive HTML dashboard from the scan results.
    Returns the absolute path to the generated file.
    """
    template_file = TEMPLATE_DIR / "report_template.html"
    if not template_file.exists():
        raise FileNotFoundError(f"Report template not found at {template_file}")

    template = template_file.read_text(encoding="utf-8")

    report_data = scan.to_dict()
    report_data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    data_json = json.dumps(report_data, indent=None, default=str)
    html = template.replace("/*__SCAN_DATA__*/", data_json)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", out.resolve())
    return str(out.resolve())


def generate_json_report(scan: ScanResult, output_path: str) -> str:
    """Export scan results as formatted JSON."""
    report_data = scan.to_dict()
    report_data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    logger.info("JSON report written to %s", out.resolve())
    return str(out.resolve())
