"""Burp Suite XML 导出解析器"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from src.models.schemas import (
    ScanResult,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.parsers.base import BaseParser, register_parser

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "info": Severity.INFO,
}


@register_parser
class BurpParser(BaseParser):
    tool_type = ToolType.BURP
    supported_extensions = [".xml"]

    def can_parse(self, file_path: Path) -> bool:
        if not super().can_parse(file_path):
            return False
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")[:2000]
            return "<issues" in text or "<issue>" in text or "burp" in text.lower()
        except Exception:
            return False

    def parse(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Burp 有两种 XML 格式：旧版 <issues> 和新版逐 issue
        for issue in root.iter("issue"):
            vuln = self._parse_issue(issue)
            if vuln:
                result.vulnerabilities.append(vuln)

        result.raw_summary = f"Burp Suite 扫描完成，发现 {len(result.vulnerabilities)} 个问题"
        return result

    def _parse_issue(self, elem: ET.Element) -> VulnerabilityFinding | None:
        name = self._get_text(elem, "name", "")
        if not name:
            return None

        severity_str = self._get_text(elem, "severity", "info").lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

        host = self._get_text(elem, "host", "")
        path = self._get_text(elem, "path", "")
        affected = f"{host}{path}"

        # 详细信息
        description = self._get_text(elem, "issueBackground", "")
        detail = self._get_text(elem, "issueDetail", "")
        if detail:
            description = f"{description}\n\n{detail}".strip()

        # 请求/响应作为证据
        request = self._get_text(elem, "requestresponse/request", "")
        response = self._get_text(elem, "requestresponse/response", "")
        evidence_parts = []
        if request:
            evidence_parts.append(f"Request:\n{request[:1000]}")
        if response:
            evidence_parts.append(f"Response:\n{response[:1000]}")
        evidence = "\n\n".join(evidence_parts)

        # CWE
        cwe_text = self._get_text(elem, "type", "")
        cwe_ids = []
        if cwe_text.isdigit():
            cwe_ids = [f"CWE-{cwe_text}"]

        # 修复建议
        remediation = self._get_text(elem, "remediationBackground", "")

        # 分类
        classification = self._get_text(elem, "vulnerabilityClassifications", "")
        owasp = ""
        if "A0" in classification:
            owasp_match = classification.split("A0")[1][:10]
            owasp = f"A0{owasp_match}"

        return VulnerabilityFinding(
            name=name,
            description=description,
            severity=severity,
            cwe_ids=cwe_ids,
            owasp_category=owasp,
            affected_asset=affected,
            evidence=evidence,
            remediation=remediation,
            tool_source=ToolType.BURP,
        )

    @staticmethod
    def _get_text(elem: ET.Element, tag: str, default: str = "") -> str:
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
