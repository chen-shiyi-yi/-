"""Nuclei JSON/JSONL 输出解析器"""

from __future__ import annotations

import json
from pathlib import Path

from src.models.schemas import (
    ScanResult,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.parsers.base import BaseParser, register_parser

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register_parser
class NucleiParser(BaseParser):
    tool_type = ToolType.NUCLEI
    supported_extensions = [".json", ".jsonl", ".ndjson"]

    def parse(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        findings = self._read_jsonl(file_path)

        for item in findings:
            vuln = self._to_finding(item)
            if vuln:
                result.vulnerabilities.append(vuln)
                # 从 host 字段提取目标资产
                target = item.get("host", "")
                if target and not any(h.ip == target for h in result.hosts):
                    result.metadata.setdefault("targets", []).append(target)

        result.raw_summary = f"Nuclei 扫描完成，发现 {len(result.vulnerabilities)} 个漏洞"
        return result

    def _read_jsonl(self, file_path: Path) -> list[dict]:
        """读取 JSONL 或 JSON 文件"""
        text = file_path.read_text(encoding="utf-8", errors="replace")
        items = []

        # 尝试 JSONL（每行一个 JSON）
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        # 如果 JSONL 没解析到，尝试完整 JSON
        if not items:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    items = data
                else:
                    items = [data]
            except json.JSONDecodeError:
                pass

        return items

    def _to_finding(self, item: dict) -> VulnerabilityFinding | None:
        template_id = item.get("template-id", item.get("templateID", ""))
        info = item.get("info", {})
        if not info and not template_id:
            return None

        name = info.get("name", template_id)
        description = info.get("description", "")
        raw_severity = info.get("severity", "info").lower()
        severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

        # CVE / CWE
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cwe_ids = classification.get("cwe-id") or []
        if isinstance(cwe_ids, int):
            cwe_ids = [str(cwe_ids)]
        elif isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        cvss_score = classification.get("cvss-score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        # 匹配信息
        matched_at = item.get("matched-at", item.get("matched", ""))
        host = item.get("host", "")
        matcher_name = item.get("matcher-name", "")
        extracted = item.get("extracted-results", [])

        # 复现步骤（curl 命令）
        curl_cmd = item.get("curl-command", "")
        repro_steps = []
        if curl_cmd:
            repro_steps = [curl_cmd]

        evidence_lines = []
        if matcher_name:
            evidence_lines.append(f"Matcher: {matcher_name}")
        if extracted:
            evidence_lines.append(f"Extracted: {', '.join(str(e) for e in extracted)}")
        evidence = "\n".join(evidence_lines)

        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]

        return VulnerabilityFinding(
            id=template_id,
            name=name,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            affected_asset=matched_at or host,
            evidence=evidence,
            reproduction_steps=repro_steps,
            remediation=info.get("remediation", ""),
            tool_source=ToolType.NUCLEI,
            references=references,
            raw_data=item,
        )
