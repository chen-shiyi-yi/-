"""SQLMap 输出解析器 - 支持 log 和 CSV 格式"""

from __future__ import annotations

import csv
import re
from io import StringIO
from pathlib import Path

from src.models.schemas import (
    ScanResult,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.parsers.base import BaseParser, register_parser


@register_parser
class SqlmapParser(BaseParser):
    tool_type = ToolType.SQLMAP
    supported_extensions = [".log", ".csv", ".txt"]

    def parse(self, file_path: Path) -> ScanResult:
        if file_path.suffix.lower() == ".csv":
            return self._parse_csv(file_path)
        return self._parse_log(file_path)

    def _parse_log(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        text = file_path.read_text(encoding="utf-8", errors="replace")

        current_url = ""
        current_param = ""
        injection_type = ""
        dbms = ""

        for line in text.splitlines():
            line = line.strip()

            # 目标 URL
            url_match = re.search(r"URL:\s*(\S+)", line)
            if url_match:
                current_url = url_match.group(1)

            # 注入参数
            param_match = re.search(r"Parameter:\s*(\S+)\s+\((\w+)\)", line)
            if param_match:
                current_param = param_match.group(1)
                injection_type = param_match.group(2)

            # DBMS
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", line)
            if dbms_match:
                dbms = dbms_match.group(1).strip()

            # 注入类型识别
            type_match = re.search(
                r"Type:\s*(.+?)(?:\s*$)", line
            )
            if type_match and "inject" in line.lower():
                inj_detail = type_match.group(1).strip()
                vuln = VulnerabilityFinding(
                    name=f"SQL Injection - {inj_detail}",
                    description=f"在参数 {current_param} 中发现 {inj_detail}",
                    severity=Severity.CRITICAL,
                    cwe_ids=["CWE-89"],
                    owasp_category="A03:2021 - Injection",
                    affected_asset=current_url,
                    affected_component=f"Parameter: {current_param}",
                    evidence=line,
                    tool_source=ToolType.SQLMAP,
                    impact=f"攻击者可通过 {current_param} 参数执行任意 SQL 查询",
                    remediation="使用参数化查询（Prepared Statements），避免字符串拼接 SQL",
                )
                result.vulnerabilities.append(vuln)

            # 数据库枚举结果
            if "available databases" in line.lower():
                dbs_match = re.search(r"\[(\d+)\]:\s*(.+)", line)
                if dbs_match:
                    result.metadata.setdefault("databases", []).append(dbs_match.group(2))

        # DBMS 信息作为额外发现
        if dbms:
            result.metadata["dbms"] = dbms

        result.raw_summary = f"SQLMap 扫描完成，发现 {len(result.vulnerabilities)} 个注入点"
        return result

    def _parse_csv(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        text = file_path.read_text(encoding="utf-8", errors="replace")

        reader = csv.DictReader(StringIO(text))
        for row in reader:
            title = row.get("title", "")
            url = row.get("URL", row.get("url", ""))
            payload = row.get("payload", "")

            severity = Severity.HIGH
            if any(kw in title.lower() for kw in ["stacked", "time-based", "blind"]):
                severity = Severity.HIGH
            elif "union" in title.lower():
                severity = Severity.CRITICAL

            vuln = VulnerabilityFinding(
                name=title or "SQL Injection",
                description=f"发现 SQL 注入: {title}",
                severity=severity,
                cwe_ids=["CWE-89"],
                owasp_category="A03:2021 - Injection",
                affected_asset=url,
                evidence=f"Payload: {payload}" if payload else "",
                tool_source=ToolType.SQLMAP,
                remediation="使用参数化查询（Prepared Statements）",
            )
            result.vulnerabilities.append(vuln)

        result.raw_summary = f"SQLMap 扫描完成，发现 {len(result.vulnerabilities)} 个注入点"
        return result
