"""Nikto Web 服务器扫描器输出解析器"""

from __future__ import annotations

import re
from pathlib import Path

from src.models.schemas import (
    ScanResult,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.parsers.base import BaseParser, register_parser


@register_parser
class NiktoParser(BaseParser):
    tool_type = ToolType.NIKTO
    supported_extensions = [".txt", ".log", ".csv"]

    def can_parse(self, file_path: Path) -> bool:
        if not super().can_parse(file_path):
            return False
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")[:3000]
            # Nikto 输出特征
            markers = [
                "nikto",
                "- Nikto",
                "OSVDB",
                "Server:",
                "Target IP:",
                "Target Hostname:",
                "Start Time:",
                "End Time:",
            ]
            text_sample = text[:2000].lower()
            return sum(1 for m in markers if m.lower() in text_sample) >= 2
        except Exception:
            return False

    def parse(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        text = file_path.read_text(encoding="utf-8", errors="replace")

        # 解析目标信息
        target_info = self._extract_target_info(text)
        result.target = target_info.get("target", "")
        result.metadata.update(target_info)

        # 解析漏洞发现
        vulns = self._extract_findings(text, result.target)
        result.vulnerabilities.extend(vulns)

        # 解析服务器信息
        server_info = self._extract_server_info(text)
        if server_info:
            result.metadata["server"] = server_info

        result.raw_summary = f"Nikto 扫描完成，发现 {len(result.vulnerabilities)} 个问题"
        return result

    def _extract_target_info(self, text: str) -> dict[str, str]:
        """提取目标信息"""
        info = {}

        # 目标 IP
        ip_match = re.search(r"Target IP:\s*(\S+)", text)
        if ip_match:
            info["target_ip"] = ip_match.group(1)

        # 目标主机名
        host_match = re.search(r"Target Hostname:\s*(\S+)", text)
        if host_match:
            info["target_hostname"] = host_match.group(1)

        # 目标端口
        port_match = re.search(r"Target Port:\s*(\d+)", text)
        if port_match:
            info["target_port"] = port_match.group(1)

        # 扫描时间
        start_match = re.search(r"Start Time:\s*(.+?)(?:\n|$)", text)
        if start_match:
            info["scan_start"] = start_match.group(1).strip()

        end_match = re.search(r"End Time:\s*(.+?)(?:\n|$)", text)
        if end_match:
            info["scan_end"] = end_match.group(1).strip()

        # 构建目标字符串
        if "target_hostname" in info:
            info["target"] = info["target_hostname"]
        elif "target_ip" in info:
            info["target"] = info["target_ip"]

        if "target_port" in info:
            info["target"] = f"{info.get('target', '')}:{info['target_port']}"

        return info

    def _extract_server_info(self, text: str) -> str:
        """提取服务器信息"""
        server_match = re.search(r"Server:\s*(.+?)(?:\n|$)", text)
        if server_match:
            return server_match.group(1).strip()
        return ""

    def _extract_findings(self, text: str, target: str) -> list[VulnerabilityFinding]:
        """提取漏洞发现"""
        vulns = []

        # Nikto 发现格式: + OSVDB-XXXX: /path: description
        # 或者: + /path: description
        pattern = r"\+\s+(?:OSVDB-(\d+):\s+)?(/\S+):\s+(.+?)(?:\n|$)"
        for match in re.finditer(pattern, text):
            osvdb_id = match.group(1)
            path = match.group(2)
            description = match.group(3).strip()

            # 跳过非漏洞行
            if self._is_info_line(description):
                continue

            # 构建漏洞
            vuln = VulnerabilityFinding(
                name=self._generate_vuln_name(description, osvdb_id),
                description=description,
                severity=self._estimate_severity(description, osvdb_id),
                affected_asset=f"{target}{path}" if target else path,
                affected_component=path,
                evidence=match.group(0).strip(),
                tool_source=ToolType.NIKTO,
                cwe_ids=self._extract_cwe_from_description(description),
            )

            # 添加 OSVDB 引用
            if osvdb_id:
                vuln.references.append(f"OSVDB-{osvdb_id}")
                vuln.cve_ids.append(f"OSVDB-{osvdb_id}")

            vulns.append(vuln)

        # 提取其他类型的发现
        vulns.extend(self._extract_other_findings(text, target))

        return vulns

    def _is_info_line(self, description: str) -> bool:
        """判断是否为信息性行（非漏洞）"""
        info_patterns = [
            r"^Server:",
            r"^Target",
            r"^Start Time",
            r"^End Time",
            r"^Host\(s\) tested",
            r"^Testing",
            r"^Completed",
        ]
        for pattern in info_patterns:
            if re.match(pattern, description, re.IGNORECASE):
                return True
        return False

    def _generate_vuln_name(self, description: str, osvdb_id: str | None) -> str:
        """生成漏洞名称"""
        if osvdb_id:
            return f"OSVDB-{osvdb_id}: {description[:80]}"
        return description[:100]

    def _estimate_severity(self, description: str, osvdb_id: str | None) -> Severity:
        """估算漏洞严重程度"""
        desc_lower = description.lower()

        # 高危关键词
        high_keywords = [
            "remote code execution",
            "command injection",
            "sql injection",
            "file inclusion",
            "directory traversal",
            "authentication bypass",
            "default password",
            "default credential",
            "backdoor",
            "shell",
            "exec",
        ]

        # 中危关键词
        medium_keywords = [
            "xss",
            "cross-site scripting",
            "information disclosure",
            "directory listing",
            "backup",
            "config",
            "admin",
            "phpinfo",
            "server-info",
            "server-status",
        ]

        # 低危关键词
        low_keywords = [
            "cookie",
            "header",
            "version",
            "banner",
            "deprecated",
            "trace",
            "options",
        ]

        for kw in high_keywords:
            if kw in desc_lower:
                return Severity.HIGH

        for kw in medium_keywords:
            if kw in desc_lower:
                return Severity.MEDIUM

        for kw in low_keywords:
            if kw in desc_lower:
                return Severity.LOW

        # 默认为中危
        return Severity.MEDIUM

    def _extract_cwe_from_description(self, description: str) -> list[str]:
        """从描述中提取 CWE"""
        cwe_ids = []
        desc_lower = description.lower()

        # CWE 映射
        cwe_mapping = {
            "xss": "CWE-79",
            "cross-site scripting": "CWE-79",
            "sql injection": "CWE-89",
            "command injection": "CWE-78",
            "directory traversal": "CWE-22",
            "path traversal": "CWE-22",
            "file inclusion": "CWE-98",
            "authentication bypass": "CWE-287",
            "default password": "CWE-798",
            "default credential": "CWE-798",
            "information disclosure": "CWE-200",
            "directory listing": "CWE-548",
            "backup": "CWE-530",
            "phpinfo": "CWE-200",
            "server-info": "CWE-200",
            "server-status": "CWE-200",
        }

        for keyword, cwe in cwe_mapping.items():
            if keyword in desc_lower:
                if cwe not in cwe_ids:
                    cwe_ids.append(cwe)

        return cwe_ids

    def _extract_other_findings(self, text: str, target: str) -> list[VulnerabilityFinding]:
        """提取其他类型的发现"""
        vulns = []

        # 提取 HTTP 方法允许的发现
        method_pattern = r"\+\s+(?:Allowed HTTP Methods):\s*(.+?)(?:\n|$)"
        for match in re.finditer(method_pattern, text, re.IGNORECASE):
            methods = match.group(1).strip()
            vuln = VulnerabilityFinding(
                name=f"HTTP Methods Allowed: {methods}",
                description=f"服务器允许以下 HTTP 方法: {methods}",
                severity=Severity.LOW,
                affected_asset=target,
                evidence=match.group(0).strip(),
                tool_source=ToolType.NIKTO,
                cwe_ids=["CWE-16"],
            )
            vulns.append(vuln)

        # 提取 X-Frame-Options 缺失
        if "X-Frame-Options" in text and "not set" in text.lower():
            vuln = VulnerabilityFinding(
                name="X-Frame-Options Header Missing",
                description="服务器未设置 X-Frame-Options 头，可能存在点击劫持风险",
                severity=Severity.LOW,
                affected_asset=target,
                evidence="X-Frame-Options header is not set",
                tool_source=ToolType.NIKTO,
                cwe_ids=["CWE-1021"],
            )
            vulns.append(vuln)

        # 提取 X-Content-Type-Options 缺失
        if "X-Content-Type-Options" in text and "not set" in text.lower():
            vuln = VulnerabilityFinding(
                name="X-Content-Type-Options Header Missing",
                description="服务器未设置 X-Content-Type-Options 头，可能存在 MIME 类型混淆风险",
                severity=Severity.LOW,
                affected_asset=target,
                evidence="X-Content-Type-Options header is not set",
                tool_source=ToolType.NIKTO,
                cwe_ids=["CWE-16"],
            )
            vulns.append(vuln)

        return vulns
