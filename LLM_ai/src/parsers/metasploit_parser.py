"""Metasploit workspace XML 导出解析器"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from src.models.schemas import (
    HostInfo,
    ScanResult,
    ServiceInfo,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.parsers.base import BaseParser, register_parser


@register_parser
class MetasploitParser(BaseParser):
    tool_type = ToolType.METASPLOIT
    supported_extensions = [".xml"]

    def can_parse(self, file_path: Path) -> bool:
        if not super().can_parse(file_path):
            return False
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")[:3000]
            # Metasploit db_export XML 特征
            markers = ["metasploit", "hosts", "services", "vulns", "loots", "creds"]
            text_lower = text.lower()
            return sum(1 for m in markers if m in text_lower) >= 2
        except Exception:
            return False

    def parse(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        tree = ET.parse(file_path)
        root = tree.getroot()

        # 解析主机
        for host_elem in root.iter("host"):
            host = self._parse_host(host_elem)
            result.hosts.append(host)

        # 解析漏洞
        for vuln_elem in root.iter("vuln"):
            vuln = self._parse_vuln(vuln_elem)
            if vuln:
                result.vulnerabilities.append(vuln)

        # 解析凭据
        for cred_elem in root.iter("cred"):
            cred = self._parse_cred(cred_elem)
            if cred:
                result.vulnerabilities.append(cred)

        # 解析 loot
        for loot_elem in root.iter("loot"):
            loot_info = self._parse_loot(loot_elem)
            if loot_info:
                result.metadata.setdefault("loots", []).append(loot_info)

        result.raw_summary = (
            f"Metasploit 扫描完成: "
            f"{len(result.hosts)} 台主机, "
            f"{len(result.vulnerabilities)} 个发现"
        )
        return result

    def _parse_host(self, elem: ET.Element) -> HostInfo:
        ip = self._get_text(elem, "addr", "")
        hostname = self._get_text(elem, "name", "")
        os = self._get_text(elem, "os-name", "")
        state = self._get_text(elem, "state", "alive")

        host = HostInfo(ip=ip, hostname=hostname, os=os, state=state)

        # 解析该主机的服务
        for svc_elem in elem.findall(".//service"):
            svc = ServiceInfo(
                host=ip,
                port=int(self._get_text(svc_elem, "port", "0")),
                protocol=self._get_text(svc_elem, "proto", "tcp"),
                service=self._get_text(svc_elem, "name", ""),
                version=self._get_text(svc_elem, "info", ""),
                state=self._get_text(svc_elem, "state", "open"),
            )
            host.services.append(svc)

        return host

    def _parse_vuln(self, elem: ET.Element) -> VulnerabilityFinding | None:
        name = self._get_text(elem, "name", "")
        if not name:
            return None

        host = self._get_text(elem, "host", "")
        port = self._get_text(elem, "port", "")
        proto = self._get_text(elem, "proto", "tcp")
        affected = f"{host}:{port}/{proto}" if port else host

        refs = []
        for ref_elem in elem.findall(".//ref"):
            ref_text = ref_elem.text or ""
            if ref_text:
                refs.append(ref_text)

        cve_ids = [r for r in refs if r.startswith("CVE-")]
        cwe_ids = [r for r in refs if r.startswith("CWE-")]

        return VulnerabilityFinding(
            name=name,
            description=self._get_text(elem, "info", ""),
            severity=Severity.MEDIUM,  # Metasploit 通常不直接给 severity
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            affected_asset=affected,
            references=[r for r in refs if r.startswith("http")],
            tool_source=ToolType.METASPLOIT,
            raw_data={"refs": refs},
        )

    def _parse_cred(self, elem: ET.Element) -> VulnerabilityFinding | None:
        host = self._get_text(elem, "host", "")
        port = self._get_text(elem, "port", "")
        user = self._get_text(elem, "user", "")
        pass_text = self._get_text(elem, "pass", "")
        ptype = self._get_text(elem, "ptype", "")

        if not (host and (user or pass_text)):
            return None

        evidence = f"Type: {ptype}, User: {user}, Pass: {'*' * len(pass_text) if pass_text else '(hash)'}"
        return VulnerabilityFinding(
            name=f"Weak Credential - {host}:{port}",
            description=f"在 {host}:{port} 发现弱凭据",
            severity=Severity.HIGH,
            cwe_ids=["CWE-798"],
            affected_asset=f"{host}:{port}",
            evidence=evidence,
            remediation="更改默认/弱密码，使用强密码策略",
            tool_source=ToolType.METASPLOIT,
        )

    def _parse_loot(self, elem: ET.Element) -> dict | None:
        ltype = self._get_text(elem, "ltype", "")
        name = self._get_text(elem, "name", "")
        host = self._get_text(elem, "host", "")
        if not name:
            return None
        return {"type": ltype, "name": name, "host": host}

    @staticmethod
    def _get_text(elem: ET.Element, tag: str, default: str = "") -> str:
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
