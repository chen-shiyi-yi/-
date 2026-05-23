"""Nmap 输出解析器 - 支持 XML 和普通文本格式"""

from __future__ import annotations

import re
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
class NmapParser(BaseParser):
    tool_type = ToolType.NMAP
    supported_extensions = [".xml", ".nmap"]

    def parse(self, file_path: Path) -> ScanResult:
        if file_path.suffix.lower() == ".xml":
            return self._parse_xml(file_path)
        return self._parse_text(file_path)

    def _parse_xml(self, file_path: Path) -> ScanResult:
        result = self._make_result(file_path)
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host_elem in root.findall(".//host"):
            host = self._parse_host_xml(host_elem)
            result.hosts.append(host)

            # Nmap 脚本输出中可能包含漏洞信息
            for script in host_elem.findall(".//script"):
                vulns = self._extract_vulns_from_script(script, host.ip)
                result.vulnerabilities.extend(vulns)

        result.raw_summary = f"Nmap 扫描完成，发现 {len(result.hosts)} 台主机"
        return result

    def _parse_host_xml(self, elem: ET.Element) -> HostInfo:
        ip = ""
        hostname = ""
        addr_elem = elem.find("address[@addrtype='ipv4']")
        if addr_elem is not None:
            ip = addr_elem.get("addr", "")
        hostname_elem = elem.find("hostnames/hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

        state = "up"
        status = elem.find("status")
        if status is not None:
            state = status.get("state", "up")

        os_name = ""
        os_match = elem.find(".//osmatch")
        if os_match is not None:
            os_name = os_match.get("name", "")

        host = HostInfo(ip=ip, hostname=hostname, os=os_name, state=state)

        for port_elem in elem.findall(".//port"):
            service = self._parse_port(port_elem)
            host.services.append(service)

        return host

    def _parse_port(self, elem: ET.Element) -> ServiceInfo:
        portid = int(elem.get("portid", 0))
        protocol = elem.get("protocol", "tcp")

        state = "open"
        state_elem = elem.find("state")
        if state_elem is not None:
            state = state_elem.get("state", "open")

        service_elem = elem.find("service")
        service_name = ""
        version = ""
        banner = ""
        extra = {}
        if service_elem is not None:
            service_name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            ver = service_elem.get("version", "")
            version = f"{product} {ver}".strip()
            banner = service_elem.get("extrainfo", "")
            extra = {
                "product": product,
                "version": ver,
                "ostype": service_elem.get("ostype", ""),
                "method": service_elem.get("method", ""),
            }

        return ServiceInfo(
            host="",  # 将在 HostInfo 层面关联
            port=portid,
            protocol=protocol,
            service=service_name,
            version=version,
            state=state,
            banner=banner,
            extra=extra,
        )

    def _extract_vulns_from_script(self, script: ET.Element, host: str) -> list[VulnerabilityFinding]:
        """从 Nmap NSE 脚本输出中提取漏洞"""
        vulns = []
        script_id = script.get("id", "")
        output = script.get("output", "")

        # vulners 脚本
        if "vulners" in script_id:
            for table in script.findall(".//table"):
                cve = ""
                cvss = None
                for elem in table.findall("elem"):
                    key = elem.get("key", "")
                    val = elem.text or ""
                    if key == "id":
                        cve = val
                    elif key == "CVSS":
                        try:
                            cvss = float(val)
                        except ValueError:
                            pass
                if cve:
                    vulns.append(VulnerabilityFinding(
                        name=cve,
                        cve_ids=[cve],
                        cvss_score=cvss,
                        severity=self._cvss_to_severity(cvss) if cvss else Severity.INFO,
                        affected_asset=host,
                        tool_source=ToolType.NMAP,
                        evidence=output,
                    ))

        # vuln 类脚本
        if "vuln" in script_id and "VULNERABLE" in output.upper():
            vulns.append(VulnerabilityFinding(
                name=script_id,
                description=output[:500],
                severity=Severity.MEDIUM,
                affected_asset=host,
                tool_source=ToolType.NMAP,
                evidence=output,
            ))

        return vulns

    def _parse_text(self, file_path: Path) -> ScanResult:
        """解析 nmap 普通文本输出"""
        result = self._make_result(file_path)
        text = file_path.read_text(encoding="utf-8", errors="replace")

        current_host = ""
        current_ip = ""
        current_host_obj = None

        for line in text.splitlines():
            # 主机行
            host_match = re.match(r"Nmap scan report for\s+(\S+)\s*\(?([\d.]+)?\)?", line)
            if host_match:
                current_host = host_match.group(1)
                current_ip = host_match.group(2) or current_host

                # 查找或创建主机对象
                current_host_obj = None
                for h in result.hosts:
                    if h.ip == current_ip:
                        current_host_obj = h
                        break
                if current_host_obj is None:
                    current_host_obj = HostInfo(ip=current_ip, hostname=current_host)
                    result.hosts.append(current_host_obj)
                continue

            # 端口行
            port_match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line)
            if port_match and current_host_obj:
                port = int(port_match.group(1))
                proto = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip()

                current_host_obj.services.append(ServiceInfo(
                    host=current_ip,
                    port=port,
                    protocol=proto,
                    service=service,
                    version=version,
                    state=state,
                ))

        result.raw_summary = f"Nmap 扫描完成，发现 {len(result.hosts)} 台主机"
        return result

    @staticmethod
    def _cvss_to_severity(score: float | None) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO
