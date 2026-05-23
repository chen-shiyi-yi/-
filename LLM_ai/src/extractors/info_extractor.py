"""信息抽取器 - 合并多工具结果，去重，统一资产视图"""

from __future__ import annotations

from src.models.schemas import HostInfo, ScanResult, ServiceInfo, VulnerabilityFinding


class InfoExtractor:
    """从多个 ScanResult 中抽取并合并信息"""

    def extract(self, scan_results: list[ScanResult]) -> tuple[list[HostInfo], list[VulnerabilityFinding]]:
        """合并所有扫描结果，返回去重后的主机列表和漏洞列表"""
        hosts = self._merge_hosts(scan_results)
        vulns = self._merge_vulnerabilities(scan_results)
        return hosts, vulns

    def _merge_hosts(self, scan_results: list[ScanResult]) -> list[HostInfo]:
        """按 IP 合并主机信息"""
        host_map: dict[str, HostInfo] = {}

        for result in scan_results:
            for host in result.hosts:
                if host.ip in host_map:
                    existing = host_map[host.ip]
                    # 合并 hostname（优先使用更详细的）
                    if host.hostname and not existing.hostname:
                        existing.hostname = host.hostname
                    elif host.hostname and existing.hostname and len(host.hostname) > len(existing.hostname):
                        existing.hostname = host.hostname
                    # 合并 OS（优先使用更详细的）
                    if host.os and not existing.os:
                        existing.os = host.os
                    elif host.os and existing.os and len(host.os) > len(existing.os):
                        existing.os = host.os
                    # 合并服务（去重，基于端口和协议）
                    existing_ports = {(s.port, s.protocol) for s in existing.services}
                    for svc in host.services:
                        if (svc.port, svc.protocol) not in existing_ports:
                            existing.services.append(svc)
                            existing_ports.add((svc.port, svc.protocol))
                        else:
                            # 更新现有服务的版本信息（如果有更详细的）
                            for existing_svc in existing.services:
                                if (existing_svc.port, existing_svc.protocol) == (svc.port, svc.protocol):
                                    if svc.version and not existing_svc.version:
                                        existing_svc.version = svc.version
                                    if svc.banner and not existing_svc.banner:
                                        existing_svc.banner = svc.banner
                                    if svc.service and not existing_svc.service:
                                        existing_svc.service = svc.service
                                    break
                    # 合并额外信息
                    if host.extra:
                        existing.extra.update(host.extra)
                else:
                    host_map[host.ip] = host.model_copy(deep=True)

        return list(host_map.values())

    def _merge_vulnerabilities(self, scan_results: list[ScanResult]) -> list[VulnerabilityFinding]:
        """合并漏洞，按多维度去重"""
        seen: dict[tuple[str, str], VulnerabilityFinding] = {}

        for result in scan_results:
            for vuln in result.vulnerabilities:
                # 生成去重键：优先使用 CVE，其次使用 (名称, 受影响资产)
                key = self._generate_vuln_key(vuln)

                if key in seen:
                    existing = seen[key]
                    self._merge_single_vulnerability(existing, vuln)
                else:
                    seen[key] = vuln.model_copy(deep=True)

        return list(seen.values())

    def _generate_vuln_key(self, vuln: VulnerabilityFinding) -> tuple[str, str]:
        """生成漏洞去重键"""
        # 如果有 CVE，使用 CVE 作为主键
        if vuln.cve_ids:
            # 使用第一个 CVE 作为主键
            cve_key = vuln.cve_ids[0]
            return (cve_key, vuln.affected_asset)

        # 如果有 CWE 和相同名称，视为同一漏洞
        if vuln.cwe_ids and vuln.name:
            cwe_key = vuln.cwe_ids[0]
            return (f"{vuln.name}:{cwe_key}", vuln.affected_asset)

        # 默认使用名称和资产
        return (vuln.name, vuln.affected_asset)

    def _merge_single_vulnerability(self, existing: VulnerabilityFinding, new: VulnerabilityFinding) -> None:
        """合并单个漏洞信息"""
        # 合并 CVE（去重）
        for cve in new.cve_ids:
            if cve not in existing.cve_ids:
                existing.cve_ids.append(cve)

        # 合并 CWE（去重）
        for cwe in new.cwe_ids:
            if cwe not in existing.cwe_ids:
                existing.cwe_ids.append(cwe)

        # 合并复现步骤（去重）
        for step in new.reproduction_steps:
            if step not in existing.reproduction_steps:
                existing.reproduction_steps.append(step)

        # 合并引用（去重）
        for ref in new.references:
            if ref not in existing.references:
                existing.references.append(ref)

        # 保留更严重的评级
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if severity_order.get(new.severity, 4) < severity_order.get(existing.severity, 4):
            existing.severity = new.severity
            existing.cvss_score = new.cvss_score or existing.cvss_score

        # 合并描述（如果新的更详细）
        if new.description and len(new.description) > len(existing.description):
            existing.description = new.description

        # 合并证据（如果新的更详细）
        if new.evidence and len(new.evidence) > len(existing.evidence):
            existing.evidence = new.evidence

        # 合并修复建议（如果新的更详细）
        if new.remediation and len(new.remediation) > len(existing.remediation):
            existing.remediation = new.remediation

        # 合并影响分析（如果新的更详细）
        if new.impact and len(new.impact) > len(existing.impact):
            existing.impact = new.impact

        # 合并工具来源（记录所有来源）
        if new.tool_source and new.tool_source not in existing.tool_source:
            existing.raw_data.setdefault("tool_sources", []).append(new.tool_source.value)
