"""数据导出器 - 支持导出为 JSON、CSV 等格式"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

from src.models.schemas import PentestReport, VulnerabilityFinding


class ReportExporter:
    """报告数据导出器"""

    def export_json(self, report: PentestReport, output_path: Path) -> Path:
        """导出为 JSON 格式"""
        data = {
            "project": {
                "name": report.project.project_name,
                "client": report.project.client,
                "tester": report.project.tester,
                "scope": report.project.scope,
                "test_start": str(report.project.test_start) if report.project.test_start else None,
                "test_end": str(report.project.test_end) if report.project.test_end else None,
            },
            "generated_at": str(report.generated_at),
            "executive_summary": report.executive_summary,
            "statistics": report.risk_summary,
            "hosts": [
                {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os": host.os,
                    "state": host.state,
                    "services": [
                        {
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service,
                            "version": svc.version,
                            "state": svc.state,
                        }
                        for svc in host.services
                    ],
                }
                for host in report.hosts
            ],
            "vulnerabilities": [
                self._vuln_to_dict(vuln)
                for vuln in report.sorted_vulnerabilities()
            ],
        }

        output_file = output_path.with_suffix(".json")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return output_file

    def export_csv(self, report: PentestReport, output_path: Path) -> Path:
        """导出为 CSV 格式"""
        output_file = output_path.with_suffix(".csv")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)

            # 写入表头
            writer.writerow([
                "序号",
                "漏洞名称",
                "严重等级",
                "CVSS 分数",
                "CVE",
                "CWE",
                "OWASP 分类",
                "受影响资产",
                "受影响组件",
                "漏洞描述",
                "修复建议",
                "工具来源",
            ])

            # 写入数据
            for i, vuln in enumerate(report.sorted_vulnerabilities(), 1):
                writer.writerow([
                    i,
                    vuln.name,
                    vuln.severity.value,
                    vuln.cvss_score or "",
                    ", ".join(vuln.cve_ids),
                    ", ".join(vuln.cwe_ids),
                    vuln.owasp_category,
                    vuln.affected_asset,
                    vuln.affected_component,
                    vuln.description[:200] if vuln.description else "",
                    vuln.remediation[:200] if vuln.remediation else "",
                    vuln.tool_source.value,
                ])

        return output_file

    def export_summary(self, report: PentestReport, output_path: Path) -> Path:
        """导出摘要报告"""
        output_file = output_path.with_suffix(".txt")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "=" * 60,
            "渗透测试报告摘要",
            "=" * 60,
            "",
            f"项目名称: {report.project.project_name}",
            f"客户: {report.project.client or '未指定'}",
            f"测试人员: {report.project.tester or '未指定'}",
            f"测试范围: {report.project.scope or '未指定'}",
            f"生成时间: {report.generated_at}",
            "",
            "-" * 60,
            "发现统计",
            "-" * 60,
            f"严重漏洞: {report.critical_count}",
            f"高危漏洞: {report.high_count}",
            f"中危漏洞: {report.medium_count}",
            f"低危漏洞: {report.low_count}",
            f"信息发现: {report.info_count}",
            f"合计: {len(report.vulnerabilities)}",
            "",
            "-" * 60,
            "资产概况",
            "-" * 60,
            f"主机数量: {len(report.hosts)}",
        ]

        # 主机详情
        for host in report.hosts:
            lines.append(f"\n  {host.ip} ({host.hostname or 'N/A'})")
            if host.os:
                lines.append(f"    OS: {host.os}")
            if host.services:
                lines.append(f"    开放端口: {len(host.services)}")
                for svc in host.services[:5]:  # 只显示前5个端口
                    lines.append(f"      - {svc.port}/{svc.protocol}: {svc.service} {svc.version}")
                if len(host.services) > 5:
                    lines.append(f"      ... 还有 {len(host.services) - 5} 个端口")

        # 高危漏洞列表
        lines.extend([
            "",
            "-" * 60,
            "高危漏洞列表",
            "-" * 60,
        ])

        high_vulns = [v for v in report.vulnerabilities if v.severity.value in ["critical", "high"]]
        if high_vulns:
            for i, vuln in enumerate(high_vulns[:10], 1):
                lines.append(f"{i}. [{vuln.severity.value.upper()}] {vuln.name}")
                lines.append(f"   受影响资产: {vuln.affected_asset}")
                if vuln.cve_ids:
                    lines.append(f"   CVE: {', '.join(vuln.cve_ids)}")
                lines.append("")
        else:
            lines.append("无高危漏洞")

        output_file.write_text("\n".join(lines), encoding="utf-8")
        return output_file

    def _vuln_to_dict(self, vuln: VulnerabilityFinding) -> dict:
        """将漏洞转换为字典"""
        return {
            "id": vuln.id,
            "name": vuln.name,
            "description": vuln.description,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "cve_ids": vuln.cve_ids,
            "cwe_ids": vuln.cwe_ids,
            "owasp_category": vuln.owasp_category,
            "affected_asset": vuln.affected_asset,
            "affected_component": vuln.affected_component,
            "evidence": vuln.evidence,
            "reproduction_steps": vuln.reproduction_steps,
            "impact": vuln.impact,
            "remediation": vuln.remediation,
            "tool_source": vuln.tool_source.value,
            "references": vuln.references,
        }
