"""报告数据结构组装器"""

from __future__ import annotations

from datetime import datetime

from src.models.schemas import PentestReport, ProjectInfo


class ReportBuilder:
    """将 PentestReport 组装为渲染上下文"""

    def __init__(self, report: PentestReport):
        self.report = report

    def build_context(self) -> dict:
        """构建模板渲染上下文"""
        report = self.report
        sorted_vulns = report.sorted_vulnerabilities()

        # 按严重等级分组
        vulns_by_severity = {}
        for vuln in sorted_vulns:
            sev = vuln.severity.value
            vulns_by_severity.setdefault(sev, []).append(vuln)

        # 资产统计
        total_ports = sum(len(h.services) for h in report.hosts)
        open_ports = sum(
            1 for h in report.hosts for s in h.services if s.state == "open"
        )

        return {
            "project": report.project,
            "generated_at": report.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": report.executive_summary,
            "hosts": report.hosts,
            "vulnerabilities": sorted_vulns,
            "vulns_by_severity": vulns_by_severity,
            "risk_summary": report.risk_summary,
            "stats": {
                "total_hosts": len(report.hosts),
                "total_ports": total_ports,
                "open_ports": open_ports,
                "total_vulns": len(report.vulnerabilities),
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
            "severity_labels": {
                "critical": "严重",
                "high": "高危",
                "medium": "中危",
                "low": "低危",
                "info": "信息",
            },
            "severity_colors": {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#28a745",
                "info": "#17a2b8",
            },
        }
