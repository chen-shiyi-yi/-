"""LLM 自然语言生成器 - 调用 Claude API 生成报告内容"""

from __future__ import annotations

from src.llm.client import LLMClient
from src.llm.prompts import (
    EXECUTIVE_SUMMARY_PROMPT,
    REMEDIATION_PROMPT,
    REPRODUCTION_STEPS_PROMPT,
    SYSTEM_PROMPT,
    VULN_CLASSIFICATION_PROMPT,
    VULN_DESCRIPTION_PROMPT,
)
from src.models.schemas import PentestReport, VulnerabilityFinding


class ReportGenerator:
    """使用 LLM 生成渗透测试报告的自然语言内容"""

    def __init__(self, client: LLMClient):
        self.client = client

    def generate_vulnerability_details(self, vuln: VulnerabilityFinding) -> None:
        """为单个漏洞生成完整的描述、复现步骤和修复建议"""
        # 生成漏洞描述
        if not vuln.description or len(vuln.description) < 50:
            vuln.description = self._generate_description(vuln)

        # 生成复现步骤
        if not vuln.reproduction_steps:
            vuln.reproduction_steps = self._generate_reproduction_steps(vuln)

        # 生成修复建议
        if not vuln.remediation or len(vuln.remediation) < 30:
            vuln.remediation = self._generate_remediation(vuln)

    def generate_all_vulnerabilities(self, report: PentestReport) -> None:
        """为报告中所有漏洞生成自然语言内容"""
        for vuln in report.vulnerabilities:
            self.generate_vulnerability_details(vuln)

    def generate_executive_summary(self, report: PentestReport) -> str:
        """生成执行摘要"""
        # 构建主要发现列表
        top_findings = []
        for vuln in report.sorted_vulnerabilities()[:5]:
            top_findings.append(
                f"- [{vuln.severity.value.upper()}] {vuln.name}: "
                f"影响 {vuln.affected_asset}"
            )
        top_findings_text = "\n".join(top_findings) if top_findings else "无"

        port_count = sum(len(h.services) for h in report.hosts)

        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            project_name=report.project.project_name,
            scope=report.project.scope or "未指定",
            test_start=report.project.test_start or "未指定",
            test_end=report.project.test_end or "未指定",
            tester=report.project.tester or "未指定",
            critical_count=report.critical_count,
            high_count=report.high_count,
            medium_count=report.medium_count,
            low_count=report.low_count,
            info_count=report.info_count,
            top_findings=top_findings_text,
            host_count=len(report.hosts),
            port_count=port_count,
        )

        return self.client.generate(prompt, system=SYSTEM_PROMPT)

    def classify_vulnerability(self, vuln: VulnerabilityFinding) -> dict:
        """使用 LLM 对漏洞进行分类和风险评估"""
        prompt = VULN_CLASSIFICATION_PROMPT.format(
            name=vuln.name,
            description=vuln.description[:500] if vuln.description else "无",
            affected_asset=vuln.affected_asset,
            current_classification=vuln.owasp_category or "未分类",
        )
        result = self.client.generate(prompt, system=SYSTEM_PROMPT)

        # 尝试解析 JSON 结果
        try:
            import json
            # 提取 JSON 部分
            json_start = result.find("{")
            json_end = result.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = result[json_start:json_end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass

        # 解析失败时返回默认值
        return {
            "owasp_category": vuln.owasp_category or "",
            "cwe_ids": vuln.cwe_ids,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "attack_complexity": "unknown",
            "impact_scope": "unknown",
        }

    def _generate_description(self, vuln: VulnerabilityFinding) -> str:
        prompt = VULN_DESCRIPTION_PROMPT.format(
            name=vuln.name,
            owasp_category=vuln.owasp_category or "未分类",
            cve_ids=", ".join(vuln.cve_ids) if vuln.cve_ids else "无",
            cwe_ids=", ".join(vuln.cwe_ids) if vuln.cwe_ids else "无",
            cvss_score=vuln.cvss_score or "未评估",
            affected_asset=vuln.affected_asset,
            affected_component=vuln.affected_component or "未指定",
            evidence=vuln.evidence[:500] if vuln.evidence else "无",
            tool_source=vuln.tool_source.value,
        )
        return self.client.generate(prompt, system=SYSTEM_PROMPT)

    def _generate_reproduction_steps(self, vuln: VulnerabilityFinding) -> list[str]:
        prompt = REPRODUCTION_STEPS_PROMPT.format(
            name=vuln.name,
            affected_asset=vuln.affected_asset,
            evidence=vuln.evidence[:500] if vuln.evidence else "无",
            tool_source=vuln.tool_source.value,
        )
        result = self.client.generate(prompt, system=SYSTEM_PROMPT)
        # 解析编号列表
        steps = []
        for line in result.splitlines():
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith("-") or line.startswith("*")):
                # 去掉编号前缀
                step = line.lstrip("0123456789.-*) ").strip()
                if step:
                    steps.append(step)
        return steps if steps else [result.strip()]

    def _generate_remediation(self, vuln: VulnerabilityFinding) -> str:
        prompt = REMEDIATION_PROMPT.format(
            name=vuln.name,
            owasp_category=vuln.owasp_category or "未分类",
            cwe_ids=", ".join(vuln.cwe_ids) if vuln.cwe_ids else "无",
            affected_asset=vuln.affected_asset,
            affected_component=vuln.affected_component or "未指定",
            existing_remediation=vuln.remediation or "无",
        )
        return self.client.generate(prompt, system=SYSTEM_PROMPT)
