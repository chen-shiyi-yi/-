"""提取器和分类器单元测试"""

import pytest

from src.models.schemas import (
    HostInfo,
    ScanResult,
    ServiceInfo,
    Severity,
    ToolType,
    VulnerabilityFinding,
)
from src.extractors.info_extractor import InfoExtractor
from src.extractors.vuln_classifier import VulnClassifier
from src.rating.risk_scorer import RiskScorer


class TestInfoExtractor:
    """信息提取器测试"""

    def setup_method(self):
        self.extractor = InfoExtractor()

    def test_merge_hosts(self):
        """测试主机合并"""
        # 创建两个扫描结果，包含同一主机的不同信息
        host1 = HostInfo(
            ip="192.168.1.1",
            hostname="server1.local",
            services=[
                ServiceInfo(host="192.168.1.1", port=80, service="http"),
                ServiceInfo(host="192.168.1.1", port=443, service="https"),
            ]
        )

        host2 = HostInfo(
            ip="192.168.1.1",
            hostname="server1.local",
            os="Ubuntu 22.04",
            services=[
                ServiceInfo(host="192.168.1.1", port=80, service="http", version="Apache 2.4"),
                ServiceInfo(host="192.168.1.1", port=22, service="ssh"),
            ]
        )

        result1 = ScanResult(tool=ToolType.NMAP, source_file="test1.xml", hosts=[host1])
        result2 = ScanResult(tool=ToolType.NMAP, source_file="test2.xml", hosts=[host2])

        hosts, _ = self.extractor.extract([result1, result2])

        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].os == "Ubuntu 22.04"
        assert len(hosts[0].services) == 3  # 80, 443, 22

    def test_merge_vulnerabilities(self):
        """测试漏洞合并"""
        vuln1 = VulnerabilityFinding(
            name="SQL Injection",
            severity=Severity.HIGH,
            affected_asset="http://example.com/api",
            cve_ids=["CVE-2021-1234"],
            cwe_ids=["CWE-89"],
            tool_source=ToolType.BURP,
        )

        vuln2 = VulnerabilityFinding(
            name="SQL Injection",
            severity=Severity.CRITICAL,
            affected_asset="http://example.com/api",
            cve_ids=["CVE-2021-1234", "CVE-2021-5678"],
            cwe_ids=["CWE-89"],
            cvss_score=9.8,
            tool_source=ToolType.SQLMAP,
        )

        result1 = ScanResult(tool=ToolType.BURP, source_file="burp.xml", vulnerabilities=[vuln1])
        result2 = ScanResult(tool=ToolType.SQLMAP, source_file="sqlmap.log", vulnerabilities=[vuln2])

        _, vulns = self.extractor.extract([result1, result2])

        assert len(vulns) == 1
        assert vulns[0].severity == Severity.CRITICAL  # 保留更严重的
        assert vulns[0].cvss_score == 9.8
        assert len(vulns[0].cve_ids) == 2  # 合并 CVE

    def test_dedup_by_cve(self):
        """测试基于 CVE 的去重"""
        vuln1 = VulnerabilityFinding(
            name="Log4j RCE",
            severity=Severity.CRITICAL,
            affected_asset="http://server1.com",
            cve_ids=["CVE-2021-44228"],
            tool_source=ToolType.NUCLEI,
        )

        vuln2 = VulnerabilityFinding(
            name="Apache Log4j Remote Code Execution",
            severity=Severity.CRITICAL,
            affected_asset="http://server2.com",
            cve_ids=["CVE-2021-44228"],
            tool_source=ToolType.NMAP,
        )

        result1 = ScanResult(tool=ToolType.NUCLEI, source_file="nuclei.json", vulnerabilities=[vuln1])
        result2 = ScanResult(tool=ToolType.NMAP, source_file="nmap.xml", vulnerabilities=[vuln2])

        _, vulns = self.extractor.extract([result1, result2])

        # 相同 CVE 但不同资产，应该保留两个
        assert len(vulns) == 2


class TestVulnClassifier:
    """漏洞分类器测试"""

    def setup_method(self):
        self.classifier = VulnClassifier()

    def test_classify_by_cwe(self):
        """测试基于 CWE 的分类"""
        vuln = VulnerabilityFinding(
            name="SQL Injection",
            cwe_ids=["CWE-89"],
        )

        result = self.classifier.classify(vuln)
        assert result == "A03:2021 - Injection"

    def test_classify_by_keyword(self):
        """测试基于关键词的分类"""
        vuln = VulnerabilityFinding(
            name="Cross-Site Scripting",
            description="XSS vulnerability found",
        )

        result = self.classifier.classify(vuln)
        assert result == "A03:2021 - Injection"

    def test_classify_existing(self):
        """测试已有分类的跳过"""
        vuln = VulnerabilityFinding(
            name="Test",
            owasp_category="A01:2021 - Broken Access Control",
        )

        result = self.classifier.classify(vuln)
        assert result == "A01:2021 - Broken Access Control"

    def test_classify_batch(self):
        """测试批量分类"""
        vulns = [
            VulnerabilityFinding(name="XSS", cwe_ids=["CWE-79"]),
            VulnerabilityFinding(name="SQLi", cwe_ids=["CWE-89"]),
            VulnerabilityFinding(name="CSRF", cwe_ids=["CWE-352"]),
        ]

        self.classifier.classify_batch(vulns)

        assert vulns[0].owasp_category == "A03:2021 - Injection"
        assert vulns[1].owasp_category == "A03:2021 - Injection"
        assert vulns[2].owasp_category == "A01:2021 - Broken Access Control"


class TestRiskScorer:
    """风险评级器测试"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_score_with_cvss(self):
        """测试有 CVSS 分数的评分"""
        vuln = VulnerabilityFinding(
            name="Test Vuln",
            cvss_score=8.5,
        )

        self.scorer.score(vuln)
        assert vuln.severity == Severity.HIGH

    def test_score_with_cwe(self):
        """测试基于 CWE 的评分"""
        vuln = VulnerabilityFinding(
            name="SQL Injection",
            cwe_ids=["CWE-89"],
        )

        self.scorer.score(vuln)
        assert vuln.cvss_score == 9.8
        assert vuln.severity == Severity.CRITICAL

    def test_score_with_keyword(self):
        """测试基于关键词的评分"""
        vuln = VulnerabilityFinding(
            name="Remote Code Execution",
            description="RCE vulnerability",
        )

        self.scorer.score(vuln)
        assert vuln.severity == Severity.CRITICAL

    def test_get_risk_summary(self):
        """测试风险统计"""
        vulns = [
            VulnerabilityFinding(name="Vuln 1", severity=Severity.CRITICAL),
            VulnerabilityFinding(name="Vuln 2", severity=Severity.CRITICAL),
            VulnerabilityFinding(name="Vuln 3", severity=Severity.HIGH),
            VulnerabilityFinding(name="Vuln 4", severity=Severity.MEDIUM),
            VulnerabilityFinding(name="Vuln 5", severity=Severity.LOW),
            VulnerabilityFinding(name="Vuln 6", severity=Severity.INFO),
        ]

        summary = self.scorer.get_risk_summary(vulns)

        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["info"] == 1