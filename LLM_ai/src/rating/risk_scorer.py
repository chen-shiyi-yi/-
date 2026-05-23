"""风险评级器 - 基于 CVSS 分数和 CWE 进行综合风险评级"""

from __future__ import annotations

from src.models.schemas import Severity, VulnerabilityFinding

# CWE -> 基础风险分数映射（无 CVSS 时的估算）
_CWE_BASE_SCORE: dict[str, float] = {
    # 注入类 - 高危
    "CWE-78": 9.8,   # OS Command Injection
    "CWE-89": 9.8,   # SQL Injection
    "CWE-79": 6.1,   # XSS
    "CWE-94": 9.0,   # Code Injection
    "CWE-95": 9.8,   # Eval Injection
    "CWE-98": 8.8,   # File Inclusion
    # 认证类
    "CWE-287": 9.8,  # Improper Authentication
    "CWE-798": 9.1,  # Hard-coded Credentials
    "CWE-306": 9.1,  # Missing Auth
    "CWE-307": 7.5,  # Brute Force
    # 访问控制
    "CWE-22": 7.5,   # Path Traversal
    "CWE-284": 8.2,  # Improper Access Control
    "CWE-862": 8.1,  # Missing Authorization
    "CWE-863": 7.5,  # Incorrect Authorization
    "CWE-352": 8.8,  # CSRF
    "CWE-639": 7.5,  # IDOR
    # SSRF
    "CWE-918": 8.6,  # SSRF
    # 反序列化
    "CWE-502": 9.8,  # Deserialization
    # 信息泄露
    "CWE-200": 5.3,  # Information Exposure
    "CWE-538": 5.3,  # Info Exposure Through Debug
    # 加密
    "CWE-327": 5.9,  # Broken Crypto
    "CWE-328": 5.9,  # Weak Hash
    "CWE-326": 7.5,  # Inadequate Encryption
    # 配置
    "CWE-16": 5.0,   # Configuration
    "CWE-611": 5.9,  # XXE
    # 日志
    "CWE-117": 5.3,  # Improper Output Neutralization for Logs
    "CWE-778": 5.3,  # Insufficient Logging
}


class RiskScorer:
    """风险评级器"""

    def __init__(self, thresholds: dict[str, float] | None = None):
        self.thresholds = thresholds or {
            "critical": 9.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 0.1,
            "info": 0.0,
        }

    def score(self, vulnerability: VulnerabilityFinding) -> None:
        """为单个漏洞评分并设置 severity，直接修改原对象"""
        # 如果已有 CVSS 分数，直接使用
        if vulnerability.cvss_score is not None:
            vulnerability.severity = self._score_to_severity(vulnerability.cvss_score)
            return

        # 通过 CWE 估算
        for cwe in vulnerability.cwe_ids:
            cwe_normalized = cwe.upper().strip()
            if not cwe_normalized.startswith("CWE-"):
                cwe_normalized = f"CWE-{cwe_normalized}"
            if cwe_normalized in _CWE_BASE_SCORE:
                score = _CWE_BASE_SCORE[cwe_normalized]
                vulnerability.cvss_score = score
                vulnerability.severity = self._score_to_severity(score)
                return

        # 通过关键词估算
        text = f"{vulnerability.name} {vulnerability.description}".lower()
        score = self._estimate_from_keywords(text)
        if score > 0:
            vulnerability.cvss_score = score
            vulnerability.severity = self._score_to_severity(score)

    def score_batch(self, vulnerabilities: list[VulnerabilityFinding]) -> None:
        """批量评分"""
        for vuln in vulnerabilities:
            self.score(vuln)

    def get_risk_summary(self, vulnerabilities: list[VulnerabilityFinding]) -> dict[str, int]:
        """获取风险等级分布统计"""
        summary = {s.value: 0 for s in Severity}
        for vuln in vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary

    def _score_to_severity(self, score: float) -> Severity:
        if score >= self.thresholds["critical"]:
            return Severity.CRITICAL
        if score >= self.thresholds["high"]:
            return Severity.HIGH
        if score >= self.thresholds["medium"]:
            return Severity.MEDIUM
        if score >= self.thresholds["low"]:
            return Severity.LOW
        return Severity.INFO

    def _estimate_from_keywords(self, text: str) -> float:
        """基于关键词估算风险分数"""
        critical_keywords = [
            "remote code execution", "rce", "command injection",
            "sql injection", "sqli", "deserialization", "authentication bypass",
            "default credential", "hard-coded credential",
        ]
        high_keywords = [
            "ssrf", "csrf", "path traversal", "directory traversal",
            "file inclusion", "lfi", "rfi", "xxe", "privilege escalation",
            "weak password", "weak credential",
        ]
        medium_keywords = [
            "xss", "cross-site scripting", "information disclosure",
            "open redirect", "cors", "missing encryption", "weak cipher",
            "clickjacking", "verbose error", "directory listing",
        ]
        low_keywords = [
            "cookie", "httponly", "secure flag", "header missing",
            "version disclosure", "banner", "deprecated",
        ]

        for kw in critical_keywords:
            if kw in text:
                return 9.5
        for kw in high_keywords:
            if kw in text:
                return 8.0
        for kw in medium_keywords:
            if kw in text:
                return 5.5
        for kw in low_keywords:
            if kw in text:
                return 2.5
        return 0.0
