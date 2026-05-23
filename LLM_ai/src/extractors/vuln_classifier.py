"""漏洞分类器 - 基于 CWE 和关键词映射到 OWASP Top 10"""

from __future__ import annotations

from src.models.schemas import VulnerabilityFinding

# CWE -> OWASP Top 10 2021 映射
_CWE_TO_OWASP: dict[str, str] = {
    # A01:2021 - Broken Access Control
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-23": "A01:2021 - Broken Access Control",
    "CWE-35": "A01:2021 - Broken Access Control",
    "CWE-59": "A01:2021 - Broken Access Control",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-201": "A01:2021 - Broken Access Control",
    "CWE-219": "A01:2021 - Broken Access Control",
    "CWE-264": "A01:2021 - Broken Access Control",
    "CWE-275": "A01:2021 - Broken Access Control",
    "CWE-276": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-285": "A01:2021 - Broken Access Control",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-359": "A01:2021 - Broken Access Control",
    "CWE-377": "A01:2021 - Broken Access Control",
    "CWE-402": "A01:2021 - Broken Access Control",
    "CWE-425": "A01:2021 - Broken Access Control",
    "CWE-441": "A01:2021 - Broken Access Control",
    "CWE-497": "A01:2021 - Broken Access Control",
    "CWE-538": "A01:2021 - Broken Access Control",
    "CWE-540": "A01:2021 - Broken Access Control",
    "CWE-548": "A01:2021 - Broken Access Control",
    "CWE-552": "A01:2021 - Broken Access Control",
    "CWE-566": "A01:2021 - Broken Access Control",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-639": "A01:2021 - Broken Access Control",
    "CWE-651": "A01:2021 - Broken Access Control",
    "CWE-668": "A01:2021 - Broken Access Control",
    "CWE-706": "A01:2021 - Broken Access Control",
    "CWE-862": "A01:2021 - Broken Access Control",
    "CWE-863": "A01:2021 - Broken Access Control",
    "CWE-913": "A01:2021 - Broken Access Control",
    # A02:2021 - Cryptographic Failures
    "CWE-261": "A02:2021 - Cryptographic Failures",
    "CWE-296": "A02:2021 - Cryptographic Failures",
    "CWE-310": "A02:2021 - Cryptographic Failures",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-321": "A02:2021 - Cryptographic Failures",
    "CWE-322": "A02:2021 - Cryptographic Failures",
    "CWE-323": "A02:2021 - Cryptographic Failures",
    "CWE-324": "A02:2021 - Cryptographic Failures",
    "CWE-325": "A02:2021 - Cryptographic Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-329": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-331": "A02:2021 - Cryptographic Failures",
    "CWE-335": "A02:2021 - Cryptographic Failures",
    "CWE-336": "A02:2021 - Cryptographic Failures",
    "CWE-337": "A02:2021 - Cryptographic Failures",
    "CWE-338": "A02:2021 - Cryptographic Failures",
    "CWE-340": "A02:2021 - Cryptographic Failures",
    "CWE-347": "A02:2021 - Cryptographic Failures",
    # A03:2021 - Injection
    "CWE-20": "A03:2021 - Injection",
    "CWE-74": "A03:2021 - Injection",
    "CWE-75": "A03:2021 - Injection",
    "CWE-77": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-80": "A03:2021 - Injection",
    "CWE-83": "A03:2021 - Injection",
    "CWE-87": "A03:2021 - Injection",
    "CWE-88": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-90": "A03:2021 - Injection",
    "CWE-91": "A03:2021 - Injection",
    "CWE-93": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-95": "A03:2021 - Injection",
    "CWE-96": "A03:2021 - Injection",
    "CWE-97": "A03:2021 - Injection",
    "CWE-98": "A03:2021 - Injection",
    "CWE-99": "A03:2021 - Injection",
    "CWE-100": "A03:2021 - Injection",
    "CWE-113": "A03:2021 - Injection",
    "CWE-116": "A03:2021 - Injection",
    # A04:2021 - Insecure Design
    "CWE-73": "A04:2021 - Insecure Design",
    "CWE-183": "A04:2021 - Insecure Design",
    "CWE-209": "A04:2021 - Insecure Design",
    "CWE-213": "A04:2021 - Insecure Design",
    "CWE-235": "A04:2021 - Insecure Design",
    "CWE-256": "A04:2021 - Insecure Design",
    "CWE-257": "A04:2021 - Insecure Design",
    "CWE-266": "A04:2021 - Insecure Design",
    "CWE-269": "A04:2021 - Insecure Design",
    "CWE-280": "A04:2021 - Insecure Design",
    "CWE-311": "A04:2021 - Insecure Design",
    "CWE-312": "A04:2021 - Insecure Design",
    "CWE-313": "A04:2021 - Insecure Design",
    "CWE-316": "A04:2021 - Insecure Design",
    "CWE-419": "A04:2021 - Insecure Design",
    "CWE-430": "A04:2021 - Insecure Design",
    "CWE-434": "A04:2021 - Insecure Design",
    "CWE-444": "A04:2021 - Insecure Design",
    "CWE-451": "A04:2021 - Insecure Design",
    "CWE-472": "A04:2021 - Insecure Design",
    "CWE-501": "A04:2021 - Insecure Design",
    "CWE-522": "A04:2021 - Insecure Design",
    "CWE-525": "A04:2021 - Insecure Design",
    "CWE-539": "A04:2021 - Insecure Design",
    "CWE-579": "A04:2021 - Insecure Design",
    "CWE-598": "A04:2021 - Insecure Design",
    "CWE-602": "A04:2021 - Insecure Design",
    "CWE-642": "A04:2021 - Insecure Design",
    "CWE-646": "A04:2021 - Insecure Design",
    "CWE-650": "A04:2021 - Insecure Design",
    "CWE-653": "A04:2021 - Insecure Design",
    "CWE-656": "A04:2021 - Insecure Design",
    "CWE-657": "A04:2021 - Insecure Design",
    "CWE-799": "A04:2021 - Insecure Design",
    "CWE-807": "A04:2021 - Insecure Design",
    "CWE-840": "A04:2021 - Insecure Design",
    "CWE-841": "A04:2021 - Insecure Design",
    "CWE-927": "A04:2021 - Insecure Design",
    "CWE-1021": "A04:2021 - Insecure Design",
    "CWE-1173": "A04:2021 - Insecure Design",
    # A05:2021 - Security Misconfiguration
    "CWE-2": "A05:2021 - Security Misconfiguration",
    "CWE-11": "A05:2021 - Security Misconfiguration",
    "CWE-13": "A05:2021 - Security Misconfiguration",
    "CWE-15": "A05:2021 - Security Misconfiguration",
    "CWE-16": "A05:2021 - Security Misconfiguration",
    "CWE-260": "A05:2021 - Security Misconfiguration",
    "CWE-276": "A05:2021 - Security Misconfiguration",
    "CWE-315": "A05:2021 - Security Misconfiguration",
    "CWE-520": "A05:2021 - Security Misconfiguration",
    "CWE-526": "A05:2021 - Security Misconfiguration",
    "CWE-537": "A05:2021 - Security Misconfiguration",
    "CWE-541": "A05:2021 - Security Misconfiguration",
    "CWE-547": "A05:2021 - Security Misconfiguration",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-614": "A05:2021 - Security Misconfiguration",
    "CWE-756": "A05:2021 - Security Misconfiguration",
    "CWE-776": "A05:2021 - Security Misconfiguration",
    "CWE-942": "A05:2021 - Security Misconfiguration",
    "CWE-1004": "A05:2021 - Security Misconfiguration",
    "CWE-1032": "A05:2021 - Security Misconfiguration",
    "CWE-1174": "A05:2021 - Security Misconfiguration",
    # A06:2021 - Vulnerable and Outdated Components
    "CWE-1035": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 - Vulnerable and Outdated Components",
    # A07:2021 - Identification and Authentication Failures
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-288": "A07:2021 - Identification and Authentication Failures",
    "CWE-290": "A07:2021 - Identification and Authentication Failures",
    "CWE-294": "A07:2021 - Identification and Authentication Failures",
    "CWE-295": "A07:2021 - Identification and Authentication Failures",
    "CWE-297": "A07:2021 - Identification and Authentication Failures",
    "CWE-300": "A07:2021 - Identification and Authentication Failures",
    "CWE-302": "A07:2021 - Identification and Authentication Failures",
    "CWE-304": "A07:2021 - Identification and Authentication Failures",
    "CWE-306": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-308": "A07:2021 - Identification and Authentication Failures",
    "CWE-346": "A07:2021 - Identification and Authentication Failures",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-521": "A07:2021 - Identification and Authentication Failures",
    "CWE-613": "A07:2021 - Identification and Authentication Failures",
    "CWE-620": "A07:2021 - Identification and Authentication Failures",
    "CWE-640": "A07:2021 - Identification and Authentication Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-940": "A07:2021 - Identification and Authentication Failures",
    # A08:2021 - Software and Data Integrity Failures
    "CWE-345": "A08:2021 - Software and Data Integrity Failures",
    "CWE-353": "A08:2021 - Software and Data Integrity Failures",
    "CWE-426": "A08:2021 - Software and Data Integrity Failures",
    "CWE-494": "A08:2021 - Software and Data Integrity Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-565": "A08:2021 - Software and Data Integrity Failures",
    "CWE-784": "A08:2021 - Software and Data Integrity Failures",
    "CWE-829": "A08:2021 - Software and Data Integrity Failures",
    "CWE-830": "A08:2021 - Software and Data Integrity Failures",
    "CWE-913": "A08:2021 - Software and Data Integrity Failures",
    # A09:2021 - Security Logging and Monitoring Failures
    "CWE-117": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-223": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-532": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-778": "A09:2021 - Security Logging and Monitoring Failures",
    # A10:2021 - Server-Side Request Forgery
    "CWE-918": "A10:2021 - Server-Side Request Forgery",
}

# 关键词 -> OWASP 映射（当没有 CWE 时使用）
_KEYWORD_TO_OWASP: dict[str, str] = {
    "xss": "A03:2021 - Injection",
    "cross-site scripting": "A03:2021 - Injection",
    "sql injection": "A03:2021 - Injection",
    "sqli": "A03:2021 - Injection",
    "command injection": "A03:2021 - Injection",
    "code injection": "A03:2021 - Injection",
    "ldap injection": "A03:2021 - Injection",
    "xpath injection": "A03:2021 - Injection",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "server-side request forgery": "A10:2021 - Server-Side Request Forgery",
    "csrf": "A01:2021 - Broken Access Control",
    "cross-site request forgery": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "insecure direct object": "A01:2021 - Broken Access Control",
    "directory traversal": "A01:2021 - Broken Access Control",
    "path traversal": "A01:2021 - Broken Access Control",
    "file inclusion": "A01:2021 - Broken Access Control",
    "lfi": "A01:2021 - Broken Access Control",
    "rfi": "A01:2021 - Broken Access Control",
    "authentication bypass": "A07:2021 - Identification and Authentication Failures",
    "weak password": "A07:2021 - Identification and Authentication Failures",
    "default credential": "A07:2021 - Identification and Authentication Failures",
    "weak credential": "A07:2021 - Identification and Authentication Failures",
    "information disclosure": "A01:2021 - Broken Access Control",
    "sensitive data": "A02:2021 - Cryptographic Failures",
    "missing encryption": "A02:2021 - Cryptographic Failures",
    "weak cipher": "A02:2021 - Cryptographic Failures",
    "ssl": "A02:2021 - Cryptographic Failures",
    "tls": "A02:2021 - Cryptographic Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "remote code execution": "A03:2021 - Injection",
    "rce": "A03:2021 - Injection",
    "open redirect": "A01:2021 - Broken Access Control",
    "cors": "A05:2021 - Security Misconfiguration",
    "security misconfiguration": "A05:2021 - Security Misconfiguration",
    "default config": "A05:2021 - Security Misconfiguration",
    "verbose error": "A05:2021 - Security Misconfiguration",
    "directory listing": "A05:2021 - Security Misconfiguration",
    "clickjacking": "A04:2021 - Insecure Design",
    "xxe": "A05:2021 - Security Misconfiguration",
    "xml external entity": "A05:2021 - Security Misconfiguration",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "broken access": "A01:2021 - Broken Access Control",
    "privilege escalation": "A01:2021 - Broken Access Control",
}


class VulnClassifier:
    """漏洞分类器 - 将漏洞映射到 OWASP Top 10 类别"""

    def classify(self, vulnerability: VulnerabilityFinding) -> str:
        """为漏洞分配 OWASP 分类，优先用 CWE，其次用关键词"""
        # 已有分类则跳过
        if vulnerability.owasp_category:
            return vulnerability.owasp_category

        # 通过 CWE 映射
        for cwe in vulnerability.cwe_ids:
            cwe_normalized = cwe.upper().strip()
            if not cwe_normalized.startswith("CWE-"):
                cwe_normalized = f"CWE-{cwe_normalized}"
            if cwe_normalized in _CWE_TO_OWASP:
                return _CWE_TO_OWASP[cwe_normalized]

        # 通过关键词映射
        text = f"{vulnerability.name} {vulnerability.description}".lower()
        for keyword, owasp in _KEYWORD_TO_OWASP.items():
            if keyword in text:
                return owasp

        return ""

    def classify_batch(self, vulnerabilities: list[VulnerabilityFinding]) -> None:
        """批量分类，直接修改原对象"""
        for vuln in vulnerabilities:
            vuln.owasp_category = self.classify(vuln)
