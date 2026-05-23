"""渗透测试报告数据模型"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolType(str, Enum):
    NMAP = "nmap"
    NUCLEI = "nuclei"
    SQLMAP = "sqlmap"
    BURP = "burp"
    METASPLOIT = "metasploit"
    NIKTO = "nikto"
    UNKNOWN = "unknown"


class ServiceInfo(BaseModel):
    """单个服务/端口信息"""
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"
    banner: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class HostInfo(BaseModel):
    """主机信息"""
    ip: str
    hostname: str = ""
    os: str = ""
    state: str = "up"
    services: list[ServiceInfo] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityFinding(BaseModel):
    """单个漏洞发现"""
    id: str = ""
    name: str
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_category: str = ""
    affected_asset: str = ""  # host:port 或 URL
    affected_component: str = ""
    evidence: str = ""  # 原始证据/输出
    reproduction_steps: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    tool_source: ToolType = ToolType.UNKNOWN
    raw_data: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """单次工具扫描的解析结果"""
    tool: ToolType
    source_file: str
    scan_time: datetime | None = None
    target: str = ""
    hosts: list[HostInfo] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    raw_summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProjectInfo(BaseModel):
    """项目元信息"""
    project_name: str = "渗透测试报告"
    client: str = ""
    tester: str = ""
    test_start: datetime | None = None
    test_end: datetime | None = None
    scope: str = ""
    methodology: str = ""
    tools_used: list[str] = Field(default_factory=list)


class PentestReport(BaseModel):
    """最终渗透测试报告"""
    project: ProjectInfo = Field(default_factory=ProjectInfo)
    executive_summary: str = ""
    hosts: list[HostInfo] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    risk_summary: dict[str, int] = Field(default_factory=dict)  # severity -> count
    generated_at: datetime = Field(default_factory=datetime.now)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.INFO)

    def sorted_vulnerabilities(self) -> list[VulnerabilityFinding]:
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.vulnerabilities, key=lambda v: severity_order[v.severity])
