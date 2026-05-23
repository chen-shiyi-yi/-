"""解析器单元测试"""

import pytest
from pathlib import Path
from xml.etree import ElementTree as ET

from src.models.schemas import Severity, ToolType
from src.parsers.nmap_parser import NmapParser
from src.parsers.nuclei_parser import NucleiParser
from src.parsers.burp_parser import BurpParser
from src.parsers.nikto_parser import NiktoParser


class TestNmapParser:
    """Nmap 解析器测试"""

    def setup_method(self):
        self.parser = NmapParser()

    def test_parse_xml(self, tmp_path):
        """测试解析 Nmap XML 格式"""
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames><hostname name="test.local"/></hostnames>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.51"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        xml_file = tmp_path / "test.xml"
        xml_file.write_text(xml_content, encoding="utf-8")

        result = self.parser.parse(xml_file)

        assert result.tool == ToolType.NMAP
        assert len(result.hosts) == 1
        assert result.hosts[0].ip == "192.168.1.1"
        assert result.hosts[0].hostname == "test.local"
        assert len(result.hosts[0].services) == 1
        assert result.hosts[0].services[0].port == 80
        assert result.hosts[0].services[0].service == "http"

    def test_parse_text(self, tmp_path):
        """测试解析 Nmap 文本格式"""
        text_content = """Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1
80/tcp open  http    Apache httpd 2.4.51

Nmap scan report for 192.168.1.2
Host is up (0.0020s latency).

PORT   STATE SERVICE VERSION
3306/tcp open mysql MySQL 8.0.27"""

        text_file = tmp_path / "test.nmap"
        text_file.write_text(text_content, encoding="utf-8")

        result = self.parser.parse(text_file)

        assert result.tool == ToolType.NMAP
        assert len(result.hosts) == 2
        assert result.hosts[0].ip == "192.168.1.1"
        assert result.hosts[1].ip == "192.168.1.2"

    def test_cvss_to_severity(self):
        """测试 CVSS 分数转换"""
        assert NmapParser._cvss_to_severity(9.5) == Severity.CRITICAL
        assert NmapParser._cvss_to_severity(7.5) == Severity.HIGH
        assert NmapParser._cvss_to_severity(5.0) == Severity.MEDIUM
        assert NmapParser._cvss_to_severity(2.0) == Severity.LOW
        assert NmapParser._cvss_to_severity(0.0) == Severity.INFO
        assert NmapParser._cvss_to_severity(None) == Severity.INFO


class TestNucleiParser:
    """Nuclei 解析器测试"""

    def setup_method(self):
        self.parser = NucleiParser()

    def test_parse_jsonl(self, tmp_path):
        """测试解析 Nuclei JSONL 格式"""
        jsonl_content = '''{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-score":10.0}},"host":"http://example.com","matched-at":"http://example.com/api"}
{"template-id":"xss-detect","info":{"name":"XSS Detection","severity":"medium","classification":{"cwe-id":["CWE-79"]}},"host":"http://example.com","matched-at":"http://example.com/search"}'''

        jsonl_file = tmp_path / "results.jsonl"
        jsonl_file.write_text(jsonl_content, encoding="utf-8")

        result = self.parser.parse(jsonl_file)

        assert result.tool == ToolType.NUCLEI
        assert len(result.vulnerabilities) == 2

        # 检查第一个漏洞
        vuln1 = result.vulnerabilities[0]
        assert vuln1.name == "Log4j RCE"
        assert vuln1.severity == Severity.CRITICAL
        assert "CVE-2021-44228" in vuln1.cve_ids
        assert vuln1.cvss_score == 10.0

        # 检查第二个漏洞
        vuln2 = result.vulnerabilities[1]
        assert vuln2.name == "XSS Detection"
        assert vuln2.severity == Severity.MEDIUM
        assert "CWE-79" in vuln2.cwe_ids

    def test_parse_json(self, tmp_path):
        """测试解析 Nuclei JSON 格式"""
        json_content = '''[
  {"template-id":"test-1","info":{"name":"Test Vuln","severity":"high"},"host":"http://test.com"}
]'''

        json_file = tmp_path / "results.json"
        json_file.write_text(json_content, encoding="utf-8")

        result = self.parser.parse(json_file)

        assert result.tool == ToolType.NUCLEI
        assert len(result.vulnerabilities) == 1


class TestBurpParser:
    """Burp Suite 解析器测试"""

    def setup_method(self):
        self.parser = BurpParser()

    def test_can_parse(self, tmp_path):
        """测试文件识别"""
        # Burp XML 文件
        burp_content = '<?xml version="1.0"?><issues burpVersion="2024.1"><issue><name>Test</name></issue></issues>'
        burp_file = tmp_path / "burp.xml"
        burp_file.write_text(burp_content, encoding="utf-8")

        assert self.parser.can_parse(burp_file) is True

        # 非 Burp 文件
        other_content = '<?xml version="1.0"?><root><item>test</item></root>'
        other_file = tmp_path / "other.xml"
        other_file.write_text(other_content, encoding="utf-8")

        assert self.parser.can_parse(other_file) is False

    def test_parse_xml(self, tmp_path):
        """测试解析 Burp XML 格式"""
        xml_content = '''<?xml version="1.0"?>
<issues>
  <issue>
    <name>SQL Injection</name>
    <severity>High</severity>
    <host>http://example.com</host>
    <path>/api/users</path>
    <issueBackground>SQL injection vulnerability found</issueBackground>
    <type>89</type>
    <remediationBackground>Use parameterized queries</remediationBackground>
  </issue>
</issues>'''

        xml_file = tmp_path / "burp.xml"
        xml_file.write_text(xml_content, encoding="utf-8")

        result = self.parser.parse(xml_file)

        assert result.tool == ToolType.BURP
        assert len(result.vulnerabilities) == 1

        vuln = result.vulnerabilities[0]
        assert vuln.name == "SQL Injection"
        assert vuln.severity == Severity.HIGH
        assert "CWE-89" in vuln.cwe_ids


class TestNiktoParser:
    """Nikto 解析器测试"""

    def setup_method(self):
        self.parser = NiktoParser()

    def test_can_parse(self, tmp_path):
        """测试文件识别"""
        nikto_content = """- Nikto v2.5.0
Target IP: 192.168.1.1
Target Hostname: example.com
Target Port: 80
Server: Apache/2.4.51

+ OSVDB-3092: /admin/: Admin directory found
+ /phpinfo.php: PHP info file found"""

        nikto_file = tmp_path / "nikto.txt"
        nikto_file.write_text(nikto_content, encoding="utf-8")

        assert self.parser.can_parse(nikto_file) is True

    def test_parse_txt(self, tmp_path):
        """测试解析 Nikto 文本格式"""
        text_content = """- Nikto v2.5.0
Target IP: 192.168.1.1
Target Hostname: example.com
Target Port: 80
Start Time: 2024-01-01 10:00:00
End Time: 2024-01-01 10:05:00
Server: Apache/2.4.51

+ OSVDB-3092: /admin/: Admin directory found
+ OSVDB-3233: /phpinfo.php: PHP info file found
+ /backup/: Backup directory found"""

        text_file = tmp_path / "nikto.txt"
        text_file.write_text(text_content, encoding="utf-8")

        result = self.parser.parse(text_file)

        assert result.tool == ToolType.NIKTO
        assert len(result.vulnerabilities) >= 2
        assert result.target == "example.com:80"