"""工具输出解析器"""

from src.parsers.base import detect_parser, get_parsers, register_parser
from src.parsers.burp_parser import BurpParser
from src.parsers.metasploit_parser import MetasploitParser
from src.parsers.nikto_parser import NiktoParser
from src.parsers.nmap_parser import NmapParser
from src.parsers.nuclei_parser import NucleiParser
from src.parsers.sqlmap_parser import SqlmapParser

__all__ = [
    "detect_parser",
    "get_parsers",
    "register_parser",
    "NmapParser",
    "NucleiParser",
    "SqlmapParser",
    "BurpParser",
    "MetasploitParser",
    "NiktoParser",
]
