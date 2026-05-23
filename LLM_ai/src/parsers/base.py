"""解析器基类和注册表"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from src.models.schemas import ScanResult, ToolType


class BaseParser(ABC):
    """工具输出解析器抽象基类"""

    tool_type: ToolType = ToolType.UNKNOWN
    supported_extensions: list[str] = []

    @abstractmethod
    def parse(self, file_path: Path) -> ScanResult:
        """解析工具输出文件，返回结构化 ScanResult"""
        ...

    def can_parse(self, file_path: Path) -> bool:
        """判断是否能解析该文件"""
        return file_path.suffix.lower() in self.supported_extensions

    def _make_result(self, file_path: Path) -> ScanResult:
        """创建空的 ScanResult 模板"""
        return ScanResult(
            tool=self.tool_type,
            source_file=str(file_path),
        )


# 解析器注册表
_PARSER_REGISTRY: list[type[BaseParser]] = []


def register_parser(cls: type[BaseParser]) -> type[BaseParser]:
    """装饰器：注册解析器到全局注册表"""
    _PARSER_REGISTRY.append(cls)
    return cls


def get_parsers() -> list[type[BaseParser]]:
    """获取所有已注册的解析器类"""
    return list(_PARSER_REGISTRY)


def detect_parser(file_path: Path) -> BaseParser | None:
    """根据文件自动检测合适的解析器"""
    for parser_cls in _PARSER_REGISTRY:
        parser = parser_cls()
        if parser.can_parse(file_path):
            return parser
    return None
