"""智能体核心调度器"""

from __future__ import annotations

from pathlib import Path

import yaml

from src.agent.pipeline import Pipeline
from src.llm.client import LLMClient
from src.models.schemas import PentestReport, ProjectInfo


class PentestAgent:
    """渗透测试报告智能体"""

    def __init__(self, config_path: Path | None = None):
        self.config = self._load_config(config_path)

    def run(
        self,
        input_dir: str | Path,
        output: str | Path = "./report",
        format: str = "md",
        project_name: str = "渗透测试报告",
        client: str = "",
        tester: str = "",
        scope: str = "",
        skip_llm: bool = False,
    ) -> PentestReport:
        """执行完整流程"""
        input_path = Path(input_dir)
        output_path = Path(output)

        # 构建项目信息
        project_info = ProjectInfo(
            project_name=project_name,
            client=client,
            tester=tester,
            scope=scope,
            tools_used=self._detect_tools(input_path),
        )

        # 初始化 LLM 客户端
        llm_client = None
        if not skip_llm:
            llm_config = self.config.get("llm", {})
            try:
                llm_client = LLMClient(
                    model=llm_config.get("model", "claude-sonnet-4-20250514"),
                    max_tokens=llm_config.get("max_tokens", 4096),
                    temperature=llm_config.get("temperature", 0.3),
                )
            except ValueError:
                skip_llm = True

        # 执行流水线
        pipeline = Pipeline(
            input_dir=input_path,
            output_path=output_path,
            output_format=format,
            project_info=project_info,
            llm_client=llm_client,
            skip_llm=skip_llm,
        )

        return pipeline.run()

    def _load_config(self, config_path: Path | None) -> dict:
        """加载配置文件"""
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "settings.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def _detect_tools(self, input_dir: Path) -> list[str]:
        """检测输入目录中使用的工具"""
        tools = set()
        if not input_dir.exists():
            return []
        for f in input_dir.rglob("*"):
            if not f.is_file():
                continue
            name = f.name.lower()
            if "nmap" in name:
                tools.add("nmap")
            elif "nuclei" in name:
                tools.add("nuclei")
            elif "sqlmap" in name:
                tools.add("sqlmap")
            elif "burp" in name:
                tools.add("burp")
            elif "msf" in name or "metasploit" in name:
                tools.add("metasploit")
            elif "nikto" in name:
                tools.add("nikto")
        return list(tools)
