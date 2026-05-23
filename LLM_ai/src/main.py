"""CLI 入口 - 渗透测试报告智能体"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from src.agent.core import PentestAgent

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pentest-agent",
        description="渗透测试报告智能体 - 自动收集、分析、生成渗透测试报告",
    )
    parser.add_argument(
        "-i", "--input",
        type=str,
        required=True,
        help="扫描结果输入目录（包含 Nmap/Nuclei/SQLMap/Burp/Metasploit 输出文件）",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./report",
        help="报告输出路径（不含扩展名），默认: ./report",
    )
    parser.add_argument(
        "-f", "--format",
        type=str,
        choices=["md", "html", "pdf", "docx", "all", "json", "csv", "summary"],
        default="md",
        help="输出格式，默认: md",
    )
    parser.add_argument(
        "--project-name",
        type=str,
        default="渗透测试报告",
        help="报告项目名称",
    )
    parser.add_argument(
        "--client",
        type=str,
        default="",
        help="客户名称",
    )
    parser.add_argument(
        "--tester",
        type=str,
        default="",
        help="测试人员",
    )
    parser.add_argument(
        "--scope",
        type=str,
        default="",
        help="测试范围描述",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="跳过 LLM 生成（仅解析和结构化，不生成自然语言描述）",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="配置文件路径（默认: config/settings.yaml）",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    console.print("[bold blue]渗透测试报告智能体[/bold blue]")
    console.print("=" * 50)

    config_path = Path(args.config) if args.config else None
    agent = PentestAgent(config_path=config_path)

    try:
        report = agent.run(
            input_dir=args.input,
            output=args.output,
            format=args.format,
            project_name=args.project_name,
            client=args.client,
            tester=args.tester,
            scope=args.scope,
            skip_llm=args.skip_llm,
        )

        console.print("\n[bold green]报告生成完成！[/bold green]")
        console.print(f"  漏洞总数: {len(report.vulnerabilities)}")
        console.print(f"  严重: {report.critical_count} | 高危: {report.high_count} | 中危: {report.medium_count} | 低危: {report.low_count} | 信息: {report.info_count}")

    except Exception as e:
        console.print(f"\n[bold red]错误:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
