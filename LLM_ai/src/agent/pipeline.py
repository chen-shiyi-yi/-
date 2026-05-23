"""处理流水线 - 采集 → 解析 → 抽取 → 分类 → 评级 → LLM生成 → 报告输出"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.extractors.info_extractor import InfoExtractor
from src.extractors.vuln_classifier import VulnClassifier
from src.llm.client import LLMClient
from src.llm.generator import ReportGenerator
from src.models.schemas import PentestReport, ProjectInfo, ScanResult
from src.parsers import detect_parser
from src.rating.risk_scorer import RiskScorer
from src.report.builder import ReportBuilder
from src.report.renderer import ReportRenderer

# 处理 Windows 终端编码问题
console = Console(force_terminal=False, file=open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1))


class Pipeline:
    """渗透测试报告生成流水线"""

    def __init__(
        self,
        input_dir: Path,
        output_path: Path,
        output_format: str = "md",
        project_info: ProjectInfo | None = None,
        llm_client: LLMClient | None = None,
        skip_llm: bool = False,
    ):
        self.input_dir = input_dir
        self.output_path = output_path
        self.output_format = output_format
        self.project_info = project_info or ProjectInfo()
        self.llm_client = llm_client
        self.skip_llm = skip_llm

        self.extractor = InfoExtractor()
        self.classifier = VulnClassifier()
        self.scorer = RiskScorer()
        self.renderer = ReportRenderer()

    def run(self) -> PentestReport:
        """执行完整流水线"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Step 1: 解析工具输出
            task = progress.add_task("解析工具输出文件...", total=None)
            scan_results = self._parse_inputs()
            progress.update(task, description=f"已解析 {len(scan_results)} 个文件")

            # Step 2: 信息抽取 & 合并
            task = progress.add_task("抽取并合并扫描结果...", total=None)
            hosts, vulns = self.extractor.extract(scan_results)
            progress.update(task, description=f"合并完成: {len(hosts)} 台主机, {len(vulns)} 个漏洞")

            # Step 3: 漏洞分类
            task = progress.add_task("漏洞分类 (OWASP Top 10)...", total=None)
            self.classifier.classify_batch(vulns)
            progress.update(task, description="分类完成")

            # Step 4: 风险评级
            task = progress.add_task("风险评级...", total=None)
            self.scorer.score_batch(vulns)
            risk_summary = self.scorer.get_risk_summary(vulns)
            progress.update(task, description="评级完成")

            # Step 5: 构建报告对象
            report = PentestReport(
                project=self.project_info,
                hosts=hosts,
                vulnerabilities=vulns,
                risk_summary=risk_summary,
            )

            # Step 6: LLM 生成自然语言内容
            if not self.skip_llm and self.llm_client:
                generator = ReportGenerator(self.llm_client)
                task = progress.add_task("LLM 生成漏洞描述...", total=len(vulns))
                for i, vuln in enumerate(vulns):
                    generator.generate_vulnerability_details(vuln)
                    progress.update(task, advance=1)

                task = progress.add_task("LLM 生成执行摘要...", total=None)
                report.executive_summary = generator.generate_executive_summary(report)
                progress.update(task, description="执行摘要生成完成")
            else:
                report.executive_summary = self._generate_default_summary(report)

            # Step 7: 渲染报告
            task = progress.add_task("渲染报告...", total=None)
            builder = ReportBuilder(report)
            output_files = self._render(builder)
            progress.update(task, description=f"报告已生成: {', '.join(str(f) for f in output_files.values())}")

        # 输出统计
        if self.llm_client:
            stats = self.llm_client.token_stats
            console.print(f"\n[dim]Token 使用: 输入 {stats['input_tokens']}, 输出 {stats['output_tokens']}, 总计 {stats['total_tokens']}[/dim]")

        return report

    def _parse_inputs(self) -> list[ScanResult]:
        """扫描输入目录，解析所有工具输出文件"""
        results = []
        if not self.input_dir.exists():
            console.print(f"[red]输入目录不存在: {self.input_dir}[/red]")
            return results

        for file_path in sorted(self.input_dir.rglob("*")):
            if not file_path.is_file():
                continue
            parser = detect_parser(file_path)
            if parser:
                try:
                    result = parser.parse(file_path)
                    results.append(result)
                    console.print(f"  [green][OK][/green] {file_path.name} -> {parser.tool_type.value}")
                except Exception as e:
                    console.print(f"  [red][FAIL][/red] {file_path.name}: {e}")
            else:
                console.print(f"  [dim][--][/dim] {file_path.name}: skipped")

        return results

    def _render(self, builder: ReportBuilder) -> dict[str, Path]:
        """根据格式渲染报告"""
        output_files = {}

        if self.output_format == "all":
            output_files = self.renderer.render_all(builder, self.output_path)
        elif self.output_format == "md":
            output_files["md"] = self.renderer.render_markdown(builder, self.output_path)
        elif self.output_format == "html":
            output_files["html"] = self.renderer.render_html(builder, self.output_path)
        elif self.output_format == "pdf":
            output_files["pdf"] = self.renderer.render_pdf(builder, self.output_path)
        elif self.output_format == "docx":
            output_files["docx"] = self.renderer.render_docx(builder, self.output_path)
        elif self.output_format == "json":
            output_files["json"] = self.renderer.export_json(builder, self.output_path)
        elif self.output_format == "csv":
            output_files["csv"] = self.renderer.export_csv(builder, self.output_path)
        elif self.output_format == "summary":
            output_files["summary"] = self.renderer.export_summary(builder, self.output_path)
        else:
            output_files["md"] = self.renderer.render_markdown(builder, self.output_path)

        return output_files

    def _generate_default_summary(self, report: PentestReport) -> str:
        """不使用 LLM 时的默认摘要"""
        parts = [
            f"本次渗透测试共扫描 {len(report.hosts)} 台主机，",
            f"发现 {len(report.vulnerabilities)} 个安全问题。",
        ]
        if report.critical_count:
            parts.append(f"其中 {report.critical_count} 个严重漏洞需要立即修复。")
        if report.high_count:
            parts.append(f"{report.high_count} 个高危漏洞建议优先处理。")
        if not report.critical_count and not report.high_count:
            parts.append("未发现严重或高危漏洞。")
        return "".join(parts)
