# 渗透测试报告智能体 - 用户手册

## 目录

1. [简介](#简介)
2. [安装与配置](#安装与配置)
3. [快速开始](#快速开始)
4. [支持的工具格式](#支持的工具格式)
5. [自定义报告模板](#自定义报告模板)
6. [配置选项](#配置选项)
7. [高级用法](#高级用法)
8. [故障排除](#故障排除)
9. [最佳实践](#最佳实践)

---

## 简介

渗透测试报告智能体是一个自动化工具，用于收集、分析和生成专业的渗透测试报告。它能够：

- **自动解析**多种安全工具的输出格式
- **智能合并**多源数据，去重和关联漏洞信息
- **AI 增强**使用 LLM 生成专业的漏洞描述和修复建议
- **多格式输出**支持 Markdown、HTML、PDF、DOCX 格式

### 主要特性

- 支持 6+ 种主流安全工具
- 基于 OWASP Top 10 2021 的漏洞分类
- CVSS v3.1 风险评级
- 可自定义的报告模板
- 批量处理能力

---

## 安装与配置

### 系统要求

- Python 3.10+
- 操作系统：Windows/Linux/macOS

### 安装步骤

1. **克隆或下载项目**
   ```bash
   git clone <repository-url>
   cd pentest-report-agent
   ```

2. **安装依赖**
   ```bash
   pip install -e .
   ```

3. **配置 API Key**
   ```bash
   # Linux/macOS
   export ANTHROPIC_API_KEY="your-api-key-here"

   # Windows
   set ANTHROPIC_API_KEY=your-api-key-here
   ```

### 验证安装

```bash
pentest-agent --help
```

---

## 快速开始

### 基本用法

```bash
pentest-agent -i ./scan-results -o ./report
```

### 完整示例

```bash
pentest-agent \
  -i ./scan-results \
  -o ./pentest-report \
  -f md \
  --project-name "Web 应用安全评估" \
  --client "示例公司" \
  --tester "安全团队" \
  --scope "https://example.com"
```

### 参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--input` | `-i` | 扫描结果输入目录 | 必填 |
| `--output` | `-o` | 报告输出路径 | `./report` |
| `--format` | `-f` | 输出格式 (md/html/pdf/docx/all) | `md` |
| `--project-name` | | 报告项目名称 | `渗透测试报告` |
| `--client` | | 客户名称 | 空 |
| `--tester` | | 测试人员 | 空 |
| `--scope` | | 测试范围描述 | 空 |
| `--skip-llm` | | 跳过 LLM 生成 | `false` |
| `--config` | | 配置文件路径 | `config/settings.yaml` |

---

## 支持的工具格式

### Nmap

**支持格式：** XML (.xml)、文本 (.nmap)

**生成方式：**
```bash
# XML 格式（推荐）
nmap -sV -sC -oX scan_results.xml target.com

# 文本格式
nmap -sV -sC -oN scan_results.nmap target.com
```

**解析内容：**
- 主机信息（IP、主机名、操作系统）
- 端口和服务信息
- NSE 脚本发现的漏洞

### Nuclei

**支持格式：** JSON (.json)、JSONL (.jsonl)

**生成方式：**
```bash
# JSON 格式
nuclei -u https://target.com -json -o results.json

# JSONL 格式
nuclei -u https://target.com -jsonl -o results.jsonl
```

**解析内容：**
- 漏洞名称和描述
- CVE/CWE 分类
- CVSS 评分
- 复现步骤（curl 命令）

### Burp Suite

**支持格式：** XML (.xml)

**生成方式：**
1. 在 Burp Suite 中选择 "Report issues"
2. 选择 XML 格式导出
3. 保存为 .xml 文件

**解析内容：**
- 漏洞详情
- 请求/响应数据
- CWE 分类
- 修复建议

### SQLMap

**支持格式：** 日志 (.log)、CSV (.csv)、文本 (.txt)

**生成方式：**
```bash
# 日志格式
sqlmap -u "https://target.com/page?id=1" --batch -o output.log

# CSV 格式
sqlmap -u "https://target.com/page?id=1" --batch --output-dir=./output
```

**解析内容：**
- 注入点信息
- 注入类型
- 数据库信息
- Payload

### Metasploit

**支持格式：** XML (.xml)

**生成方式：**
```bash
# 在 msfconsole 中
db_export -f xml output.xml
```

**解析内容：**
- 主机信息
- 服务信息
- 漏洞信息
- 凭据信息

### Nikto

**支持格式：** 文本 (.txt)、日志 (.log)

**生成方式：**
```bash
# 文本格式
nikto -h https://target.com -output results.txt

# 日志格式
nikto -h https://target.com -output results.log
```

**解析内容：**
- Web 服务器漏洞
- 配置问题
- 信息泄露
- OSVDB 引用

---

## 自定义报告模板

### 模板位置

报告模板位于 `src/report/templates/` 目录：

- `report.md.j2` - Markdown 模板
- `report.html.j2` - HTML 模板

### 模板语法

使用 Jinja2 模板语法：

```jinja2
{{ variable }}  # 变量输出
{% if condition %}...{% endif %}  # 条件判断
{% for item in list %}...{% endfor %}  # 循环
```

### 可用变量

#### 项目信息
- `{{ project.project_name }}` - 项目名称
- `{{ project.client }}` - 客户名称
- `{{ project.tester }}` - 测试人员
- `{{ project.test_start }}` - 测试开始时间
- `{{ project.test_end }}` - 测试结束时间
- `{{ project.scope }}` - 测试范围

#### 统计信息
- `{{ stats.total_vulns }}` - 漏洞总数
- `{{ stats.critical }}` - 严重漏洞数
- `{{ stats.high }}` - 高危漏洞数
- `{{ stats.medium }}` - 中危漏洞数
- `{{ stats.low }}` - 低危漏洞数
- `{{ stats.info }}` - 信息发现数
- `{{ stats.total_hosts }}` - 主机总数
- `{{ stats.open_ports }}` - 开放端口数

#### 主机列表
```jinja2
{% for host in hosts %}
  {{ host.ip }} - {{ host.hostname }}
  {{ host.os }} - {{ host.state }}

  {% for svc in host.services %}
    {{ svc.port }}/{{ svc.protocol }} - {{ svc.service }} {{ svc.version }}
  {% endfor %}
{% endfor %}
```

#### 漏洞列表
```jinja2
{% for vuln in vulnerabilities %}
  {{ vuln.name }} - {{ vuln.severity.value }}
  {{ vuln.description }}
  {{ vuln.affected_asset }}

  {% if vuln.reproduction_steps %}
    {% for step in vuln.reproduction_steps %}
      {{ loop.index }}. {{ step }}
    {% endfor %}
  {% endif %}

  {% if vuln.remediation %}
    修复建议: {{ vuln.remediation }}
  {% endif %}
{% endfor %}
```

#### 严重等级标签
```jinja2
{{ severity_labels[vuln.severity.value] }}  # 输出：严重/高危/中危/低危/信息
```

### 自定义示例

#### 添加公司 Logo

```jinja2
# {{ project.project_name }}

![Logo](path/to/logo.png)

**生成时间:** {{ generated_at }}
```

#### 自定义漏洞表格

```jinja2
| 漏洞名称 | 严重等级 | CVSS | 受影响资产 | 状态 |
|---------|---------|------|-----------|------|
{% for vuln in vulnerabilities %}
| {{ vuln.name }} | {{ severity_labels[vuln.severity.value] }} | {{ vuln.cvss_score or "N/A" }} | {{ vuln.affected_asset }} | 待修复 |
{% endfor %}
```

#### 添加风险评估图表

```jinja2
## 风险分布

```mermaid
pie title 漏洞严重等级分布
    "严重" : {{ stats.critical }}
    "高危" : {{ stats.high }}
    "中危" : {{ stats.medium }}
    "低危" : {{ stats.low }}
    "信息" : {{ stats.info }}
```
```

---

## 配置选项

### 配置文件

配置文件位于 `config/settings.yaml`：

```yaml
# LLM 配置
llm:
  provider: claude
  model: claude-sonnet-4-20250514
  max_tokens: 4096
  temperature: 0.3

# 报告配置
report:
  default_format: md
  language: zh-CN
  org:
    name: "安全评估团队"
    logo: ""

# 风险评级阈值
rating:
  thresholds:
    critical: 9.0
    high: 7.0
    medium: 4.0
    low: 0.1
    info: 0.0

# 解析器配置
parsers:
  auto_detect: true
  extensions:
    ".xml": ["nmap", "burp", "metasploit"]
    ".json": ["nuclei"]
    ".jsonl": ["nuclei"]
    ".log": ["sqlmap", "nikto"]
    ".csv": ["sqlmap"]
    ".txt": ["nikto"]
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | Claude API Key | 必填 |
| `PENTEST_REPORT_FORMAT` | 默认输出格式 | `md` |
| `PENTEST_REPORT_LANG` | 报告语言 | `zh-CN` |

---

## 高级用法

### 批量处理

```bash
# 处理多个扫描结果目录
for dir in ./scan1 ./scan2 ./scan3; do
  pentest-agent -i "$dir" -o "./reports/$(basename $dir)"
done
```

### 跳过 LLM 生成

如果不需要 AI 生成的描述，可以跳过 LLM 步骤：

```bash
pentest-agent -i ./scan-results -o ./report --skip-llm
```

### 使用自定义配置

```bash
pentest-agent -i ./scan-results -o ./report --config ./my-config.yaml
```

### 生成多种格式

```bash
pentest-agent -i ./scan-results -o ./report -f all
```

---

## 故障排除

### 常见问题

#### 1. API Key 错误

**错误信息：**
```
ValueError: 未设置 ANTHROPIC_API_KEY 环境变量
```

**解决方案：**
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

#### 2. 文件解析失败

**错误信息：**
```
[FAIL] scan.xml: Parse error
```

**解决方案：**
- 检查文件格式是否正确
- 确认文件编码为 UTF-8
- 验证文件是否损坏

#### 3. 模板渲染错误

**错误信息：**
```
jinja2.exceptions.TemplateNotFound
```

**解决方案：**
- 检查模板文件是否存在
- 验证模板语法是否正确
- 确认变量名拼写

#### 4. 内存不足

**错误信息：**
```
MemoryError
```

**解决方案：**
- 减少同时处理的文件数量
- 使用 `--skip-llm` 跳过 LLM 生成
- 分批处理大型扫描结果

### 调试模式

```bash
# 启用详细日志
export PYTHONDEBUG=1
pentest-agent -i ./scan-results -o ./report
```

---

## 最佳实践

### 1. 扫描结果组织

```
scan-results/
├── nmap/
│   ├── scan1.xml
│   └── scan2.xml
├── nuclei/
│   └── results.jsonl
├── burp/
│   └── issues.xml
└── sqlmap/
    └── output.log
```

### 2. 命名规范

- 使用描述性文件名
- 包含工具名称和目标
- 示例：`nmap_example.com_20240101.xml`

### 3. 定期备份

```bash
# 备份扫描结果
tar -czf scan-results-backup.tar.gz ./scan-results

# 备份报告
cp ./report.md ./backups/report-$(date +%Y%m%d).md
```

### 4. 报告审查

生成报告后，建议：

1. **检查漏洞描述**：确保技术细节准确
2. **验证修复建议**：确认建议的可行性
3. **补充业务影响**：添加具体的业务影响说明
4. **更新复现步骤**：验证步骤的可操作性

### 5. 团队协作

- 使用版本控制管理报告模板
- 建立报告审查流程
- 维护漏洞知识库
- 定期更新 LLM prompts

---

## 附录

### A. 漏洞严重等级定义

| 等级 | CVSS 分数 | 说明 |
|------|----------|------|
| 严重 (Critical) | 9.0-10.0 | 远程代码执行、SQL 注入、认证绕过 |
| 高危 (High) | 7.0-8.9 | SSRF、CSRF、路径遍历、文件包含 |
| 中危 (Medium) | 4.0-6.9 | XSS、信息泄露、配置错误 |
| 低危 (Low) | 0.1-3.9 | 版本泄露、Cookie 标志缺失 |
| 信息 (Info) | 0.0 | 信息性发现 |

### B. OWASP Top 10 2021

1. A01:2021 - Broken Access Control
2. A02:2021 - Cryptographic Failures
3. A03:2021 - Injection
4. A04:2021 - Insecure Design
5. A05:2021 - Security Misconfiguration
6. A06:2021 - Vulnerable and Outdated Components
7. A07:2021 - Identification and Authentication Failures
8. A08:2021 - Software and Data Integrity Failures
9. A09:2021 - Security Logging and Monitoring Failures
10. A10:2021 - Server-Side Request Forgery (SSRF)

### C. 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Anthropic Claude API](https://docs.anthropic.com/claude/reference)

---

*本手册最后更新时间: 2024*
*版本: 1.0*
