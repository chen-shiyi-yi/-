# 示例数据

本目录包含用于演示和测试的示例扫描数据。

## 文件说明

- `nmap_scan.xml` - Nmap 扫描结果示例
- `nuclei_results.jsonl` - Nuclei 扫描结果示例
- `burp_issues.xml` - Burp Suite 导出示例

## 快速演示

### 使用示例数据生成报告

```bash
# 使用示例数据生成 Markdown 报告（跳过 LLM）
python -m src.main -i ./examples -o ./demo-report --skip-llm

# 生成 HTML 报告
python -m src.main -i ./examples -o ./demo-report -f html --skip-llm

# 生成所有格式
python -m src.main -i ./examples -o ./demo-report -f all --skip-llm
```

### 使用 LLM 生成增强报告

```bash
# 设置 API Key
export ANTHROPIC_API_KEY="your-api-key"

# 生成带 AI 增强的报告
python -m src.main -i ./examples -o ./demo-report -f md \
  --project-name "示例渗透测试报告" \
  --client "示例公司" \
  --tester "安全团队" \
  --scope "192.168.1.0/24"
```

## 数据格式说明

### Nmap XML 格式

```xml
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.51"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

### Nuclei JSONL 格式

```json
{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},"host":"http://example.com"}
```

### Burp Suite XML 格式

```xml
<issues>
  <issue>
    <name>SQL injection</name>
    <severity>High</severity>
    <host>http://example.com</host>
    <path>/api/users</path>
  </issue>
</issues>
```
