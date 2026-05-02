# jar-analyzer Web 工作台实现说明

> 基于分支 `feature/interactive-callgraph-and-taint-visualization` (commit `5508f1a7`) 实际代码编写。

---

## 总体架构

```
浏览器 (SPA)                    Java 后端                     外部服务
┌──────────────────┐    HTTP    ┌──────────────────────┐    HTTPS   ┌──────────┐
│ index.html       │ ─────────→ │ NanoHTTPD :10032     │ ────────→ │ LLM API  │
│ dashboard.js     │ ←───────── │ (com.sun.net.httpserver)│ ←────── │ (OpenAI/  │
│ dashboard.css    │    JSON/   │                       │          │ DeepSeek/ │
│ (约 1600 行 JS)   │    HTML    │ 38 个 API Handler     │          │ Ollama)   │
└──────────────────┘            │ CoreEngine (MyBatis)  │          └──────────┘
                                │ SQLite (jar-analyzer.db)│
                                └──────────────────────┘
```

**关键技术选型**：
- 前端：原生 JavaScript（零框架依赖），单页应用，hash 路由
- 后端 HTTP：`com.sun.net.httpserver`（JDK 内置，零额外依赖）
- 数据层：MyBatis 操作 SQLite，查询走二级缓存
- 序列化：Fastjson2
- 图表：D3.js v6（力导向图布局）

---

## 模块一：HTTP API 路由系统

**文件**：`server/PathMatcher.java` (87 行)

### 架构

所有路由集中在一个 `static` 块中注册，使用 HashMap 做精确匹配：

```
/handlerMap (HashMap<String, HttpHandler>)
  ├── 静态资源: /index, /favicon.ico, /static/dashboard.js, /static/dashboard.css
  ├── 报告页:   /report/latest, /report/latest.html
  ├── API (内部): /api/server_status, /api/generate_audit_report,
  │              /api/start_project_build, /api/build_status,
  │              /api/method_graph, /api/security_overview, ...
  └── API (MCP可调用): /api/get_callers, /api/get_callee,
                       /api/fernflower_code, /api/cfr_code,
                       /api/dfs_analyze, /api/taint_graph, ...
```

### 鉴权机制

`PathMatcher.handleReq()` 对所有 `/api/` 路径检查 Token Header（大小写兼容 `Token` / `token`）。鉴权是可选的，由 GUI 启动参数 `-sa` / `-st` 控制。未通过鉴权返回 HTML 错误页，前端识别 `NEED TOKEN HEADER` 关键字后提示用户填写 Token。

### 亮点

**API 分层设计**：注释明确标记了"内部 API"和"MCP 可调用 API"。MCP Server（Go 语言编写的独立进程）通过调用下半部分的 API 获取反编译代码、方法信息等，而上半部分的构建、报告生成等功能不暴露给 MCP。

---

## 模块二：前端 SPA 框架

**文件**：`index.html` (519 行), `dashboard.js` (1652 行), `dashboard.css` (838 行)

### 页面路由

使用 URL hash 实现 7 个页面的切换：

```
#overview  → 概览
#build     → 浏览器构建
#search    → 方法检索
#method    → 方法工作台
#dfs       → DFS 分析
#security  → 安全巡航
#report    → LLM 报告
```

`syncPageFromHash()` 在页面加载和 hashchange 事件时触发，`activatePage()` 切换对应 section 的 `workspace-page-active` CSS class，并执行惰性加载逻辑（如首次进入 security 页面时自动请求数据）。

### 状态管理

全局 `state` 对象集中管理所有跨页面状态：
- `selectedMethod`：当前选中的方法（在搜索/安全巡航中选中，在工作台中消费）
- `methodGraphHtml` / `taintGraphHtml`：缓存的图表 HTML
- `reportMarkdown` / `reportHtml`：缓存的报告内容
- `securityData` / `securityLoaded`：安全巡航缓存标记
- `activePage`：当前页面

### Token 持久化

`localStorage` 存储 API Token（key: `jar-analyzer-browser-token`）。每次 API 请求自动从输入框读取并附加到 `Token` Header。清空 Token 时调用 `localStorage.removeItem()`。

### 亮点

**零框架依赖**：全部使用原生 DOM API 和 Fetch API，无 React/Vue/jQuery。这保证了在任何现代浏览器中开箱即用，不需要 npm install。

**统一的错误处理**：`buildFriendlyError()` 识别特定的错误字符串（`CORE ENGINE IS NULL`、`NEED TOKEN HEADER`）并转换为中文友好提示；`showNotice()` 在页面顶部显示全局通知，3 种样式（success/warning/error）。

**方法选中交互**：搜索结果中的每条方法记录都带"选中"按钮，点击后调用 `setSelectedMethod()` 同时更新表单字段和侧边栏卡片，再自动跳转到方法工作台页面。

---

## 模块三：浏览器构建

**文件**：`server/ProjectBuildManager.java` (261 行), `server/handler/StartProjectBuildHandler.java` (90 行), `server/handler/GetBuildStatusHandler.java` (40 行)

### 架构

```
浏览器                        ProjectBuildManager                CoreRunner
  │                                │                                │
  ├─ POST /api/start_project_build─→                                │
  │  (文件二进制 或 server_path)     │                                │
  │                                ├─ synchronized(start)           │
  │                                │  检查 running 标志              │
  │                                │  启动 daemon 线程               │
  │                                │                                │
  │  ←──── {success, started} ────┤                                │
  │                                │                                │
  │  ┌─ 每 1.8s 轮询 ─────────────→                                │
  │  │ GET /api/build_status       │                                │
  │  │                             ├─ snapshot()                    │
  │  │ ←── {progress, logs, ...} ──┤ 返回 volatile 字段快照          │
  │  └─ 直到 finished=true ────────┤                                │
  │                                │                                │
  │                                ├─ runBuild()                    │
  │                                │  └─ CoreRunner.runBrowser() ──→ 解析 JAR
  │                                │                                写入 SQLite
  │                                │  ←──── 完成 ───────────────────
  │                                ├─ finished=true, success=true
```

### 实现细节

**两种输入方式**（`StartProjectBuildHandler`）：
1. **文件上传**：二进制 body + `X-File-Name` Header → 保存到 `jar-analyzer-download/browser-upload/{timestamp}-{filename}`
2. **服务器路径**：`source_path` 参数，要求文件已存在于服务器本地

**防重入**：`start()` 方法使用 `synchronized` + `running` 标志保证同时只有一个构建任务。

**进度模拟**：`resolveMessage()` 根据 `progress` 百分比区间返回对应的阶段描述文字（15% = "正在解析 class 并落库"、70% = "正在写入方法调用关系" 等）。同时从 GUI 的 `BuildBar.getValue()` 同步真实进度。

**日志系统**：`LinkedList<String>` 做日志缓存，最多保留 160 条，每条带 `[HH:mm:ss]` 时间戳，`snapshot()` 返回副本。

**前端轮询**：`scheduleBuildPolling()` 使用 `window.setTimeout`（非 setInterval），每次收到响应后才安排下一次，间隔 1.8 秒。`finished` 为 true 时自动停止。

### 亮点

**构建不阻塞浏览器**：后台线程执行，浏览器无需保持连接。通过 `/api/build_status` 轮询获取实时进度，前端用进度条 + 日志区展示。构建完成后自动触发状态刷新和安全巡航数据重载。

---

## 模块四：方法检索与工作台

**文件**：`server/handler/GetMethodsByClassHandler.java`, `GetMethodsByStrHandler.java`, `GetCallersHandler.java`, `GetCalleeHandler.java`, `GetImplsHandler.java`, `GetSuperImplsHandler.java`, `GetCodeCFRHandler.java`, `GetCodeFernflowerHandler.java`, `MethodGraphHandler.java`

### 调用关系查询

所有查询最终走 `CoreEngine` 的 MyBatis 映射器，直接对 SQLite 执行 SQL：

| API | SQL 逻辑 | 返回 |
|-----|---------|------|
| `/api/get_callers` | `method_call_table WHERE callee_* = ?` | 调用者列表 |
| `/api/get_callee` | `method_call_table WHERE caller_* = ?`  | 被调用列表 |
| `/api/get_impls` | `method_impl_table` 精确匹配 | 实现类列表 |
| `/api/get_super_impls` | `method_impl_table` 父类接口查询 | 父类实现 |
| `/api/get_methods_by_class` | `method_table WHERE class_name = ?` | 类的方法列表 |
| `/api/get_methods_by_str` | `string_table WHERE value LIKE ?` | 包含字符串的方法 |

### 反编译

CFR 和 Fernflower 两个引擎的输出格式是：
```json
{
  "methodCode": "public void exec(String cmd) { ... }",
  "fullClassCode": "package com.demo; public class ... { ... }"
}
```

`methodCode` 是方法级精确提取（从完整类代码中按大括号匹配截取），`fullClassCode` 是整个类的反编译结果。前端以折叠面板展示。

### 方法调用图

`MethodGraphHandler` 查询当前方法的 callers + callees，调用 `RenderEngine.renderHtml()` 生成 D3.js 力导向图 HTML。前端用 iframe 的 `srcdoc` 属性直接渲染，不通过文件。

### 亮点

**方法级代码提取**：不是返回整个类的反编译结果让用户自己找，而是精确匹配方法签名（含 JVM 描述符），在完整类代码中定位到方法头行，再按大括号匹配提取方法体。这依赖于 `slicer.py` 同款算法在 Java 侧的实现。

**D3.js 交互式调用图**：不是静态 SVG，是力导向图——节点可以拖拽、缩放，双击节点可以展开更深层调用关系（在 GUI 版本中支持，Web 版本展示核心调用图）。

---

## 模块五：DFS 分析与污点图

**文件**：`server/handler/DFSHandler.java` (141 行), `server/handler/TaintGraphHandler.java` (107 行), `dfs/DFSEngine.java`, `taint/TaintAnalyzer.java`

### DFS 分析流程

```
/api/dfs_analyze
  │
  ├─ 参数: sink_class, sink_method, sink_method_desc
  │        source_class, source_method, source_method_desc (可选)
  │        depth, limit, from_sink, search_null_source
  │
  ├─ DFSEngine.doAnalyze()
  │   ├─ from_sink=true:  从 Sink 反向 BFS，搜索到达 Sink 的调用者
  │   │                   再正向搜索调用者的调用者（Web 入口）
  │   ├─ from_sink=false: 从指定 Source 正向 DFS 到 Sink
  │   └─ search_null_source=true: Source 为空时自动枚举
  │       所有 Spring 端点 + Servlet/Filter 入口
  │
  └─ 返回 List<DFSResult> (JSON 数组)
```

### 污点图生成

`TaintGraphHandler` 的两步流程：
1. 先执行 DFS 分析（同 `DFSHandler`）
2. 将每条 DFS 路径送入 `TaintAnalyzer.analyze()` 做 JVM 栈帧级污点验证
3. `TaintGraphRenderEngine.buildChainsJson()` 将污点分析结果序列化为 D3.js 所需的 JSON 格式
4. `HtmlGraphUtil.renderTaintGraph()` 将 JSON 注入 HTML 模板，返回完整 HTML

污点分析失败时（如类文件缺失）回退为仅展示 DFS 路径。

### 前端 DFS 预设

`dashboard.js` 中的 `SECURITY_PRESETS` 数组定义了 8 个预设：

```javascript
{ id: 'runtime-exec',       sinkClass: 'java/lang/Runtime',        sinkMethod: 'exec',         ... }
{ id: 'processbuilder-start', sinkClass: 'java/lang/ProcessBuilder', sinkMethod: 'start',       ... }
{ id: 'jndi-lookup',        sinkClass: 'javax/naming/Context',     sinkMethod: 'lookup',       ... }
{ id: 'deserialization',    sinkClass: 'java/io/ObjectInputStream', sinkMethod: 'readObject',   ... }
{ id: 'script-eval',        sinkClass: 'javax/script/ScriptEngine', sinkMethod: 'eval',         ... }
{ id: 'ssrf-url',           sinkClass: 'java/net/URL',             sinkMethod: 'openConnection',... }
{ id: 'file-write',         sinkClass: 'java/io/FileOutputStream', sinkMethod: '<init>',        ... }
{ id: 'reflection-invoke',  sinkClass: 'java/lang/reflect/Method',  sinkMethod: 'invoke',       ... }
```

DFS 面板和安全巡航页面都渲染这些预设，点击按钮时 `applyDfsPreset()` 填充表单并跳转到 DFS 面板。

### 亮点

**Sink → Source 反向搜索**：传统的调用链分析是从入口正向追。DFS 分析默认从危险 Sink 反向 BFS，自动找到所有能到达 Sink 的 Web 入口。这对于漏洞挖掘场景更实用——审计人员先确定危险函数，再反向追查调用来源。

**DFS + 污点双重验证**：DFS 找到的调用链只是静态调用关系，污点分析进一步在 JVM 栈帧级别验证数据是否真的能从 Source 流向 Sink（参数是否被传递、是否被常量覆盖等）。

---

## 模块六：安全巡航

**文件**：`server/handler/GetSecurityOverviewHandler.java` (219 行)

### 架构

这是一个**聚合型 API**，单次请求返回所有安全巡航数据：

```
GET /api/security_overview
  │
  ├─ engine.getAllSpringC()     → controllers[]
  ├─ engine.getAllServlets()    → servlets[]
  ├─ engine.getAllFilters()     → filters[]
  ├─ engine.getAllListeners()   → listeners[]
  ├─ engine.getSpringM() for each controller → mappings[]
  │
  └─ 7 类 Hunt (每类调用 engine.getCallersLike()):
      ├─ command-exec:    Runtime.exec + ProcessBuilder.start
      ├─ jndi-lookup:     Context.lookup + InitialContext.lookup
      ├─ deserialization: ObjectInputStream.readObject
      ├─ script-eval:     ScriptEngine.eval
      ├─ ssrf-network:    URL.openConnection
      ├─ reflection:      Method.invoke + ClassLoader.loadClass
      └─ file-write:      FileOutputStream.<init> + Files.write
```

### 数据结构

```json
{
  "success": true,
  "assets": {
    "controllers": [{ "className": "..." }, ...],  // 按类名排序
    "servlets": [...],
    "filters": [...],
    "listeners": [...],
    "mappings": [{                                // Spring 端点映射
      "className": "...",
      "methodName": "...",
      "methodDesc": "...",
      "restfulType": "POST",                       // GET/POST/PUT/DELETE
      "actualPath": "/api/exec"
    }, ...]                                        // 按路径→类名→方法名排序
  },
  "hunts": [{
    "id": "command-exec",
    "title": "命令执行",
    "severity": "high",                            // critical / high / medium
    "presetId": "runtime-exec",                    // 关联到 DFS 预设
    "callerCount": 5,                              // 命中数量
    "findings": [{                                 // 前 5 条详情
      "className": "...",
      "methodName": "...",
      "methodDesc": "...",
      "matchedSink": "Runtime.exec"
    }, ...]
  }, ...]
}
```

### 前端渲染

**风险摘要卡片**：`resolveSecuritySummary()` 动态计算：
- Web 入口资产 = controllers + servlets + filters + listeners 总数
- Spring 路由 = mappings 数量
- 命中风险类别 = 有命中的 Hunt 数量
- 风险得分 = `min(100, entrypoint×2 + mapping + Σ(min(callerCount,8) × severityWeight))`

**优先排查方向**：按 `severityScore × callerCount` 排序，带比例条可视化（`priority-meter`），每个方向可一键套用 DFS 预设。

**内置漏洞排查**：每类 Hunt 展示前 5 条命中，每条带两个操作按钮：
- "送入工作台" → `setSelectedMethod()` + `activatePage('method')`
- "调用图" → `setSelectedMethod()` + `activatePage('method')` + `loadMethodGraph()`

**Spring 入口映射**：展示 HTTP 方法 + 路径 + 类名 + 方法名，同样可送入工作台或生成调用图。

### 亮点

**一个 API 搞定全局态势**：安全巡航将 Web 入口枚举 + 7 类危险 Sink 调用者排查 + Spring 映射提取合并到一个请求中。不需要用户分别去"先看看有哪些 Controller"、"再搜搜有没有 Runtime.exec"、"再看看路径映射"——打开页面就是全局态势。

**风险得分是算法化的**：不是拍脑袋的 0-100 评分。入口数量、映射数量、危险命中数量和严重权重都有明确的权重系数，可解释、可复现。

**从巡航到深挖的闭环**："送入工作台"和"调用图"按钮实现了每个发现的可操作化。安全研究员看到一条命中后，点一下就进入该方法的工作台，接着就能反编译、查调用链、追 DFS。

---

## 模块七：LLM 审计报告

**文件**：
- `report/LLMConfig.java` (101 行)
- `report/LLMClient.java` (150 行)
- `report/AuditReportBuilder.java` (212 行)
- `report/MarkdownReportRenderer.java` (388 行)
- `report/ReportPanel.java` (459 行，Swing GUI)
- `oneclick/OneClickAnalyzer.java` (229 行)
- `server/handler/GenerateAuditReportHandler.java` (181 行)
- `server/LatestAuditReportStore.java` (48 行)
- `server/handler/GetLatestAuditReportPageHandler.java` (33 行)

### 架构

```
GenerateAuditReportHandler (HTTP API)
  │
  ├── [analyze_first=true]
  │   ├── OneClickAnalyzer.analyzeProject()
  │   │   ├── DFAEngine.analyze()         → DFA 数据流分析
  │   │   └── SerializableChainFinder.findChains() → 利用链挖掘
  │   └── AuditReportBuilder.generate()
  │
  ├── [analyze_first=false]
  │   ├── 读取 OneClickAnalyzer.lastDfaFindings (volatile 缓存)
  │   └── AuditReportBuilder.generate()
  │
  └── 返回 { success, markdown, html, logs, dfa_count, gadget_count }
       │
       └── LatestAuditReportStore.update(html, markdown, targetName)
                │
                └── GET /report/latest → GetLatestAuditReportPageHandler
                                         返回缓存的 HTML
```

### LLMClient 实现

**协议**：OpenAI Chat Completions API 兼容格式。
```
POST {endpoint}
Authorization: Bearer {apiKey}
{
  "model": "{model}",
  "max_tokens": 4096,
  "temperature": 0.3,
  "messages": [
    { "role": "system", "content": "你是一位专业的 Java 安全审计专家..." },
    { "role": "user",   "content": "# jar-analyzer 静态分析结果摘要\n..." }
  ]
}
```

**安全措施**：
- API Key 通过 `JPasswordField`（GUI）或 `type="password"`（Web）收集，仅内存持有
- 日志只记录 endpoint 和 model，不记录 API Key 或请求体
- 响应解析失败时错误信息截断到 200 字符

**System Prompt**（70 行）：严格定义了 LLM 的输出格式——报告结构、风险评级标准、修复建议要求。

### AuditReportBuilder

数据聚合逻辑：将 DFA 发现（最多 30 条路径）、污点分析结果（最多 20 条）、反序列化利用链候选（最多 20 条）整合为结构化 Markdown 摘要。三类数据可以来自：
- `OneClickAnalyzer` 的实时分析结果（`analyzeFirst=true`）
- 全局 volatile 缓存（`OneClickAnalyzer.hasRun=true`）
- 已有的 DFS/污点结果（TaintCache）

### MarkdownReportRenderer

纯确定性的 Markdown → HTML 转换管线：
1. **CommonMark** 解析 Markdown（含 GFM 表格扩展 `TablesExtension`）
2. **标题遍历**（`collectHeadings`）— 遍历 AST 提取所有 H1-H4 标题节点
3. **ID 分配**（`assignHeadingIds`）— 中文标题 slugify 后分配唯一 ID，解决 ID 冲突
4. **严重程度提取**（正则 `\[严重|高危|高|中危|中|低危|低\]`）— 统计风险分布
5. **HTML 渲染**：自定义 `AttributeProvider` 为每个标题注入 `id` 属性
6. **页面组装**：120 行内联 CSS（CSS 变量 + 响应式 + 打印友好），侧边栏目录导航，5 张风险摘要卡片

输出是完全自包含的 HTML 文件，可直接保存交付。

### LatestAuditReportStore

进程内内存缓存：`volatile` 字段存储最新报告的 HTML/Markdown/目标名称/时间戳。`/report/latest` 端点读取缓存直接返回。`Cache-Control: no-store` 确保浏览器不缓存过期报告。

### 亮点

**LLM 只做写作，不做分析**：所有安全分析（DFA 污点追踪、DFS 调用链、利用链挖掘）都是确定性 Java 算法完成的。LLM 的角色是"安全写作专家"——将结构化的分析发现转化为人类可读的专业报告。这避免了 LLM 在代码分析中产生幻觉。

**厂商无关**：任何兼容 OpenAI Chat Completions API 的服务都可以用。用户可以选择 ChatGPT、DeepSeek、本地 Ollama——endpoint 字段填入对应 URL 即可。对于有代码隐私要求的场景，可用本地模型。

**自包含 HTML 报告**：报告文件中 CSS 全部内联，无外部依赖，可直接另存为 `.html` 文件交付给客户或归档。

**分析缓存复用**：`OneClickAnalyzer` 的分析结果通过 `volatile static` 字段全局共享。分析一次后，可以多次生成报告（调整 prompt、换模型、换 API Key），不需要反复运行 DFA 和利用链挖掘。

---

## 模块八：浏览器构建

前面已在模块三详述。补充说明：

**与 GUI 构建的关系**：`ProjectBuildManager.runBuild()` 最终调用的是 `CoreRunner.runBrowser()`——这是 `CoreRunner` 的一个专门入口，与 GUI 的"Start"按钮走同一套 ASM 解析 + MyBatis 写入管线，只是触发方式不同。

**构建进度来源**：`resolveProgress()` 除了自己维护的 `progress` 变量，还会从 GUI 的 `BuildBar.getValue()` 同步进度。这确保了如果用户同时打开了 GUI 客户端，构建进度在两端保持一致。

---

## 安全设计

### Token 认证
- 大小写兼容的 Header 检测（`Token` / `token`）
- 前端 localStorage 持久化，每次请求自动附加
- 不支持 Cookie/Session（无状态设计）

### API Key 保护
- Web 端：`type="password"` 输入框，不缓存到 localStorage
- Swing 端：`JPasswordField`，getText 后 char 数组即清
- 日志白名单：记录 endpoint/model，不记录 key/body

### 报告缓存
- `LatestAuditReportStore` 是进程内存缓存，重启后清空
- `/report/latest` 使用 `Cache-Control: no-store` 强制浏览器重新请求

---

## 关键指标

| 指标 | 数值 |
|------|------|
| 前端 JS 代码量 | ~1650 行 |
| 前端 CSS 代码量 | ~838 行 |
| HTTP API 端点 | 38 个 |
| Java 后端新增类 | 51 个文件 |
| 新增代码总量 | ~8,500 行 |
| 前端依赖 | 0（D3.js 由服务端提供） |
| 浏览器兼容 | 所有支持 Fetch API 的现代浏览器 |
