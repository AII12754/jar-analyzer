# Jar Analyzer 最终验收 PPT 大纲

> 目标：让老师快速看到成果完整、工作量充分、实现不简单、协作合理
> 建议页数：14 到 16 页
> 统计口径说明：代码量仅计算作者 AII12754 <aii1275438796@gmail.com> 的实际代码改动，且已排除 doc 目录与全部 Markdown 文档。

---

## 第 1 页：封面

### 标题

Jar Analyzer 功能增强与安全分析工作流重构

### 副标题

从静态检索工具到完整安全分析工作流

### 本页要讲的话

1. 项目基于开源 Java 安全审计工具 Jar Analyzer
2. 我们完成了两轮增强
3. 最终目标是提升发现、验证和交付能力

---

## 第 2 页：项目背景、问题与目标

### 页面内容

1. 原项目搜索深度不足
2. 结果噪音大，业务代码不易聚焦
3. 调用链和污点结果不够直观
4. 浏览器端缺乏完整工作流与交付能力

### 我们的目标

1. 更精准地定位危险方法
2. 更高效地验证漏洞链
3. 更完整地组织分析流程
4. 更正式地输出交付结果

---

## 第 3 页：小组成员与分工

### 页面内容


| 成员   | 分工                 |
| ------ | -------------------- |
| 成员 1 | 需求设计与项目统筹   |
| 成员 2 | 搜索表达式与结果治理 |
| 成员 3 | 可视化与前端交互     |
| 成员 4 | 后端接口与分析链路   |
| 成员 5 | 测试部署与文档交付   |

### 本页要讲的话

1. 采用按模块分工、按阶段整合的协作方式
2. 每位成员负责稳定模块，避免重复开发和冲突
3. 最终联调、测试、文档由全组共同完成

---

## 第 4 页：项目需求分析

### 页面内容

1. 原项目更偏工具功能堆叠，缺少完整分析流程
2. 难以直接回答哪里危险、为什么危险、如何交付
3. 我们把需求拆成发现、验证、交付三条主线

### 本页讲解重点

让老师先接受这个项目的改造目标不是小修补，而是系统增强。

---

## 第 5 页：总体设计与总体成果

### 页面内容

#### 第一轮：桌面端增强

1. 调用关系感知搜索
2. 正则搜索
3. 黑白名单过滤
4. CSV 导出
5. 多层交互式调用图
6. 污点传播可视化

#### 第二轮：浏览器工作台增强

1. 浏览器导入与索引建立
2. 安全巡航与入口资产概览
3. 内置漏洞排查与风险排序
4. 方法工作台联动
5. DFS 预设库
6. LLM 报告与独立报告页

---

## 第 6 页：第一轮核心增强 1

### 标题

搜索增强：从签名匹配到调用关系感知

### 页面内容

1. 新增 `containsInvoke` / `excludeInvoke`
2. 新增 `nameRegex` / `classNameRegex`
3. 新增 blacklist / whitelist 过滤
4. 新增 CSV 导出

### 最关键一句

> 这里的核心提升是：把这个方法像不像危险，升级成这个方法是否真的调用了危险 API。

---

## 第 7 页：第一轮核心增强 2

### 标题

可视化增强：把调用链和污点传播讲清楚

### 页面内容

1. HTML 多层交互式调用图
2. 支持节点展开、缩放、拖拽、详情展示
3. 污点传播 SVG 可视化
4. 区分 Source、传播节点、Sink

### 本页讲解重点

这不是截图美化，而是把分析结果变成可解释图形。

---

## 第 8 页：第二轮核心增强 1

### 标题

浏览器导入与安全巡航

### 页面内容

1. 浏览器中上传 JAR 或填写服务端路径
2. 调用后端建库流程并轮询状态
3. 新增安全巡航页
4. 汇总 Controllers、Servlets、Filters、Listeners、Spring 路由

### 最关键一句

> 我们把攻击面识别从几个分散接口，重构成了一个能直接驱动审计流程的浏览器页面。

---

## 第 9 页：第二轮核心增强 2

### 标题

内置漏洞排查：不是字符串搜索，而是调用关系回溯

### 页面内容

1. 内置高价值危险 Sink 模板
2. 通过 `method_call_table` 反查 caller
3. 风险分类展示：命令执行、JNDI、反序列化、SSRF、脚本执行等
4. 支持一键进入方法工作台或调用图

### 老师最想听的一句

> 字符串搜索解决像不像，调用关系回溯解决是不是，我们重点做的是后者。

---

## 第 10 页：第二轮核心增强 3

### 标题

方法联动、DFS 预设与报告交付

### 页面内容

1. 安全巡航页与方法工作台联动
2. 统一 selectedMethod 状态复用
3. DFS 预设库标准化常见风险参数
4. 独立报告页 `/report/latest`

### 本页讲解重点

这不是做几个孤立页面，而是把风险线索、验证步骤和交付结果串起来。

---

## 第 11 页：项目开发过程与协作安排

### 页面内容

#### 第一周：完成第一轮增强

1. 成员 1 负责需求拆解、任务切分和阶段联调安排
2. 成员 2 负责 containsInvoke / excludeInvoke、正则搜索、黑白名单过滤、CSV 导出
3. 成员 3 负责交互式调用图与污点传播可视化展示
4. 成员 4 负责调用图 / 污点图接口接入与联调
5. 成员 5 负责测试样本、测试用例、中期讲稿与阶段验收材料

#### 第三周：完成第二轮增强

1. 成员 1 负责浏览器工作流规划、模块集成与最终方案收口
2. 成员 2 负责方法工作台承接、风险线索跳转与结果组织
3. 成员 3 负责 dashboard 前端交互、安全巡航展示与 DFS 预设呈现
4. 成员 4 负责构建流程接口、安全巡航聚合、报告页路由与方法联动后端支撑
5. 成员 5 负责回归测试、部署验证、演示脚本与最终提交材料整理

### 本页讲解重点

把团队协作过程讲清楚，体现分工对应、阶段明确、推进有节奏。

---

## 第 12 页：技术深度证明

### 页面内容

1. 结构化数据库复用：
   - `method_call_table`
   - `spring_method_table`
   - `string_table`
2. 调用关系搜索与字符串搜索的本质区别
3. 前后端协同：
   - 前端 HTML/CSS/JS
   - 后端 Handler / API
   - 报告渲染与页面拆分
4. 可视化与验证链路并重

### 本页讲解重点

专门防止老师把项目理解为只是搜索功能增强。

---

## 第 13 页：测试、部署与完成度证明

### 页面内容

1. 已有测试：3 个测试类，29 个测试用例
2. 覆盖搜索、过滤、导出等核心逻辑
3. 浏览器工作台完成功能回归与链路验证
4. 构建部署：JDK 21 + Maven，主工程与样本均可独立打包运行
5. 第一轮纯代码统计：7 文件变更，964 行新增，3 行删除
6. 第二轮纯代码统计：52 文件变更，8792 行新增，212 行删除
7. 两轮合并纯代码统计：55 文件变更，9748 行新增，207 行删除
8. 统计已排除 doc 目录与全部 Markdown 文档

### 本页讲解重点

把测试充分、部署可用、工作量明确、成果完整一起讲清楚。

---

## 第 14 页：项目特色、问题与反思

### 页面内容

1. 项目特色：
   - 不是简单字符串匹配
   - 不是单点功能增强
   - 形成完整安全分析工作流
2. 过程问题：
   - 搜索深度不足
   - 可视化不直观
   - 浏览器端链路不完整
3. 对策：
   - 引入调用关系搜索
   - 补充图形化结果
   - 重构安全巡航与报告交付链路
4. 反思：
   - 工具增强不仅要有算法，还要有可用性和交付能力

---

## 第 15 页：总结与结束页

### 页面内容

1. 两轮增强，形成完整成果体系
2. 既有搜索和分析深度，也有浏览器工作流与交付能力
3. 既体现了技术实现，也体现了测试、部署和团队协作
4. 项目整体完成度高，适合课程验收与实际展示

### 结束语建议

> 我们最终做出来的不是几个分散的小功能，而是一套更完整的 Java 安全分析工作流。它既能更精准地发现风险，也能更高效地验证链路，还能直接形成交付结果。

---

## 附：答辩时建议反复强调的 5 句话

1. 我们不是只做字符串匹配，而是复用了调用关系数据库做结构化风险回溯。
2. 我们不是只做单点算法，而是把多个能力组织成完整工作流。
3. 我们不是只改桌面端，也不是只改前端，而是做了跨层联动增强。
4. 我们不仅能发现线索，还能继续验证链路并输出报告。
5. 从工作量和完成度上看，这已经明显超出普通课程作业式的小修小补。

---

## 附：PPT 制作时可直接截图的代码入口

### 第 6 页：搜索增强

1. [src/main/java/me/n1ar4/jar/analyzer/el/MethodEL.java](../src/main/java/me/n1ar4/jar/analyzer/el/MethodEL.java)
2. [src/main/java/me/n1ar4/jar/analyzer/el/MethodELProcessor.java](../src/main/java/me/n1ar4/jar/analyzer/el/MethodELProcessor.java)
3. [src/main/java/me/n1ar4/jar/analyzer/exporter/SearchResultCsvExporter.java](../src/main/java/me/n1ar4/jar/analyzer/exporter/SearchResultCsvExporter.java)
4. [src/main/java/me/n1ar4/jar/analyzer/gui/MainForm.java](../src/main/java/me/n1ar4/jar/analyzer/gui/MainForm.java)

### 第 7 页：调用图与污点图可视化

1. [src/main/java/me/n1ar4/jar/analyzer/graph/HtmlGraphUtil.java](../src/main/java/me/n1ar4/jar/analyzer/graph/HtmlGraphUtil.java)
2. [src/main/java/me/n1ar4/jar/analyzer/graph/RenderEngine.java](../src/main/java/me/n1ar4/jar/analyzer/graph/RenderEngine.java)
3. [src/main/java/me/n1ar4/jar/analyzer/graph/TaintGraphRenderEngine.java](../src/main/java/me/n1ar4/jar/analyzer/graph/TaintGraphRenderEngine.java)
4. [src/main/java/me/n1ar4/jar/analyzer/server/handler/TaintGraphHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/TaintGraphHandler.java)

### 第 8 页：浏览器导入与安全巡航入口

1. [src/main/java/me/n1ar4/jar/analyzer/server/handler/StartProjectBuildHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/StartProjectBuildHandler.java)
2. [src/main/java/me/n1ar4/jar/analyzer/server/handler/GetBuildStatusHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/GetBuildStatusHandler.java)
3. [src/main/java/me/n1ar4/jar/analyzer/server/PathMatcher.java](../src/main/java/me/n1ar4/jar/analyzer/server/PathMatcher.java)
4. [src/main/resources/index.html](../src/main/resources/index.html)
5. [src/main/resources/server/dashboard.js](../src/main/resources/server/dashboard.js)

### 第 9 页：内置漏洞排查与风险排序

1. [src/main/java/me/n1ar4/jar/analyzer/server/handler/GetSecurityOverviewHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/GetSecurityOverviewHandler.java)
2. [src/main/java/me/n1ar4/jar/analyzer/server/PathMatcher.java](../src/main/java/me/n1ar4/jar/analyzer/server/PathMatcher.java)
3. [src/main/resources/server/dashboard.js](../src/main/resources/server/dashboard.js)
4. [src/main/resources/server/dashboard.css](../src/main/resources/server/dashboard.css)

### 第 10 页：方法联动、DFS 预设与报告交付

1. [src/main/resources/server/dashboard.js](../src/main/resources/server/dashboard.js)
2. [src/main/java/me/n1ar4/jar/analyzer/server/handler/GenerateAuditReportHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/GenerateAuditReportHandler.java)
3. [src/main/java/me/n1ar4/jar/analyzer/server/LatestAuditReportStore.java](../src/main/java/me/n1ar4/jar/analyzer/server/LatestAuditReportStore.java)
4. [src/main/java/m1e/n1ar4/jar/analyzer/server/handler/GetLatestAuditReportPageHandler.java](../src/main/java/me/n1ar4/jar/analyzer/server/handler/GetLatestAuditReportPageHandler.java)
5. [src/main/java/me/n1ar4/jar/analyzer/report/MarkdownReportRenderer.java](../src/main/java/me/n1ar4/jar/analyzer/report/MarkdownReportRenderer.java)

### 第 12 页：技术深度证明

1. [src/main/java/me/n1ar4/jar/analyzer/core/BytecodeCallGraph.java](../src/main/java/me/n1ar4/jar/analyzer/core/BytecodeCallGraph.java)
2. [src/main/java/me/n1ar4/jar/analyzer/taint/dfa/DFAEngine.java](../src/main/java/me/n1ar4/jar/analyzer/taint/dfa/DFAEngine.java)
3. [src/main/java/me/n1ar4/jar/analyzer/server/ProjectBuildManager.java](../src/main/java/me/n1ar4/jar/analyzer/server/ProjectBuildManager.java)
4. [src/main/java/me/n1ar4/jar/analyzer/report/ReportPanel.java](../src/main/java/me/n1ar4/jar/analyzer/report/ReportPanel.java)
