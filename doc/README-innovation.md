# jar-analyzer 创新功能说明文档

> 版本：v5.19+
> 新增功能：反序列化利用链自动挖掘（A）、过程间数据流分析 DFA（B）、LLM 智能审计报告（D）

这份文档不仅说明“怎么用”，也重点回答两个更适合答辩/演示的问题：

1. 这几个功能在工程上到底是怎么做出来的
2. 它们相比原有能力，为什么具有明确的研究意义和实际价值

---

## 样本适配说明（先看这个）

当前仓库已经提供统一的 A/B 演示样本：

- `test/innovation-demo/target/innovation-demo-0.0.1-SNAPSHOT.jar`

该样本专门为两个新增功能设计：

1. **功能 A（反序列化利用链自动挖掘）**

   - 包含 `ExecPayload` 这类**通过父类继承获得 Serializable 能力**的类
   - 包含 `readObject`、`readResolve`、`compareTo`、`hashCode`、`toString` 多种触发入口
   - 触发路径最终到达 `Runtime.exec`
2. **功能 B（过程间 DFA）**

   - 包含 Spring MVC 入口 `DemoCommandController.exec(@RequestParam String cmd)`
   - 参数经 `Facade -> Service -> Runtime.exec` 形成完整 Web Source → Sink 调用链
3. **结论**

   - 若要稳定演示 A 和 B，优先使用 `innovation-demo`
   - `springboot-test` 仍然可以作为 B 的备选样本
   - `test` 目录里其他样本不适合同时覆盖 A/B

### test 目录现成样本结论

当前仓库 `test/` 目录下的现成样本，适配情况如下：


| 样本                            | 是否适合 A | 是否适合 B | 说明                                                                                     |
| ------------------------------- | ---------- | ---------- | ---------------------------------------------------------------------------------------- |
| `test/innovation-demo`          | **是**     | **是**     | 统一演示样本，内置 Serializable Trigger →`Runtime.exec` 与 Spring MVC → `Runtime.exec` |
| `test/springboot-test`          | 否         | **是**     | 含 Spring MVC → Service →`Runtime.exec` 调用链，适合演示 B                             |
| `test/springboot-undertow`      | 否         | 一般       | 有 Spring MVC 入口，但未内置明显危险 Sink，不适合稳定演示漏洞命中                        |
| `test/leak-test`                | 否         | 否         | 主要用于信息泄露相关测试，不适合 A/B                                                     |
| `test/serialization-data/1.ser` | 否         | 否         | 这是序列化数据样本，不是可供 A 直接加载分析的 JAR                                        |

结论：

- **`innovation-demo` 可以直接同时演示 A 和 B**
- **`springboot-test` 仍可作为 B 的备选演示样本**

### 统一演示方法（推荐）

推荐使用统一样本：`test/innovation-demo/target/innovation-demo-0.0.1-SNAPSHOT.jar`

该样本中包含两条核心链路：

B 功能链路：

`DemoCommandController.exec(String cmd)`
→ `DemoCommandFacade.dispatch(cmd)`
→ `DemoCommandService.execute(cmd)`
→ `DemoCommandService.doInternal(cmd)`
→ `Runtime.getRuntime().exec(cmd)`

A 功能链路：

`ExecPayload.readObject(ObjectInputStream)`
→ `BaseSerializablePayload.triggerSink(command)`
→ `SerializableCommandBridge.stageOne(command)`
→ `SerializableCommandBridge.stageTwo(command)`
→ `Runtime.getRuntime().exec(command)`

#### 操作步骤

1. 在项目根目录执行：
   `mvn clean package -DskipTests`
2. 进入 `test/innovation-demo` 目录执行：
   `mvn clean package -DskipTests`
3. 启动 jar-analyzer GUI，加载：
   `test/innovation-demo/target/innovation-demo-0.0.1-SNAPSHOT.jar`
4. 等待主界面分析完成
5. 先演示 **A 功能**：切换到 `gadget` 面板，点击 `自动利用链挖掘（实验性）`
6. 点击 `开始挖掘`
7. 预期重点关注以下 Trigger / Sink：

- `me.n1ar4.demo.innovation.serialization.ExecPayload#readObject`
- `me.n1ar4.demo.innovation.serialization.ExecPayload#readResolve`
- `me.n1ar4.demo.innovation.serialization.ExecPayload#compareTo`
- Sink 为 `Runtime.exec`

8. 再演示 **B 功能**：切换到 `chains` 面板，点击 `过程间数据流分析（DFA）`
9. 点击 `开始 DFA 分析`
10. 预期重点关注以下路径：

- `me.n1ar4.demo.innovation.web.DemoCommandController#exec`
- `me.n1ar4.demo.innovation.web.DemoCommandService#doInternal`
- Sink 为 `Runtime.exec`

#### 演示话术

可以这样介绍：

> 这个统一样本同时覆盖了两种现实场景：一类是反序列化入口触发危险调用，另一类是 Spring MVC 请求参数一路流向命令执行。A 用来展示利用链挖掘的结构化发现能力，B 用来展示 Web 入口到危险 Sink 的自动数据流分析能力。两个结果都落到 `Runtime.exec`，便于现场解释和对照。

### 备选样本说明

如果统一样本临时不可用，仍可使用以下备选：

- `springboot-test`：适合 B，不适合 A
- `springboot-undertow`：只适合展示 Spring MVC 入口识别，不适合稳定命中 Sink
- `serialization-data/1.ser`：只是序列化数据，不是 A 所需的 JAR 样本

统一样本 `innovation-demo` 已满足 A 所需的三个关键要素：

1. 某个类直接或间接实现 `Serializable`
2. 类中存在 `readObject` / `readResolve` / `hashCode` / `compareTo` 这类触发方法
3. 触发方法经调用链能到达 `Runtime.exec` / `Method.invoke` / `Context.lookup` 等 Sink

当前版本已增强 A 的触发类识别能力：不仅支持**直接实现** `Serializable` 的类，也支持**通过父类/接口继承获得 Serializable 能力**的类，这比初版更适合真实业务代码。

---

## 功能 A：反序列化利用链自动挖掘

### 功能介绍

基于 JAR 文件的调用图，自动搜索从 `Serializable` 类的触发入口（如 `readObject`、`hashCode` 等）到危险 Sink 方法（如 `Runtime.exec`、`JNDI.lookup` 等）的调用路径，辅助挖掘 Java 反序列化利用链（类似 ysoserial gadget chain）。

**入口位置**：gadget 面板 → 「自动利用链挖掘（实验性）」按钮

### 技术原理

#### 触发点（Trigger）收集

扫描 `jar-analyzer-temp/` 目录中的所有 `.class` 文件，使用 ASM `ClassReader` 检测：

- 类是否**直接或通过父类/接口间接**实现 `java.io.Serializable` 接口
- 是否包含以下触发方法：


| 方法名             | 触发时机                         |
| ------------------ | -------------------------------- |
| `readObject`       | 反序列化时自动调用               |
| `readResolve`      | 反序列化后替换对象               |
| `readObjectNoData` | 类缺失时调用                     |
| `finalize`         | 对象被 GC 时调用                 |
| `hashCode`         | 放入 HashMap/HashSet 时触发      |
| `equals`           | 比较操作触发                     |
| `compareTo`        | 排序操作触发（PriorityQueue 等） |
| `toString`         | 字符串转换触发                   |

#### 危险 Sink 定义


| Sink                           | 危险类型            |
| ------------------------------ | ------------------- |
| `Runtime.exec`                 | RCE（任意命令执行） |
| `ProcessBuilder.start`         | RCE（进程创建）     |
| `Context.lookup`               | JNDI 注入           |
| `ObjectInputStream.readObject` | 嵌套反序列化链      |
| `Method.invoke`                | 反射调用            |
| `ClassLoader.loadClass`        | 类加载滥用          |
| `FileOutputStream.<init>`      | 任意文件写入        |
| `ScriptEngine.eval`            | 脚本注入            |

#### 搜索算法

采用**深度优先搜索（DFS）**在方法调用图上搜索：

```
Trigger（如 hashCode） 
  → A.method1() 
    → B.method2() 
      → Runtime.exec()  ← SINK 命中！
```

- 最大搜索深度：12 层
- 每个 Trigger × Sink 组合最多返回 5 条路径
- 全局最多返回 50 条候选链
- 使用已访问集合（visited set）避免环路

#### 算法保守性（类层次分析）

接口/抽象类方法调用时，查询数据库获取实际调用目标。分析的 soundness（不漏报）优先于 precision（精度），可能存在误报（false positive），需人工验证。

### 实现拆解

从实现角度看，功能 A 不是“简单搜关键字”，而是一个由 4 个步骤组成的链式分析器：

1. **候选类发现**

- 扫描 `jar-analyzer-temp/` 目录中的字节码
- 建立类继承信息，识别哪些类直接或间接具备 `Serializable` 能力
- 这一点很关键，因为真实项目里很多危险类不是直接 `implements Serializable`，而是从父类继承得到可序列化能力

2. **Trigger 抽取**

- 从候选类的方法表中识别 `readObject`、`readResolve`、`compareTo`、`hashCode` 等典型触发入口
- 这些方法不是随便选的，而是来源于 Java 反序列化和集合触发语义，能对应到现实中的利用触发面

3. **调用图搜索**

- 先使用数据库中的 `method_call_table` 进行图搜索
- 如果数据库调用图为空或不完整，则退化到直接基于 `jar-analyzer-temp` 的字节码调用图构建结果
- 这样做的意义是：功能 A 不再被单一持久化层绑定，演示和生产场景都更稳定

4. **继承/声明归一化**

- 在实际修复中，额外补上了“沿继承链解析真实声明方法”的逻辑
- 例如 `ExecPayload` 调用继承自父类的 `triggerSink`，如果只看当前类 owner，会导致路径中途断掉；归一化后才能走到 `SerializableCommandBridge` 与最终的 `Runtime.exec`

### 结合 innovation-demo 的实际命中讲解

当前统一样本中，A 功能最适合现场讲解的一条链可以概括为：

`ExecPayload.readObject(ObjectInputStream)`
→ `BaseSerializablePayload.triggerSink(String)`
→ `SerializableCommandBridge.stageOne(String)`
→ `SerializableCommandBridge.stageTwo(String)`
→ `CommandExecSupport.exec(String)`
→ `Runtime.exec(String)`

这条链适合演示的原因是：

- 它同时覆盖了**继承 Serializable**、**多触发方法**、**跨类调用传播**、**最终落到 RCE Sink** 这四个点
- 它能清楚说明“自动利用链挖掘”不是只看某一个危险方法，而是从可触发入口一直向后搜索到危险行为

### 意义与价值

#### 研究意义

- 它把传统依赖人工经验的 gadget 排查，转成了“可批量跑”的静态链挖掘问题
- 它证明了 jar-analyzer 不只是查询工具，而是在向“自动漏洞发现引擎”演进
- 它覆盖的不是单点漏洞，而是“触发条件 + 调用链 + 危险行为”三段式结构，这比单纯搜 `Runtime.exec` 更接近真实利用分析

#### 工程价值

- 适合批量筛选疑似反序列化利用类，帮助审计人员缩小排查范围
- 适合在引入大量第三方组件、历史代码复杂、缺少源码上下文时做首轮风险发现
- 适合把候选链进一步交给 chains 面板或人工分析做二次验证，形成“自动初筛 + 人工确认”的工作流

#### 答辩/演示价值

如果需要给老师或评审解释这项能力，可以概括为：

> A 功能解决的是“系统自动帮我从一堆可序列化类里，找到哪些类可能在反序列化或容器触发时一路调用到危险操作”。它展示的是从字节码、继承关系、调用图到漏洞链结果的完整闭环，而不是单个规则命中。

### 使用步骤

1. 在主界面的 **start** 面板加载 `test/innovation-demo/target/innovation-demo-0.0.1-SNAPSHOT.jar` 并完成分析（等待进度条完成）
2. 切换到 **gadget** 面板
3. 点击「**自动利用链挖掘（实验性）**」按钮
4. 在弹出的对话框中点击「**开始挖掘**」
5. 等待扫描完成（耗时取决于 JAR 大小，通常 10-60 秒）
6. 在结果表格中查看候选链
7. 点击任意行，在下方详情区查看完整调用路径
8. 推荐重点展示 `ExecPayload#readObject`、`ExecPayload#readResolve`、`ExecPayload#compareTo` 到 `Runtime.exec` 的链

### 演示效果

```
发现候选链：
┌────┬──────────────────┬─────────────┬──────────────────┬────┬─────────────────────────────────────┐
│ #  │ 触发类           │ 触发方法    │ 危险类型         │ 深 │ 调用链摘要                          │
├────┼──────────────────┼─────────────┼──────────────────┼────┼─────────────────────────────────────┤
│  1 │ BadHashMap       │ readObject  │ RCE via Runtime  │  4 │ BadHashMap#readObject → ... → exec  │
│  2 │ EvilComparator   │ compareTo   │ JNDI Injection   │  3 │ EvilComparator#compareTo → lookup   │
└────┴──────────────────┴─────────────┴──────────────────┴────┴─────────────────────────────────────┘
```

---

## 功能 B：过程间数据流分析（Interprocedural DFA）

### 功能介绍

基于**方法摘要（Method Summary）+ Worklist 算法**的过程间污点分析，自动从 HTTP 请求参数（Source）追踪数据流到危险操作（Sink），发现 SQL 注入、SSRF、路径穿越等漏洞。

相比现有的 DFS + 污点分析（沿给定链路逐步验证），DFA 是**主动分析**：无需用户指定 Source/Sink，由引擎自动遍历整个代码库寻找污点路径。

**入口位置**：chains 面板 → 「过程间数据流分析（DFA）」按钮

### 技术原理

#### 格理论基础（Lattice Theory）

对每个局部变量 slot 使用**二值格（Two-valued Lattice）**：

```
    TAINTED  (⊤)   ← 被用户数据污染
        |
    CLEAN    (⊥)   ← 未被污染
```

合并操作（join，用于控制流汇合点）：`TAINTED ⊔ CLEAN = TAINTED`

这保证了**保守性（soundness）**：只要数据可能被污染，就视为污染。

#### 两阶段分析

**第一阶段：过程内分析（Intra-Procedural）**

`DFAIntraAnalyzer` 对每个方法的字节码进行模拟执行：

1. 对每个参数 `p`，假设 `p` 被污染，其他参数干净
2. 模拟 `LOAD`、`STORE`、`DUP`、`INVOKE*` 等指令的污点传播
3. 检查 `XRETURN` 指令时栈顶是否为污染值
4. 若参数 `p` → 返回值被污染，记录到 `MethodSummary.paramToReturn`

结果：每个方法对应一个 `MethodSummary`，描述其"污点传播规则"。

**第二阶段：过程间分析（Inter-Procedural）**

`DFAEngine` 运行 Worklist 算法：

```
初始化：
  对所有 source 方法（如 HttpServletRequest.getParameter 或 Spring MVC Controller 参数入口），
  设置 isAlwaysTainted = true，将其调用者加入 worklist

Worklist 迭代：
  while worklist 非空:
    取出 (method, taintedSlots, path)
    if method 是 sink → 记录发现
    else:
      查询 method 的所有 callee
      for each callee:
        使用 MethodSummary 计算传播结果
        if 污点有变化:
          worklist.add(callee, newTaint, path + callee)
```

#### 内置 Source 和 Sink

**Source（污点来源）**：


| Source                                       | 描述                    |
| -------------------------------------------- | ----------------------- |
| `HttpServletRequest.getParameter`            | URL 查询参数            |
| `HttpServletRequest.getHeader`               | HTTP 请求头             |
| `HttpServletRequest.getInputStream`          | 请求体                  |
| `HttpServletRequest.getQueryString`          | 查询字符串              |
| `Part.getInputStream`                        | 文件上传                |
| `Cookie.getValue`                            | Cookie 值               |
| `HttpServletRequest.getPathInfo`             | URL 路径段              |
| `@RequestParam` / Spring MVC Controller 参数 | Spring Web 请求绑定参数 |

**Sink（危险操作）**：


| Sink                                       | 漏洞类型     |
| ------------------------------------------ | ------------ |
| `Statement.execute/executeQuery`           | SQL 注入     |
| `Context.lookup` / `InitialContext.lookup` | JNDI 注入    |
| `Runtime.exec` / `ProcessBuilder.start`    | 远程命令执行 |
| `FileInputStream.<init>` / `Paths.get`     | 路径穿越     |
| `URL.<init>` / `URL.openConnection`        | SSRF         |
| `HttpServletResponse.getWriter`            | 潜在 XSS     |
| `ScriptEngine.eval`                        | 脚本注入     |
| `ObjectInputStream.readObject`             | 反序列化     |

#### 精度说明

- **Flow-insensitive**：不区分程序语句的执行顺序（保守）
- **Context-insensitive**：不区分调用上下文（同一方法多处调用共享摘要）
- **保守近似**：宁可误报（false positive）也不漏报（false negative）

实际使用时建议结合 chains 面板的污点分析进行二次验证。

### 实现拆解

功能 B 的实现比传统“给定 Source/Sink 再做 DFS”更进一步，它实际上是把问题拆成了两个子问题：

1. **每个方法本身怎么传播污点**
2. **这些方法连接起来以后，污点怎么跨方法扩散**

对应到工程实现，就是两个模块：

#### 1. `DFAIntraAnalyzer` 负责过程内摘要构建

- 逐个扫描 `jar-analyzer-temp` 中的方法字节码
- 对每个参数做一次“假设它被污染”的模拟执行
- 记录它是否会污染返回值，或者继续影响后续调用
- 最终把每个方法浓缩成一个 `MethodSummary`

它的价值在于：不需要每次全量重新解释所有字节码，可以先把每个方法的“传播规律”缓存下来，再在图上做传播。

#### 2. `DFAEngine` 负责过程间传播

- 把 Source 方法放进 worklist
- 沿调用图查找 callee
- 结合 `MethodSummary` 计算污点是否继续传播
- 一旦触达内置 Sink，就记录漏洞路径

这里本轮修复过几个关键工程点：

- 增加了 **Spring MVC Controller 参数** 作为 Source，而不再只识别传统 Servlet API
- 修复了 **返回值/参数污点在跨方法传播时被丢失** 的问题
- 修复了 **数据库类名使用 `/`，而字节码摘要使用 `.` 导致匹配失败** 的问题
- 补充了 **调用图数据库与字节码调用图的双通路并集**，避免单一数据源出问题时 DFA 全部失效
- 增加了 **直接命中 Sink callee 时立即记录发现** 的逻辑，避免路径只差最后一跳却不出结果

### 结合 innovation-demo 的实际命中讲解

当前样本已经稳定命中的路径如下：

`DemoCommandController.exec(String)`
→ `DemoCommandFacade.dispatch(String)`
→ `DemoCommandService.execute(String)`
→ `DemoCommandService.doInternal(String)`
→ `CommandExecSupport.exec(String)`
→ `Runtime.exec(String)`

这条路径非常适合讲解 B 的核心价值，因为它同时体现了：

- Source 不是 `HttpServletRequest.getParameter` 这种底层 API，而是 **Spring MVC 参数绑定后的控制器方法参数**
- 污点不是停留在单个方法里，而是跨越 Controller、Facade、Service、工具类多跳传播
- 结果不是单纯“搜到了 `Runtime.exec`”，而是给出了完整的 Source → Sink 传播路径和修复建议

### 与现有 DFS + 污点验证的区别

原有 chains 面板更像是“给定入口后验证这条链能不能通”。

功能 B 的定位则是：

- **自动发现入口**
- **自动发现 Sink**
- **自动尝试把入口和 Sink 接起来**

因此它更像一个“主动型发现器”，而 chains 面板更像“精确型验证器”。两者不是替代关系，而是前后衔接关系。

### 意义与价值

#### 研究意义

- 说明 jar-analyzer 已经从“方法查询工具”升级为“能做过程间程序分析的静态分析平台”
- 展示了方法摘要、工作队列传播、保守近似等程序分析核心思想在真实工程中的落地
- 支持 Spring MVC 这类现代 Java Web 编程模型，说明模型不是停留在老式 Servlet 时代

#### 工程价值

- 适合对业务 JAR、微服务 JAR、网关插件、SDK 包做首轮 Web 风险筛查
- 能帮助快速发现“参数一路传到危险执行点”的路径，特别适合排查命令执行、SQL 注入、SSRF、文件操作等问题
- 能把发现结果直接交给人工复核、DFS 精确链分析或 LLM 报告模块，形成流水线

#### 答辩/演示价值

可以这样讲：

> B 功能解决的是“系统自己从 Web 入口出发，主动在整个代码库里搜索能否一路流到危险操作”。它不要求用户先手工指定链路，而是自动在跨类、跨层次的调用关系里传播污点，这代表工具具备了更强的程序分析能力。

### 使用步骤

1. 加载 `test/innovation-demo/target/innovation-demo-0.0.1-SNAPSHOT.jar` 并等待主界面分析完成
2. 切换到 **chains** 面板
3. 点击「**过程间数据流分析（DFA）**」按钮
4. 在弹出对话框中点击「**开始 DFA 分析**」
5. 等待两阶段分析完成（`过程内分析` → `Worklist 传播`），观察左侧日志
6. 在结果表格中重点关注 `DemoCommandController#exec → DemoCommandFacade#dispatch → DemoCommandService#execute → DemoCommandService#doInternal → CommandExecSupport#exec → Runtime.exec` 相关路径
7. 点击行查看完整路径和修复建议

### 演示效果

```
分析日志：
  第一阶段：过程内字节码分析，构建方法摘要...
  方法摘要构建完成，共 12847 个
  第二阶段：过程间污点传播（Worklist 算法）...
  分析完成，共发现 23 个潜在漏洞路径

结果示例：
┌─────────────────────┬────────────────────┬──────────────┬──────────────────────────────────────────┐
│ 漏洞类型            │ Source 方法         │ Sink 方法    │ 路径摘要                                  │
├─────────────────────┼────────────────────┼──────────────┼──────────────────────────────────────────┤
│ SQL Injection       │ getParameter       │ execute      │ getParameter → queryUser → execute       │
│ SSRF                │ getHeader          │ openConn     │ getHeader → makeRequest → openConnection │
└─────────────────────┴────────────────────┴──────────────┴──────────────────────────────────────────┘
```

---

## 功能 D：LLM 智能安全审计报告

### 功能介绍

将 jar-analyzer 现有所有分析模块的结果（DFS 漏洞链、污点分析、DFA 数据流分析、反序列化利用链）汇聚成结构化的安全发现摘要，通过 OpenAI 兼容 API 调用大语言模型（LLM），自动生成专业的安全审计报告。当前版本不再停留在“输出一段 Markdown 文本”，而是增加了报告页内的网页化预览、目录导航、严重级别高亮卡片、HTML 导出以及浏览器预览能力。

**入口位置**：chains 面板 → 「LLM 智能审计报告」按钮

进入报告页后，既可以直接点击「生成审计报告」消费当前缓存结果，也可以点击「★ 一键分析整个项目并生成报告」，让系统在当前页内自动执行 DFA、反序列化利用链挖掘并最终生成网页化报告。

### 技术原理

#### 数据聚合

`AuditReportBuilder` 从以下来源收集数据：


| 数据来源           | 描述                                |
| ------------------ | ----------------------------------- |
| `TaintCache.cache` | chains 面板 DFS + 污点分析结果      |
| `DFAEngine` 结果   | 过程间 DFA 分析路径（需先运行 DFA） |
| 利用链候选列表     | 反序列化挖掘结果（需先运行挖掘）    |

#### Prompt 设计

使用 System Prompt 定义 LLM 角色和输出格式：

```
你是一位专业的 Java 安全审计专家...
请生成包含以下结构的报告：
# 执行摘要
## 发现的安全问题（按严重程度排序）
### [严重/高/中/低] 漏洞名称
- 技术分析
- 受影响代码路径
- 修复建议
## 总体安全评分
## 修复优先级建议
```

User Message 包含所有结构化安全发现（限制总长度防止 token 超限）。

#### HTTP 客户端（LLMClient）

- 使用项目已有的 OkHttp3 依赖，额外创建独立超时配置（默认 120s）
- 支持 OpenAI Chat Completions API 格式（`POST /v1/chat/completions`）
- 请求/响应使用 Fastjson2 序列化

#### 网页化预览层

当前版本在报告展示层新增了一个 Markdown → HTML 的网页化渲染步骤：

- 使用 CommonMark 解析 LLM 返回的 Markdown 报告
- 支持 GFM 表格渲染，避免 Markdown 表格在 GUI 中退化成纯文本
- 自动为标题生成目录导航
- 自动从报告中的严重级别标签中提取统计信息，生成“严重 / 高危 / 中危 / 低危”高亮卡片
- 在面板中提供“网页预览 / Markdown 源文”双视图
- 支持直接导出 `.html` 文件，或一键交给系统浏览器打开

这一步的意义是把“模型输出的文本”升级成“可以直接展示、截图、导出和交付的网页报告”。

#### 安全特性

- **API Key 零持久化**：仅在内存中持有，不写入磁盘、不记录到日志
- **HTTPS 强制建议**：Endpoint 应使用 HTTPS（OkHttp3 本身支持 TLS）
- **无供应商绑定**：支持任何兼容 OpenAI API 的服务

### 实现拆解

功能 D 的重点不在“接一个大模型接口”，而在于它把前面多个分析模块的结果组织成了可交付的安全报告流程。

#### 1. 结果汇聚

`AuditReportBuilder` 并不是简单拼字符串，而是把不同来源的发现先转换为统一的安全发现摘要：

- DFS + 污点验证结果负责提供“已知链路的精确确认”
- DFA 结果负责提供“自动发现的 Source → Sink 风险路径”
- 利用链挖掘结果负责提供“反序列化类的候选利用路径”

这样汇总后，LLM 处理的输入已经是结构化信息，而不是原始日志堆砌。

#### 2. Prompt 约束

文档里的 Prompt 设计其实体现的是一个重要工程点：

- 先限定模型角色为 Java 安全审计专家
- 再限定输出结构为执行摘要、问题分级、影响路径、修复建议、总体评分
- 最后把真实路径数据塞进去

这能显著减少“模型自由发挥”的不稳定性，让输出更像正式交付文档，而不是聊天回答。

#### 3. 人机协作定位

这个模块本质上不是替代审计人员，而是把：

- 结构化分析结果
- 漏洞类型判断
- 修复建议模板
- 报告语言组织

这几个耗时但重复度高的动作交给模型完成，从而缩短从“发现问题”到“形成报告”的时间。

#### 4. 当前页一键分析与报告联动

这次实现里还把原来分离的两个动作合并到了同一页：

- 以前是“先单独跑一键分析，再弹出报告页”
- 现在是“直接在报告页里点击大按钮，在当前页完成整项目分析并生成报告”

这样做的好处是：

- 入口更统一，老师或用户更容易理解完整工作流
- 左侧控制台可以实时展示 DFA、利用链挖掘、LLM 调用三个阶段的进度
- 右侧网页预览会在报告生成完成后直接刷新，不需要再切换窗口

### 意义与价值

#### 研究意义

- 说明项目不只是做静态分析，还尝试把静态分析结果转化为“可读、可汇报、可交付”的知识产品
- 展示了传统程序分析工具与 LLM 协作的具体结合点：不是让模型直接替代分析，而是让模型消费分析结果

#### 工程价值

- 适合甲方内部安全巡检后的报告生成
- 适合乙方审计项目中快速形成初稿，再由人工修订
- 适合把多模块结果统一成一份 Markdown 报告，降低沟通和交付成本
- 适合直接导出为网页报告用于演示、内部汇报和项目交付
- 适合把“整项目分析 + 最终报告”压缩到一个页面操作完成，降低使用门槛

#### 答辩/演示价值

可以这样讲：

> D 功能解决的是“发现结果很多，但人工整理报告很慢”的问题。它把前面 A、B 以及已有 chains 分析的结果统一收敛，再由 LLM 生成结构化审计报告，体现的是从分析引擎到交付产物的完整闭环能力。

如果要补充现在的新亮点，可以再加一句：

> 当前版本已经把报告页做成了一个网页化工作台，支持在同一页里直接一键分析整个项目并生成最终报告，更接近真实产品形态。

### 适合展示给老师的亮点

如果需要突出“看起来很厉害但又讲得明白”，功能 D 的亮点可以总结为：

- 它不是单独的 AI 聊天窗口，而是建立在已有分析结果之上的**结果编排层**
- 它体现的是**静态分析 + 结构化摘要 + 大模型生成**三层组合
- 它让项目从“能分析”进一步走到“能形成专业输出”

### 使用步骤

1. 切换到 **chains** 面板，点击「**LLM 智能审计报告**」
2. 填写 LLM 配置：

   - **API Endpoint**：OpenAI 格式的接口地址
     - OpenAI 官方：`https://api.openai.com/v1/chat/completions`
     - Azure OpenAI：`https://<resource>.openai.azure.com/openai/deployments/<dep>/chat/completions?api-version=2024-02-01`
     - 本地 Ollama：`http://localhost:11434/v1/chat/completions`
     - DeepSeek：`https://api.deepseek.com/v1/chat/completions`
   - **API Key**：对应服务的 API Key
   - **模型名称**：如 `gpt-4o`、`gpt-4o-mini`、`deepseek-chat`、`llama3.1` 等
3. 推荐直接点击「**★ 一键分析整个项目并生成报告**」

   - 系统会在当前页内依次执行：DFA → 反序列化利用链挖掘 → LLM 报告生成
   - 左侧控制台显示分析日志
   - 右侧网页预览会在报告生成后自动刷新
4. 如果你已经提前跑过 DFA 或利用链挖掘，也可以直接点击「**生成审计报告**」复用当前缓存结果
5. 报告生成后：

   - 点击「导出 .md 文件」保存 Markdown 源文
   - 点击「导出 .html 文件」生成可交付网页报告
   - 点击「浏览器预览」在系统浏览器中打开完整 HTML 报告
   - 点击「复制到剪贴板」复制 Markdown 内容

#### 本地 vLLM 示例

- **API Endpoint**：`http://localhost:8111/v1/chat/completions`
- **模型目录**：`/root/share/models/Qwen2.5-14B-Instruct`
- **启动命令**：`CUDA_VISIBLE_DEVICES=5 vllm serve /root/share/models/Qwen2.5-14B-Instruct --port 8111`
- ssh -NL 8111:127.0.0.1:8111 spl@211.81.55.182 -p 1194
- CUDA_VISIBLE_DEVICES=5 vllm serve /root/share/models/Qwen2.5-14B-Instruct --port 8111
- http://localhost:8111/v1/chat/completions
- /root/share/models/Qwen2.5-14B-Instruct

如果本地服务不校验密钥，`API Key` 可以填写一个占位值；模型名称则应填写服务端实际加载的模型名。

### 报告示例结构

```markdown
# Java 安全审计报告

## 执行摘要
本次分析共发现 15 个安全问题，其中严重 3 个、高危 5 个...

## 发现的安全问题

### [严重] SQL 注入 - UserController#queryUser
**技术分析**：
用户输入直接拼接到 SQL 语句，攻击者可构造恶意输入...

**受影响路径**：
`HttpServletRequest#getParameter → UserController#queryUser → Statement#execute`

**修复建议**：
使用 PreparedStatement 替代字符串拼接：
```java
// 不安全
String sql = "SELECT * FROM users WHERE id=" + userId;
// 安全
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
ps.setString(1, userId);
```

### [高危] JNDI 注入 - ...

## 总体安全评分：35/100（需要立即修复）

## 修复优先级建议

1. 立即修复所有 SQL 注入漏洞（影响数据/系统完整性）
2. 修复 JNDI 注入风险（可导致 RCE）
3. ...

```





---

## 各功能对比总结

| 特性 | 功能 A（利用链挖掘）| 功能 B（过程间 DFA）| 功能 D（LLM 报告）|
|------|---------------------|---------------------|-------------------|
| 分析对象 | 反序列化利用链 | 通用污点传播 | 综合分析结果 |
| 需要网络 | 否 | 否 | 是（LLM API）|
| 分析速度 | 中（依赖 JAR 大小）| 较慢（扫描全部字节码）| 快（聚合后调用 LLM）|
| 结果精度 | 中（需人工验证）| 低-中（保守分析）| 高（AI 辅助判断）|
| 适用场景 | Java 反序列化审计 | Web 应用安全审计 | 生成交付型报告 |
| 前置要求 | 完成 JAR 分析 | 完成 JAR 分析 | 运行其他分析模块 |

---

## 面向答辩的总结表述

如果需要在答辩时用一段话概括这三个功能，可以直接使用下面这段：

> 功能 A 解决的是反序列化触发链自动发现问题，核心是从 Serializable 触发点自动搜索到危险 Sink；功能 B 解决的是 Web 入口到危险操作的过程间数据流传播问题，核心是方法摘要和 Worklist 传播；功能 D 解决的是分析结果交付效率问题，核心是把 A/B 和已有链路分析结果统一聚合，再生成结构化审计报告。三者分别对应“自动发现候选链”“自动发现污点路径”“自动输出审计成果”，共同构成了从发现到验证再到交付的完整闭环。

---

## 常见问题

**Q：反序列化链挖掘结果很多，哪些值得重点关注？**  
A：优先关注 Sink 为 `RCE`（`Runtime.exec` / `ProcessBuilder.start`）和 `JNDI Injection` 的候选链；链深度越浅（2-4层）越可能是真实利用链；触发方法为 `readObject` / `hashCode` / `compareTo` 的最值得跟进。

**Q：DFA 分析耗时很长怎么办？**  
A：DFA 需要扫描所有字节码构建摘要，大型 JAR（>10MB）可能需要 2-5 分钟。建议在分析完成后再进行其他操作，或使用多核机器——后续版本将支持多线程加速。

**Q：LLM 报告生成失败，显示 ERROR？**  
A：常见原因：① API Key 错误；② Endpoint 地址不正确；③ 网络超时（可在代码中调整 `timeoutSeconds`）；④ Token 超限（分析结果太多，可先减少数据量）。

**Q：DFA 分析发现了很多误报怎么办？**  
A：DFA 当前是保守近似分析，在 flow-insensitive 的前提下必然会有误报。建议将 DFA 结果导入 chains 面板，使用 DFS + 精确污点分析进行二次验证。

---

*更多文档请参考 [README.md](../README.md) 和其他模块文档（`doc/` 目录）。*
```
