## API

现在 `Jar Analyzer` 在分析完成后提供 `HTTP API` 和浏览器工作台两种使用方式。

- 浏览器工作台入口：`http://127.0.0.1:10032/`
- 默认绑定 `0.0.0.0:10032`，你可以通过 `gui --port [port]` 指定参数
- 如果启用了 `server auth`，浏览器页面本身仍可访问，但所有 `/api/*` 请求都需要携带 `Token` Header

浏览器工作台当前内置以下能力：

- 运行状态概览
- 浏览器上传 JAR / WAR 并构建数据库
- JAR / Spring Controller / 方法检索
- 方法调用关系查询、反编译查看与调用图展示
- DFS 分析与污点图展示
- LLM 审计报告一键生成

参数说明：

- ${class-name} 是完整类名例如 `java.lang.String`
- ${method} 是普通的方法名称（除了 `<init>` 和 `<clinit>` 方法）
- ${desc} 是完整的方法描述例如 `()Ljava/lang/Class;`
- ${str} 是普通的字符串

| API                             | 参数                                                | 功能                       |
|:--------------------------------|:--------------------------------------------------|:-------------------------|
| /api/server_status              | /                                                 | 查询当前服务端、引擎和一键分析缓存状态     |
| /api/start_project_build        | `POST` 表单或二进制上传                                 | 启动浏览器构建任务               |
| /api/build_status               | /                                                 | 查询浏览器构建任务进度与数据库状态        |
| /api/generate_audit_report      | `POST` 表单：endpoint/api_key/model/analyze_first | 在浏览器中生成 LLM 审计报告      |
| /api/get_jars_list              | /                                                 | 查询所有输入的 JAR 文件           |
| /api/get_jar_by_class           | class=${class-name}                               | 根据输入的完整类名查询归属 JAR 文件     |
| /api/get_callers                | class=${class-name}&method=${method}&desc=${desc} | 根据方法信息找到所有调用者            |
| /api/get_callers_like           | class=${class-name}&method=${method}&desc=${desc} | 根据方法信息模糊找到所有调用者          |
| /api/get_callee                 | class=${class-name}&method=${method}&desc=${desc} | 根据方法信息找到所有被调用者           |
| /api/get_method                 | class=${class-name}&method=${method}&desc=${desc} | 根据方法信息查询具体方法信息           |
| /api/get_method_like            | class=${class-name}&method=${method}&desc=${desc} | 根据方法信息模糊查找方法信息           |
| /api/get_methods_by_str         | str=${str}                                        | 查询包含指定字符串的方法信息           |
| /api/get_methods_by_class       | class=${class-name}                               | 查询 CLASS 中的所有方法          |
| /api/get_impls                  | class=${class-name}&method=${method}&desc=${desc} | 查询方法的所有子类和实现             |
| /api/get_super_impls            | class=${class-name}&method=${method}&desc=${desc} | 查询方法的所有父类和接口             |
| /api/get_all_spring_controllers | /                                                 | 查询所有的 SPRING CONTROLLER  |
| /api/get_spring_mappings        | class=${class-name}                               | 根据类名查询所有的 SPRING MAPPING |
| /api/get_abs_path               | class=${class-name}                               | 得到 CLASS 文件的本地绝对路径       |
| /api/get_class_by_class         | class=${class-name}                               | 得到 CLASS 的详细信息           |
| /api/get_all_servlets           | /                                                 | 得到所有的 SERVLET 信息         |
| /api/get_all_listeners          | /                                                 | 得到所有的 LISTENER 信息        |
| /api/get_all_filters            | /                                                 | 得到所有的 FILTER 信息          |
| /api/fernflower_code            | class=${class-name}&method=${method}&desc=${desc} | 使用 FERNFLOWER 反编译某个方法    |
| /api/cfr_code                   | class=${class-name}&method=${method}&desc=${desc} | 使用 CFR 反编译某个方法           |
| /api/dfs_analyze                | 参数过多请参考 DFSHandler 类                              | 执行 DFS 分析                |
| /api/method_graph               | class=${class-name}&method=${method}&desc=${desc} | 返回当前方法的 HTML 调用图        |
| /api/taint_graph                | 参数过多请参考 DFSHandler 类                              | 返回 DFS / 污点图 HTML        |

`/api/start_project_build` 调用方式

- 表单模式：`POST` `application/x-www-form-urlencoded`，至少传 `source_path`
- 上传模式：`POST` 原始二进制请求体，并携带 `X-File-Name` Header
- 可选字段：`fix_class`、`quick_mode`、`clean_before_build`、`rt_jar_path`
- 上传文件会落到 `jar-analyzer-download/browser-upload` 目录，建议前端随后轮询 `/api/build_status`

`/api/generate_audit_report` 表单字段说明

- `endpoint`：兼容 OpenAI Chat Completions 的完整地址，例如 `http://localhost:11434/v1/chat/completions`
- `api_key`：Bearer Key，本地模型如果无需鉴权也建议填一个占位值以兼容统一逻辑
- `model`：模型名称，例如 `gpt-4o-mini` / `qwen2.5-14b-instruct`
- `analyze_first`：`true` 表示先执行一键分析再生成报告，`false` 表示优先复用当前缓存


`DFSHandler` 示例

```text
http://127.0.0.1:10032/api/dfs_analyze?
sink_class=java/lang/Runtime&sink_method=exec&sink_method_desc=(Ljava/lang/String;)Ljava/lang/Process;&
source_class=[可选]&source_method=[可选]&source_method_desc=[可选]&
depth=10&limit=10&from_sink=true&search_null_source=true
```