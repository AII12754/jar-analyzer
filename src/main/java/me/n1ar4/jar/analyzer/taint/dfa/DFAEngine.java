/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.taint.dfa;

import me.n1ar4.jar.analyzer.core.BytecodeCallGraph;
import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.entity.ClassResult;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import org.objectweb.asm.Type;

import java.util.*;

/**
 * 过程间数据流分析引擎（DFA Engine）
 * <p>
 * 采用 <b>Worklist 算法</b>，在方法调用图（Call Graph）上进行过程间污点传播：
 * <pre>
 *   Worklist ← {所有 source 方法}
 *   while Worklist ≠ ∅:
 *       m ← Worklist.pop()
 *       for each call site of m:
 *           compute propagation via MethodSummary
 *           if callee 污点状态有变化:
 *               Worklist.add(callee)
 *           if callee is SINK and tainted:
 *               report finding
 * </pre>
 * </p>
 *
 * <h3>Source / Sink 定义</h3>
 * Source 与 Sink 通过字符串前缀匹配（支持类名前缀 + 方法名）来配置，
 * 默认内置了常见 Web/反序列化安全相关的 source 和 sink。
 *
 * <h3>与过程内分析的协作</h3>
 * {@link DFAIntraAnalyzer} 负责从字节码构建每个方法的 {@link MethodSummary}；
 * 本引擎负责在调用图上传播这些摘要所描述的污点边。
 *
 * <h3>精度说明</h3>
 * 当前实现是 <em>flow-insensitive</em>（不区分程序点顺序）且
 * <em>context-insensitive</em>（调用上下文不区分），
 * 保守近似以确保 soundness（不漏报为首要目标），可能存在误报。
 */
public class DFAEngine {

    private static final Logger logger = LogManager.getLogger();

    /** 默认 Source 方法列表（类名.方法名 前缀匹配） */
    private static final List<String[]> DEFAULT_SOURCES = Arrays.asList(
            // HTTP 请求参数
            new String[]{"javax.servlet.http.HttpServletRequest", "getParameter"},
            new String[]{"javax.servlet.http.HttpServletRequest", "getHeader"},
            new String[]{"javax.servlet.http.HttpServletRequest", "getQueryString"},
            new String[]{"javax.servlet.http.HttpServletRequest", "getInputStream"},
            new String[]{"javax.servlet.http.HttpServletRequest", "getReader"},
            // Spring MVC
            new String[]{"org.springframework.web.bind.annotation", "RequestParam"},
            // 文件上传
            new String[]{"javax.servlet.http.Part", "getInputStream"},
            // Cookie
            new String[]{"javax.servlet.http.Cookie", "getValue"},
            // URL Path
            new String[]{"javax.servlet.http.HttpServletRequest", "getPathInfo"}
    );

    /** 默认 Sink 方法列表 */
    private static final List<String[]> DEFAULT_SINKS = Arrays.asList(
            // RCE
            new String[]{"java.lang.Runtime", "exec", "RCE via Runtime.exec"},
            new String[]{"java.lang.ProcessBuilder", "start", "RCE via ProcessBuilder.start"},
            // SQL 注入
            new String[]{"java.sql.Statement", "execute", "SQL Injection"},
            new String[]{"java.sql.Statement", "executeQuery", "SQL Injection"},
            new String[]{"java.sql.Statement", "executeUpdate", "SQL Injection"},
            new String[]{"java.sql.Connection", "prepareStatement", "SQL Injection"},
            // JNDI
            new String[]{"javax.naming.Context", "lookup", "JNDI Injection"},
            new String[]{"javax.naming.InitialContext", "lookup", "JNDI Injection"},
            // Path Traversal
            new String[]{"java.io.FileInputStream", "<init>", "Path Traversal"},
            new String[]{"java.io.FileOutputStream", "<init>", "Arbitrary File Write"},
            new String[]{"java.nio.file.Paths", "get", "Path Traversal"},
            // SSRF
            new String[]{"java.net.URL", "<init>", "SSRF"},
            new String[]{"java.net.URL", "openConnection", "SSRF"},
            // XSS
            new String[]{"javax.servlet.http.HttpServletResponse", "getWriter", "Potential XSS"},
            // Expression Language 注入
            new String[]{"javax.el.ExpressionFactory", "createValueExpression", "EL Injection"},
            // 脚本注入
            new String[]{"javax.script.ScriptEngine", "eval", "Script Injection"},
            // 反序列化
            new String[]{"java.io.ObjectInputStream", "readObject", "Deserialization"}
    );

    /** 过程内分析器（提供方法摘要） */
    private final DFAIntraAnalyzer intraAnalyzer;

    /** 分析进度回调 */
    private final DFAProgressCallback callback;

    /** 已发现的污点路径 */
    private final List<DFAFinding> findings = new ArrayList<>();
    private final Set<String> findingKeys = new HashSet<>();

    /** 最大过程间传播步骤数，防止无限循环 */
    private static final int MAX_PROPAGATION_STEPS = 10000;

    public DFAEngine(DFAProgressCallback callback) {
        this.intraAnalyzer = new DFAIntraAnalyzer();
        this.callback = callback;
    }

    /**
     * 执行完整的过程间数据流分析
     *
     * @return 发现的污点路径列表
     */
    public List<DFAFinding> analyze() {
        findings.clear();
        findingKeys.clear();

        if (MainForm.getEngine() == null || !MainForm.getEngine().isEnabled()) {
            notifyProgress("引擎未就绪，请先加载 JAR");
            return Collections.emptyList();
        }

        // 第一阶段：过程内分析，构建所有方法摘要
        notifyProgress("第一阶段：过程内字节码分析，构建方法摘要...");
        intraAnalyzer.analyzeAll(msg -> notifyProgress("  " + msg));
        notifyProgress("方法摘要构建完成，共 " + intraAnalyzer.getSummaryCount() + " 个");

        // 第二阶段：过程间 Worklist 传播
        notifyProgress("第二阶段：过程间污点传播（Worklist 算法）...");
        runWorklist();

        notifyProgress("分析完成，共发现 " + findings.size() + " 个潜在漏洞路径");
        return new ArrayList<>(findings);
    }

    /**
     * Worklist 算法核心：从所有 source 出发，沿调用图传播污点，到达 sink 时记录
     */
    private void runWorklist() {
        // 每个 worklist 条目：当前方法 + 已污染的参数下标集合 + 调用路径
        Queue<WorklistItem> worklist = new LinkedList<>();

        // 初始化：将所有 source 方法的返回值标记为污染，并加入 worklist
        Map<String, MethodSummary> cache = intraAnalyzer.getSummaryCache();

        for (Map.Entry<String, MethodSummary> entry : cache.entrySet()) {
            MethodSummary summary = entry.getValue();
            if (isSource(summary.getClassName(), summary.getMethodName())) {
                summary.setAlwaysTainted(true);
                // source 的"调用者"需要被分析——将 source 本身的返回值传染给调用者
                // 通过数据库查询调用者，以 return 值传进入
                List<MethodResult> callers = queryCallers(summary);
                for (MethodResult caller : callers) {
                    Set<Integer> initialTaint = new HashSet<>();
                    initialTaint.add(MethodSummary.RETURN_INDEX); // 返回值被污染
                    List<MethodResult> path = new ArrayList<>();
                    path.add(new MethodResult(summary.getClassName(), summary.getMethodName(), summary.getMethodDesc()));
                    path.add(caller);
                    worklist.add(new WorklistItem(caller, initialTaint, path));
                }
            }
        }

        addSpringEntrySources(worklist, cache);

        // Worklist 迭代
        Set<String> visited = new HashSet<>();
        int steps = 0;
        while (!worklist.isEmpty() && steps < MAX_PROPAGATION_STEPS) {
            steps++;
            WorklistItem item = worklist.poll();
            String visitKey = item.toKey();

            if (visited.contains(visitKey)) {
                continue;
            }
            visited.add(visitKey);

            MethodSummary summary = getSummaryForMethod(item.method, cache);
            if (summary == null) {
                // 无摘要：保守处理，假设返回值被污染
                summary = createConservativeSummary(item.method);
            }

            // 如果是 sink 且有污点到达，记录发现
            if (isSink(summary.getClassName(), summary.getMethodName())) {
                recordFinding(item.path, summary.getClassName(), summary.getMethodName());
                if (findings.size() >= 200) {
                    notifyProgress("发现数量达到上限（200），停止传播");
                    return;
                }
                continue; // sink 之后不再继续传播
            }

            // 传播：查询该方法的所有 callee
            List<MethodResult> callees = queryCallees(summary);
            for (MethodResult callee : callees) {
                MethodSummary calleeSummary = getSummaryForMethod(callee, cache);
                if (calleeSummary == null) {
                    calleeSummary = createConservativeSummary(callee);
                }

                // 使用摘要计算传播结果。
                // 旧实现固定只把 this(0) 视为污点，会直接丢失从 source 带来的返回值/参数污点，
                // 导致大量应继续传播的路径在第一跳后被截断。
                Set<Integer> taintedArgs = buildConservativeTaintedArgs(callee, item.taintedSlots);
                if (taintedArgs.isEmpty()) {
                    continue;
                }

                if (isSink(callee.getClassName(), callee.getMethodName())) {
                    List<MethodResult> sinkPath = new ArrayList<>(item.path);
                    sinkPath.add(callee);
                    recordFinding(sinkPath, callee.getClassName(), callee.getMethodName());
                    if (findings.size() >= 200) {
                        notifyProgress("发现数量达到上限（200），停止传播");
                        return;
                    }
                    continue;
                }

                MethodSummary.PropagationResult prop = calleeSummary.propagate(taintedArgs);

                Set<Integer> newTaint = new HashSet<>(item.taintedSlots);
                if (prop.isReturnTainted()) {
                    newTaint.add(MethodSummary.RETURN_INDEX);
                }
                newTaint.addAll(prop.getNewTaintedArgs());

                if (!newTaint.isEmpty()) {
                    List<MethodResult> newPath = new ArrayList<>(item.path);
                    newPath.add(callee);
                    worklist.add(new WorklistItem(callee, newTaint, newPath));
                }
            }
        }

        if (steps >= MAX_PROPAGATION_STEPS) {
            notifyProgress("警告：达到最大传播步骤数 " + MAX_PROPAGATION_STEPS + "，分析提前终止");
        }
    }

    // ---------------------------------------------------------------- 辅助方法

    private boolean isSource(String className, String methodName) {
        className = normalizeClassName(className);
        for (String[] src : DEFAULT_SOURCES) {
            if (className.contains(src[0]) && methodName.equals(src[1])) {
                return true;
            }
        }
        return false;
    }

    private boolean isSink(String className, String methodName) {
        className = normalizeClassName(className);
        for (String[] sink : DEFAULT_SINKS) {
            if (className.contains(sink[0]) && methodName.equals(sink[1])) {
                return true;
            }
        }
        return false;
    }

    private String getSinkDescription(String className, String methodName) {
        className = normalizeClassName(className);
        for (String[] sink : DEFAULT_SINKS) {
            if (className.contains(sink[0]) && methodName.equals(sink[1])) {
                return sink[2];
            }
        }
        return "Unknown Sink";
    }

    private void recordFinding(List<MethodResult> path, String sinkClass, String sinkMethod) {
        String key = buildFindingKey(path, sinkClass, sinkMethod);
        if (!findingKeys.add(key)) {
            return;
        }
        findings.add(new DFAFinding(
                new ArrayList<>(path),
                getSinkDescription(sinkClass, sinkMethod),
                sinkClass,
                sinkMethod
        ));
    }

    private String buildFindingKey(List<MethodResult> path, String sinkClass, String sinkMethod) {
        StringBuilder sb = new StringBuilder();
        for (MethodResult method : path) {
            sb.append(methodKey(method)).append("->");
        }
        sb.append(sinkClass).append("#").append(sinkMethod);
        return sb.toString();
    }

    private MethodSummary getSummaryForMethod(MethodResult m, Map<String, MethodSummary> cache) {
        String normalizedClassName = normalizeClassName(m.getClassName());
        String key = normalizedClassName + "#" + m.getMethodName() + "#" + m.getMethodDesc();
        MethodSummary exact = cache.get(key);
        if (exact != null) {
            return exact;
        }

        MethodSummary matched = null;
        for (MethodSummary summary : cache.values()) {
            if (!summary.getClassName().equals(normalizedClassName)) {
                continue;
            }
            if (!summary.getMethodName().equals(m.getMethodName())) {
                continue;
            }
            if (matched != null) {
                return null;
            }
            matched = summary;
        }
        return matched;
    }

    private MethodSummary createConservativeSummary(MethodResult m) {
        MethodSummary s = new MethodSummary(m.getClassName(), m.getMethodName(), m.getMethodDesc());
        // 保守：参数0可以传染返回值
        s.addParamToReturn(0);
        s.addParamToReturn(1);
        return s;
    }

    private void addSpringEntrySources(Queue<WorklistItem> worklist,
                                       Map<String, MethodSummary> cache) {
        if (MainForm.getEngine() == null) {
            return;
        }

        int entryCount = 0;
        try {
            ArrayList<ClassResult> controllers = MainForm.getEngine().getAllSpringC();
            for (ClassResult controller : controllers) {
                if (controller == null || controller.getClassName() == null) {
                    continue;
                }
                ArrayList<MethodResult> mappings = MainForm.getEngine().getSpringM(controller.getClassName());
                for (MethodResult mapping : mappings) {
                    if (!isSpringWebEntry(mapping)) {
                        continue;
                    }

                    Set<Integer> taintedArgs = buildSpringEntryTaint(mapping);
                    if (taintedArgs.isEmpty()) {
                        continue;
                    }

                    MethodSummary summary = getSummaryForMethod(mapping, cache);
                    MethodResult seedMethod = normalizeMethod(mapping);
                    if (summary != null) {
                        summary.setAlwaysTainted(true);
                        seedMethod = new MethodResult(
                                summary.getClassName(),
                                summary.getMethodName(),
                                summary.getMethodDesc());
                    }
                    List<MethodResult> path = new ArrayList<>();
                    path.add(seedMethod);
                    worklist.add(new WorklistItem(seedMethod, taintedArgs, path));
                    entryCount++;
                }
            }
        } catch (Exception e) {
            notifyProgress("Spring MVC 入口收集失败：" + e.getMessage());
            return;
        }

        if (entryCount > 0) {
            notifyProgress("第三类 Source：已加载 " + entryCount + " 个 Spring MVC 入口方法");
        }
    }

    private boolean isSpringWebEntry(MethodResult method) {
        if (method == null) {
            return false;
        }
        String restfulType = method.getRestfulType();
        return restfulType != null && !restfulType.trim().isEmpty() &&
                !"Unknown".equalsIgnoreCase(restfulType.trim());
    }

    private Set<Integer> buildSpringEntryTaint(MethodResult method) {
        Set<Integer> taintedArgs = new HashSet<>();
        try {
            Type[] argTypes = Type.getArgumentTypes(method.getMethodDesc());
            for (int i = 0; i < argTypes.length; i++) {
                Type arg = argTypes[i];
                if (arg.getSort() != Type.VOID) {
                    taintedArgs.add(i + 1);
                }
            }
        } catch (Exception ignored) {
            taintedArgs.add(1);
        }
        return taintedArgs;
    }

    private Set<Integer> buildConservativeTaintedArgs(MethodResult callee, Set<Integer> currentTaint) {
        if (currentTaint == null || currentTaint.isEmpty()) {
            return Collections.emptySet();
        }

        Set<Integer> taintedArgs = new HashSet<>();
        for (int idx : currentTaint) {
            if (idx >= 0) {
                taintedArgs.add(idx);
            }
        }

        if (!taintedArgs.isEmpty()) {
            return taintedArgs;
        }

        // 当前方法的返回值带污点，但调用图里没有精确到调用点的实参映射，
        // 这里采用保守近似：认为该污点可能流入后续调用的所有实参与 this。
        taintedArgs.add(0);
        try {
            int argCount = Type.getArgumentTypes(callee.getMethodDesc()).length;
            for (int i = 1; i <= argCount; i++) {
                taintedArgs.add(i);
            }
        } catch (Exception ignored) {
            taintedArgs.add(1);
        }
        return taintedArgs;
    }

    private List<MethodResult> queryCallers(MethodSummary summary) {
        LinkedHashMap<String, MethodResult> merged = new LinkedHashMap<>();
        try {
            if (MainForm.getEngine() != null) {
                ArrayList<MethodResult> callers = MainForm.getEngine().getCallers(
                        summary.getClassName(), summary.getMethodName(), summary.getMethodDesc());
                if (callers != null) {
                    for (MethodResult caller : callers) {
                        MethodResult normalized = normalizeMethod(caller);
                        merged.put(methodKey(normalized), normalized);
                    }
                }
            }
        } catch (Exception e) {
            // ignore and merge bytecode call graph
        }
        for (MethodResult caller : BytecodeCallGraph.getInstance().getCallers(
                summary.getClassName(), summary.getMethodName(), summary.getMethodDesc())) {
            MethodResult normalized = normalizeMethod(caller);
            merged.put(methodKey(normalized), normalized);
        }
        return new ArrayList<>(merged.values());
    }

    private List<MethodResult> queryCallees(MethodSummary summary) {
        LinkedHashMap<String, MethodResult> merged = new LinkedHashMap<>();
        try {
            if (MainForm.getEngine() != null) {
                ArrayList<MethodResult> callees = MainForm.getEngine().getCallee(
                        summary.getClassName(), summary.getMethodName(), summary.getMethodDesc());
                if (callees != null) {
                    for (MethodResult callee : callees) {
                        MethodResult normalized = normalizeMethod(callee);
                        merged.put(methodKey(normalized), normalized);
                    }
                }
            }
        } catch (Exception e) {
            // ignore and merge bytecode call graph
        }
        for (MethodResult callee : BytecodeCallGraph.getInstance().getCallees(
                summary.getClassName(), summary.getMethodName(), summary.getMethodDesc())) {
            MethodResult normalized = normalizeMethod(callee);
            merged.put(methodKey(normalized), normalized);
        }
        return new ArrayList<>(merged.values());
    }

    private String methodKey(MethodResult method) {
        return normalizeClassName(method.getClassName()) + "#" + method.getMethodName() + "#" + method.getMethodDesc();
    }

    private MethodResult normalizeMethod(MethodResult method) {
        if (method == null) {
            return null;
        }
        MethodResult normalized = new MethodResult(
                normalizeClassName(method.getClassName()),
                method.getMethodName(),
                method.getMethodDesc());
        normalized.setRestfulType(method.getRestfulType());
        normalized.setPath(method.getActualPath());
        return normalized;
    }

    private String normalizeClassName(String className) {
        if (className == null) {
            return "";
        }
        return className.replace('/', '.');
    }

    private void notifyProgress(String msg) {
        logger.info("[DFAEngine] {}", msg);
        if (callback != null) {
            callback.onProgress(msg);
        }
    }

    // ---------------------------------------------------------------- 内部类

    /** Worklist 中的每个分析条目 */
    private static class WorklistItem {
        final MethodResult method;
        final Set<Integer> taintedSlots;
        final List<MethodResult> path;

        WorklistItem(MethodResult method, Set<Integer> taintedSlots, List<MethodResult> path) {
            this.method = method;
            this.taintedSlots = taintedSlots;
            this.path = path;
        }

        String toKey() {
            return method.getClassName() + "#" + method.getMethodName()
                    + "#" + method.getMethodDesc() + "#" + taintedSlots.toString();
        }
    }

    /**
     * 数据流分析发现结果
     */
    public static class DFAFinding {
        private final List<MethodResult> path;
        private final String sinkDescription;
        private final String sinkClass;
        private final String sinkMethod;

        public DFAFinding(List<MethodResult> path, String sinkDescription,
                          String sinkClass, String sinkMethod) {
            this.path = path;
            this.sinkDescription = sinkDescription;
            this.sinkClass = sinkClass;
            this.sinkMethod = sinkMethod;
        }

        public List<MethodResult> getPath() {
            return path;
        }

        public String getSinkDescription() {
            return sinkDescription;
        }

        public String getSinkClass() {
            return sinkClass;
        }

        public String getSinkMethod() {
            return sinkMethod;
        }

        public String getSourceMethod() {
            if (path == null || path.isEmpty()) return "Unknown";
            MethodResult first = path.get(0);
            return first.getClassName() + "#" + first.getMethodName();
        }

        public int getPathDepth() {
            return path == null ? 0 : path.size();
        }

        /**
         * 生成简要摘要字符串：Source → ... → Sink
         */
        public String toSummary() {
            if (path == null || path.isEmpty()) return "Empty path";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < path.size(); i++) {
                MethodResult m = path.get(i);
                String shortClass = m.getClassName();
                int dot = shortClass.lastIndexOf('.');
                if (dot >= 0) shortClass = shortClass.substring(dot + 1);
                sb.append(shortClass).append("#").append(m.getMethodName());
                if (i < path.size() - 1) sb.append(" → ");
            }
            return sb.toString();
        }
    }
}
