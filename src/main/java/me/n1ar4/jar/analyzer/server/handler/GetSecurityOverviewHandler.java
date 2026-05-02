/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.server.handler;

import com.alibaba.fastjson2.JSON;
import me.n1ar4.jar.analyzer.engine.CoreEngine;
import me.n1ar4.jar.analyzer.entity.ClassResult;
import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.server.NanoHTTPD;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GetSecurityOverviewHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        CoreEngine engine = MainForm.getEngine();
        if (engine == null || !engine.isEnabled()) {
            return error();
        }

        ArrayList<ClassResult> controllers = sortClasses(engine.getAllSpringC());
        ArrayList<ClassResult> servlets = sortClasses(engine.getAllServlets());
        ArrayList<ClassResult> filters = sortClasses(engine.getAllFilters());
        ArrayList<ClassResult> listeners = sortClasses(engine.getAllListeners());
        ArrayList<MethodResult> mappings = collectMappings(engine, controllers);

        List<Map<String, Object>> hunts = new ArrayList<>();
        hunts.add(buildHunt(engine,
                "command-exec",
                "命令执行",
                "high",
                "直接命中 Runtime.exec 或 ProcessBuilder.start 的调用者，通常需要优先审查。",
                "runtime-exec",
                new SinkPattern("Runtime.exec", "java/lang/Runtime", "exec", ""),
                new SinkPattern("ProcessBuilder.start", "java/lang/ProcessBuilder", "start", "")));
        hunts.add(buildHunt(engine,
                "jndi-lookup",
                "JNDI 调用",
                "critical",
                "出现 JNDI lookup 的地方，往往需要结合外部输入继续判断注入风险。",
                "jndi-lookup",
                new SinkPattern("Context.lookup", "javax/naming/Context", "lookup", ""),
                new SinkPattern("InitialContext.lookup", "javax/naming/InitialContext", "lookup", "")));
        hunts.add(buildHunt(engine,
                "deserialization",
                "反序列化",
                "high",
                "命中 ObjectInputStream.readObject 的调用者，适合作为反序列化排查入口。",
                "deserialization",
                new SinkPattern("ObjectInputStream.readObject", "java/io/ObjectInputStream", "readObject", "")));
        hunts.add(buildHunt(engine,
                "script-eval",
                "脚本执行",
                "high",
                "脚本引擎 eval 常见于模板执行、动态脚本或命令桥接场景。",
                "script-eval",
                new SinkPattern("ScriptEngine.eval", "javax/script/ScriptEngine", "eval", "")));
        hunts.add(buildHunt(engine,
                "ssrf-network",
                "网络出站",
                "medium",
                "URL.openConnection 一类网络出站能力，适合结合业务参数继续排查 SSRF。",
                "ssrf-url",
                new SinkPattern("URL.openConnection", "java/net/URL", "openConnection", "")));
        hunts.add(buildHunt(engine,
                "reflection",
                "反射调用",
                "medium",
                "Method.invoke 与 ClassLoader.loadClass 一类能力常用于框架反射，也可能藏业务动态执行点。",
                "reflection-invoke",
                new SinkPattern("Method.invoke", "java/lang/reflect/Method", "invoke", ""),
                new SinkPattern("ClassLoader.loadClass", "java/lang/ClassLoader", "loadClass", "")));
        hunts.add(buildHunt(engine,
                "file-write",
                "文件写入",
                "medium",
                "文件写入能力需要结合文件名、路径来源继续判断路径穿越或任意写文件风险。",
                "file-write",
                new SinkPattern("FileOutputStream.<init>", "java/io/FileOutputStream", "<init>", ""),
                new SinkPattern("Files.write", "java/nio/file/Files", "write", "")));

        Map<String, Object> assets = new LinkedHashMap<>();
        assets.put("controllers", controllers);
        assets.put("servlets", servlets);
        assets.put("filters", filters);
        assets.put("listeners", listeners);
        assets.put("mappings", mappings);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "安全巡航已生成");
        result.put("assets", assets);
        result.put("hunts", hunts);
        return buildJSON(JSON.toJSONString(result));
    }

    private ArrayList<MethodResult> collectMappings(CoreEngine engine, List<ClassResult> controllers) {
        LinkedHashMap<String, MethodResult> unique = new LinkedHashMap<>();
        for (ClassResult controller : controllers) {
            if (controller == null || isBlank(controller.getClassName())) {
                continue;
            }
            ArrayList<MethodResult> mappings = engine.getSpringM(controller.getClassName());
            for (MethodResult mapping : mappings) {
                if (mapping == null) {
                    continue;
                }
                unique.put(methodKey(mapping), mapping);
            }
        }
        ArrayList<MethodResult> results = new ArrayList<>(unique.values());
        results.sort(Comparator
                .comparing(MethodResult::getActualPath, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(MethodResult::getClassName, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(MethodResult::getMethodName, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(MethodResult::getMethodDesc, String.CASE_INSENSITIVE_ORDER));
        return results;
    }

    private List<Map<String, Object>> collectFindings(CoreEngine engine, SinkPattern... patterns) {
        LinkedHashMap<String, Map<String, Object>> unique = new LinkedHashMap<>();
        for (SinkPattern pattern : patterns) {
            ArrayList<MethodResult> callers = engine.getCallersLike(pattern.sinkClass, pattern.sinkMethod, pattern.sinkDesc);
            for (MethodResult caller : callers) {
                if (caller == null) {
                    continue;
                }
                String key = methodKey(caller);
                if (unique.containsKey(key)) {
                    continue;
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("className", nullSafe(caller.getClassName()));
                item.put("methodName", nullSafe(caller.getMethodName()));
                item.put("methodDesc", nullSafe(caller.getMethodDesc()));
                item.put("matchedSink", pattern.displayName);
                item.put("sinkClass", pattern.sinkClass);
                item.put("sinkMethod", pattern.sinkMethod);
                item.put("sinkMethodDesc", nullSafe(pattern.sinkDesc));
                unique.put(key, item);
            }
        }
        ArrayList<Map<String, Object>> results = new ArrayList<>(unique.values());
        results.sort(Comparator
            .comparing((Map<String, Object> item) -> String.valueOf(item.get("className")), String.CASE_INSENSITIVE_ORDER)
            .thenComparing(item -> String.valueOf(item.get("methodName")), String.CASE_INSENSITIVE_ORDER)
            .thenComparing(item -> String.valueOf(item.get("methodDesc")), String.CASE_INSENSITIVE_ORDER));
        return results;
    }

    private Map<String, Object> buildHunt(CoreEngine engine,
                                          String id,
                                          String title,
                                          String severity,
                                          String summary,
                                          String presetId,
                                          SinkPattern... patterns) {
        List<Map<String, Object>> findings = collectFindings(engine, patterns);
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", id);
        item.put("title", title);
        item.put("severity", severity);
        item.put("summary", summary);
        item.put("presetId", presetId);
        item.put("callerCount", findings.size());
        item.put("findings", findings);
        return item;
    }

    private ArrayList<ClassResult> sortClasses(ArrayList<ClassResult> input) {
        input.sort(Comparator.comparing(ClassResult::getClassName, String.CASE_INSENSITIVE_ORDER));
        return input;
    }

    private String methodKey(MethodResult result) {
        return nullSafe(result.getClassName())
                + '#'
                + nullSafe(result.getMethodName())
                + '#'
                + nullSafe(result.getMethodDesc());
    }

    private String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static final class SinkPattern {
        private final String displayName;
        private final String sinkClass;
        private final String sinkMethod;
        private final String sinkDesc;

        private SinkPattern(String displayName, String sinkClass, String sinkMethod, String sinkDesc) {
            this.displayName = displayName;
            this.sinkClass = sinkClass;
            this.sinkMethod = sinkMethod;
            this.sinkDesc = sinkDesc == null ? "" : sinkDesc;
        }
    }
}