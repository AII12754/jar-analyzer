/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.gadget.auto;

import me.n1ar4.jar.analyzer.core.BytecodeCallGraph;
import me.n1ar4.jar.analyzer.engine.CoreEngine;
import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.gadget.auto.model.ChainCandidate;
import me.n1ar4.jar.analyzer.gadget.auto.model.SerSinkDef;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.starter.Const;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import org.objectweb.asm.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/**
 * 反序列化利用链自动挖掘引擎
 * <p>
 * 算法核心：
 * 1. 扫描所有实现了 java.io.Serializable 的类，找到 readObject/readResolve/
 *    readObjectNoData/finalize 等触发点（trigger）
 * 2. 在已构建的方法调用图（method_call_table）上，以各触发点为起始，
 *    做深度优先搜索，寻找能到达危险 sink 的调用路径
 * 3. 对候选路径执行简易可行性筛选（类层次分析 CHA）：
 *    接口方法调用时，只保留实现了该接口且可序列化的类
 * 4. 返回 {@link ChainCandidate} 列表供 UI 展示
 * </p>
 */
public class SerializableChainFinder {

    private static final Logger logger = LogManager.getLogger();

    /**
     * 反序列化触发入口方法名列表
     * 这些方法在反序列化时由 JVM 自动调用
     */
    private static final List<String> TRIGGER_METHODS = Arrays.asList(
            "readObject",
            "readResolve",
            "readObjectNoData",
            "finalize",
            "hashCode",
            "equals",
            "compareTo",
            "toString"
    );

    /**
     * 危险 Sink 定义列表
     * 每个 Sink 描述一类危险操作
     */
    private static final List<SerSinkDef> SINK_DEFS = Arrays.asList(
            new SerSinkDef("java/lang/Runtime", "exec", "RCE via Runtime.exec"),
            new SerSinkDef("java/lang/ProcessBuilder", "start", "RCE via ProcessBuilder.start"),
            new SerSinkDef("javax/naming/Context", "lookup", "JNDI Injection"),
            new SerSinkDef("java/io/ObjectInputStream", "readObject", "Deserialization Chain"),
            new SerSinkDef("java/lang/reflect/Method", "invoke", "Reflective Invocation"),
            new SerSinkDef("java/lang/ClassLoader", "loadClass", "ClassLoader Abuse"),
            new SerSinkDef("java/io/FileOutputStream", "<init>", "Arbitrary File Write"),
            new SerSinkDef("javax/script/ScriptEngine", "eval", "Script Injection")
    );

    /** 最大搜索深度，防止超时 */
    public static final int MAX_DEPTH = 12;

    /** 最大结果数量 */
    public static final int MAX_RESULTS = 50;

    private final CoreEngine engine;
    private final ChainSearchProgressCallback callback;

    public SerializableChainFinder(ChainSearchProgressCallback callback) {
        this.engine = MainForm.getEngine();
        this.callback = callback;
    }

    /**
     * 执行自动挖掘，返回发现的候选链列表
     *
     * @return 候选链列表
     */
    public List<ChainCandidate> findChains() {
        List<ChainCandidate> results = new ArrayList<>();

        if (engine == null || !engine.isEnabled()) {
            logger.warn("引擎未就绪，无法执行链挖掘");
            return results;
        }

        // 第一步：收集所有可序列化类的触发方法
        notifyProgress("正在扫描可序列化类...");
        List<MethodResult> triggers = collectTriggerMethods();
        notifyProgress("发现 " + triggers.size() + " 个触发点，开始图搜索...");

        // 第二步：对每个触发点 × 每个 Sink 做 DFS
        int done = 0;
        for (MethodResult trigger : triggers) {
            if (results.size() >= MAX_RESULTS) {
                break;
            }
            for (SerSinkDef sink : SINK_DEFS) {
                if (results.size() >= MAX_RESULTS) {
                    break;
                }
                List<List<MethodResult>> paths = dfsFind(trigger, sink);
                for (List<MethodResult> path : paths) {
                    results.add(buildCandidate(path, sink, trigger));
                }
            }
            done++;
            if (done % 10 == 0) {
                notifyProgress("已处理 " + done + "/" + triggers.size() + " 个触发点，发现 " + results.size() + " 条候选链...");
            }
        }

        notifyProgress("挖掘完成，共发现 " + results.size() + " 条候选链");
        return results;
    }

    /**
     * 第一步：扫描 jar-analyzer-temp 目录，找到所有可序列化类的触发方法
     */
    private List<MethodResult> collectTriggerMethods() {
        List<MethodResult> triggers = new ArrayList<>();
        Path tempDir = Paths.get(Const.tempDir);
        if (!Files.exists(tempDir) || !Files.isDirectory(tempDir)) {
            return triggers;
        }

        Map<String, SerializableClassInfo> classInfoMap = new HashMap<>();

        // 遍历所有 .class 文件
        try {
            Files.walkFileTree(tempDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (file.toString().endsWith(".class")) {
                        byte[] bytes;
                        try {
                            bytes = Files.readAllBytes(file);
                        } catch (IOException e) {
                            return FileVisitResult.CONTINUE;
                        }
                        SerializableClassInfo info = extractSerializableInfo(bytes);
                        if (info != null && info.className != null) {
                            classInfoMap.put(info.className, info);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            logger.error("扫描 temp 目录失败: {}", e.getMessage());
        }

        Set<String> serializableClasses = resolveSerializableClasses(classInfoMap);
        for (SerializableClassInfo info : classInfoMap.values()) {
            if (!serializableClasses.contains(info.className)) {
                continue;
            }
            for (String triggerName : TRIGGER_METHODS) {
                if (info.hasMethods.contains(triggerName)) {
                    MethodResult m = new MethodResult(
                            info.className.replace("/", "."),
                            triggerName,
                            info.triggerDescs.getOrDefault(triggerName, "")
                    );
                    triggers.add(m);
                }
            }
        }
        return triggers;
    }

    private Set<String> resolveSerializableClasses(Map<String, SerializableClassInfo> classInfoMap) {
        Set<String> serializableClasses = new HashSet<>();

        for (SerializableClassInfo info : classInfoMap.values()) {
            if (info.directSerializable) {
                serializableClasses.add(info.className);
            }
        }

        boolean changed;
        do {
            changed = false;
            for (SerializableClassInfo info : classInfoMap.values()) {
                if (serializableClasses.contains(info.className)) {
                    continue;
                }

                if (info.superName != null && serializableClasses.contains(info.superName)) {
                    changed = serializableClasses.add(info.className) || changed;
                    continue;
                }

                for (String iface : info.interfaces) {
                    if ("java/io/Serializable".equals(iface) || serializableClasses.contains(iface)) {
                        changed = serializableClasses.add(info.className) || changed;
                        break;
                    }
                }
            }
        } while (changed);

        return serializableClasses;
    }

    /**
     * 从字节码中提取可序列化类信息
     */
    private SerializableClassInfo extractSerializableInfo(byte[] bytes) {
        SerializableClassInfo info = new SerializableClassInfo();
        try {
            ClassReader cr = new ClassReader(bytes);
            cr.accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public void visit(int version, int access, String name, String signature,
                                  String superName, String[] interfaces) {
                    info.className = name;
                    info.superName = superName;
                    if (interfaces != null) {
                        for (String iface : interfaces) {
                            info.interfaces.add(iface);
                            if ("java/io/Serializable".equals(iface)) {
                                info.directSerializable = true;
                            }
                        }
                    }
                }

                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    if (TRIGGER_METHODS.contains(name)) {
                        info.hasMethods.add(name);
                        info.triggerDescs.put(name, descriptor);
                    }
                    return null;
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES);
        } catch (Exception e) {
            return null;
        }
        return info.className != null ? info : null;
    }

    private static class SerializableClassInfo {
        String className;
        String superName;
        boolean directSerializable = false;
        Set<String> interfaces = new HashSet<>();
        Set<String> hasMethods = new HashSet<>();
        Map<String, String> triggerDescs = new HashMap<>();
    }

    /**
     * 从 trigger 出发，DFS 搜索能到达 sink 的路径
     *
     * @param trigger  起始触发方法
     * @param sinkDef  目标 Sink 定义
     * @return 所有满足条件的调用路径
     */
    private List<List<MethodResult>> dfsFind(MethodResult trigger, SerSinkDef sinkDef) {
        List<List<MethodResult>> found = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        List<MethodResult> path = new ArrayList<>();
        path.add(trigger);
        dfsHelper(trigger, sinkDef, path, visited, 0, found);
        return found;
    }

    private void dfsHelper(
            MethodResult current,
            SerSinkDef sinkDef,
            List<MethodResult> path,
            Set<String> visited,
            int depth,
            List<List<MethodResult>> found
    ) {
        if (found.size() >= 5) {
            // 每个 trigger × sink 组合最多找 5 条
            return;
        }
        if (depth >= MAX_DEPTH) {
            return;
        }

        // 检查是否命中 Sink
        if (matchesSink(current, sinkDef)) {
            found.add(new ArrayList<>(path));
            return;
        }

        String key = methodKey(current);
        if (visited.contains(key)) {
            return;
        }
        visited.add(key);

        // 从数据库查询 callee 列表（当前方法调用了哪些方法）
        ArrayList<MethodResult> callees = mergeCallees(current);

        if (callees != null) {
            for (MethodResult callee : callees) {
                path.add(callee);
                dfsHelper(callee, sinkDef, path, visited, depth + 1, found);
                path.remove(path.size() - 1);
            }
        }

        visited.remove(key);
    }

    private ArrayList<MethodResult> mergeCallees(MethodResult current) {
        LinkedHashMap<String, MethodResult> merged = new LinkedHashMap<>();
        try {
            ArrayList<MethodResult> dbCallees = engine.getCallee(
                    current.getClassName(),
                    current.getMethodName(),
                    current.getMethodDesc()
            );
            if (dbCallees != null) {
                for (MethodResult callee : dbCallees) {
                    merged.put(methodKey(callee), callee);
                }
            }
        } catch (Exception ignored) {
        }

        for (MethodResult callee : BytecodeCallGraph.getInstance().getCallees(
                current.getClassName(),
                current.getMethodName(),
                current.getMethodDesc())) {
            merged.put(methodKey(callee), callee);
        }
        return new ArrayList<>(merged.values());
    }

    /**
     * 判断方法是否匹配指定的 Sink 定义
     */
    private boolean matchesSink(MethodResult m, SerSinkDef sink) {
        String className = m.getClassName().replace(".", "/");
        String methodName = m.getMethodName();
        // 类名前缀匹配（处理 JDK 内部类变体）
        return className.contains(sink.getClassName()) &&
                methodName.equals(sink.getMethodName());
    }

    private ChainCandidate buildCandidate(List<MethodResult> path, SerSinkDef sink, MethodResult trigger) {
        ChainCandidate c = new ChainCandidate();
        c.setPath(new ArrayList<>(path));
        c.setSinkDescription(sink.getDescription());
        c.setTriggerMethod(trigger.getMethodName());
        c.setTriggerClass(trigger.getClassName());
        c.setSinkClass(sink.getClassName().replace("/", "."));
        c.setSinkMethod(sink.getMethodName());
        c.setDepth(path.size());
        return c;
    }

    private String methodKey(MethodResult m) {
        return m.getClassName() + "#" + m.getMethodName() + "#" + m.getMethodDesc();
    }

    private void notifyProgress(String msg) {
        logger.info("[SerChainFinder] {}", msg);
        if (callback != null) {
            callback.onProgress(msg);
        }
    }

    /**
     * ASM ClassVisitor：仅检查类是否实现 Serializable 接口（保留兼容用）
     */
    private static class SerializableChecker extends ClassVisitor {
        boolean isSerializable = false;

        SerializableChecker() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            if (interfaces != null) {
                for (String iface : interfaces) {
                    if ("java/io/Serializable".equals(iface)) {
                        isSerializable = true;
                    }
                }
            }
            super.visit(version, access, name, signature, superName, interfaces);
        }
    }
}
