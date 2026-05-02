/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.core;

import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.starter.Const;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class BytecodeCallGraph {
    private static final Logger logger = LogManager.getLogger();

    private static volatile BytecodeCallGraph instance;

    private final Map<String, List<MethodResult>> calleeMap = new HashMap<>();
    private final Map<String, List<MethodResult>> callerMap = new HashMap<>();
    private final Map<String, String> superClassMap = new HashMap<>();
    private final Map<String, Set<String>> interfaceMap = new HashMap<>();
    private final Map<String, Set<String>> declaredMethodMap = new HashMap<>();

    private BytecodeCallGraph() {
        build();
    }

    public static BytecodeCallGraph getInstance() {
        BytecodeCallGraph local = instance;
        if (local == null) {
            synchronized (BytecodeCallGraph.class) {
                local = instance;
                if (local == null) {
                    instance = local = new BytecodeCallGraph();
                }
            }
        }
        return local;
    }

    public static void reset() {
        synchronized (BytecodeCallGraph.class) {
            instance = null;
        }
    }

    public List<MethodResult> getCallees(String className, String methodName, String methodDesc) {
        return collectResolved(calleeMap, className, methodName, methodDesc);
    }

    public List<MethodResult> getCallers(String className, String methodName, String methodDesc) {
        return collectResolved(callerMap, className, methodName, methodDesc);
    }

    private void build() {
        Path tempDir = Paths.get(Const.tempDir);
        if (!Files.exists(tempDir)) {
            return;
        }

        logger.info("build bytecode fallback call graph from {}", tempDir.toAbsolutePath());
        try {
            Files.walkFileTree(tempDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (!file.toString().endsWith(".class")) {
                        return FileVisitResult.CONTINUE;
                    }
                    try {
                        byte[] bytes = Files.readAllBytes(file);
                        analyzeClass(bytes);
                    } catch (Exception ignored) {
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            logger.warn("build bytecode call graph error: {}", e.getMessage());
        }
    }

    private void analyzeClass(byte[] bytes) {
        ClassNode cn = new ClassNode();
        try {
            new ClassReader(bytes).accept(cn, ClassReader.SKIP_FRAMES);
        } catch (Exception e) {
            return;
        }

        String className = cn.name.replace("/", ".");
        if (cn.superName != null) {
            superClassMap.put(className, cn.superName.replace("/", "."));
        }
        Set<String> interfaces = new LinkedHashSet<>();
        if (cn.interfaces != null) {
            for (String iface : cn.interfaces) {
                interfaces.add(iface.replace("/", "."));
            }
        }
        interfaceMap.put(className, interfaces);

        for (MethodNode mn : cn.methods) {
            declaredMethodMap.computeIfAbsent(className, ignored -> new LinkedHashSet<>())
                    .add(signature(mn.name, mn.desc));
            String callerKey = key(className, mn.name, mn.desc);
            Set<String> dedup = new LinkedHashSet<>();
            for (AbstractInsnNode insn : mn.instructions) {
                if (!(insn instanceof MethodInsnNode)) {
                    continue;
                }
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                MethodResult callee = resolveDeclaredMethod(new MethodResult(
                        methodInsn.owner.replace("/", "."),
                        methodInsn.name,
                        methodInsn.desc));
                String calleeKey = key(callee.getClassName(), callee.getMethodName(), callee.getMethodDesc());
                if (!dedup.add(calleeKey)) {
                    continue;
                }

                calleeMap.computeIfAbsent(callerKey, ignored -> new ArrayList<>()).add(callee);

                MethodResult caller = new MethodResult(className, mn.name, mn.desc);
                callerMap.computeIfAbsent(calleeKey, ignored -> new ArrayList<>()).add(caller);
            }
        }
    }

    private List<MethodResult> collectResolved(Map<String, List<MethodResult>> source,
                                               String className,
                                               String methodName,
                                               String methodDesc) {
        LinkedHashSet<String> searchKeys = resolveMethodKeys(className, methodName, methodDesc);
        List<MethodResult> results = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String searchKey : searchKeys) {
            List<MethodResult> methods = source.get(searchKey);
            if (methods == null) {
                continue;
            }
            for (MethodResult method : methods) {
                MethodResult resolved = resolveDeclaredMethod(method);
                String resolvedKey = key(resolved.getClassName(), resolved.getMethodName(), resolved.getMethodDesc());
                if (seen.add(resolvedKey)) {
                    results.add(resolved);
                }
            }
        }
        return results;
    }

    private LinkedHashSet<String> resolveMethodKeys(String className, String methodName, String methodDesc) {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(className);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (current == null || !visited.add(current)) {
                continue;
            }
            if (hasDeclaredMethod(current, methodName, methodDesc)) {
                keys.add(key(current, methodName, methodDesc));
            }
            String superClass = superClassMap.get(current);
            if (superClass != null) {
                queue.add(superClass);
            }
            for (String iface : interfaceMap.getOrDefault(current, Collections.emptySet())) {
                queue.add(iface);
            }
        }
        if (keys.isEmpty()) {
            keys.add(key(className, methodName, methodDesc));
        }
        return keys;
    }

    private MethodResult resolveDeclaredMethod(MethodResult method) {
        if (method == null) {
            return null;
        }
        LinkedHashSet<String> keys = resolveMethodKeys(
                method.getClassName(),
                method.getMethodName(),
                method.getMethodDesc());
        String resolvedKey = keys.iterator().next();
        if (resolvedKey.equals(key(method.getClassName(), method.getMethodName(), method.getMethodDesc()))) {
            return method;
        }
        String[] parts = resolvedKey.split("#", 3);
        return new MethodResult(parts[0], parts[1], parts[2]);
    }

    private boolean hasDeclaredMethod(String className, String methodName, String methodDesc) {
        return declaredMethodMap.getOrDefault(className, Collections.emptySet())
                .contains(signature(methodName, methodDesc));
    }

    private static String signature(String methodName, String methodDesc) {
        return methodName + "#" + methodDesc;
    }

    private static String key(String className, String methodName, String methodDesc) {
        return className + "#" + methodName + "#" + methodDesc;
    }
}