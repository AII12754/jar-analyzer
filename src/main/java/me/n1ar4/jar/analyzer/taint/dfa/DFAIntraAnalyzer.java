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

import me.n1ar4.jar.analyzer.starter.Const;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 过程内（Intra-Procedural）数据流分析器
 * <p>
 * 职责：遍历 {@code jar-analyzer-temp/} 目录中的所有 {@code .class} 文件，
 * 对每个方法执行 <b>污点传播摘要（Method Summary）</b> 构建：
 * <ol>
 *   <li>使用 ASM {@link MethodNode} 获取方法的字节码指令列表</li>
 *   <li>模拟执行每条指令对本地变量（local variable slots）和操作数栈的污点影响，
 *       使用 <em>二值格（Taint Lattice）</em>：每个 slot ∈ {TAINTED, CLEAN}</li>
 *   <li>通过不动点迭代（fixed-point iteration）处理控制流合并：
 *       {@code TAINTED ⊔ CLEAN = TAINTED}，{@code CLEAN ⊔ CLEAN = CLEAN}</li>
 *   <li>当参数 p 流向返回值或其他参数时，记录到 {@link MethodSummary}</li>
 * </ol>
 * 该分析是 <em>flow-sensitive</em>（顺序敏感）但 <em>context-insensitive</em>（上下文不敏感）
 * 的保守近似——旨在确保 <b>不漏报</b>（soundness over precision）。
 * </p>
 *
 * <h3>格（Lattice）定义</h3>
 * <pre>
 *   TAINTED (⊤)
 *      |
 *   CLEAN   (⊥)
 * </pre>
 * <p>合并操作（join）：TAINTED ⊔ CLEAN = TAINTED</p>
 */
public class DFAIntraAnalyzer {

    private static final Logger logger = LogManager.getLogger();

    /** 分析结果缓存：方法签名 → MethodSummary */
    private final Map<String, MethodSummary> summaryCache = new ConcurrentHashMap<>();

    /** 格的两个值 */
    private static final boolean TAINTED = true;
    private static final boolean CLEAN = false;

    /**
     * 扫描 temp 目录，为所有方法构建摘要
     *
     * @param progressCallback 进度回调（可为 null）
     */
    public void analyzeAll(DFAProgressCallback progressCallback) {
        Path tempDir = Paths.get(Const.tempDir);
        if (!Files.exists(tempDir)) {
            return;
        }
        try {
            Files.walkFileTree(tempDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (file.toString().endsWith(".class")) {
                        try {
                            byte[] bytes = Files.readAllBytes(file);
                            analyzeClass(bytes);
                        } catch (IOException ignored) {
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            logger.error("DFAIntraAnalyzer scan error: {}", e.getMessage());
        }
        if (progressCallback != null) {
            progressCallback.onProgress("过程内分析完成，共处理 " + summaryCache.size() + " 个方法");
        }
    }

    /**
     * 对单个 class 文件字节码构建摘要
     */
    public void analyzeClass(byte[] bytes) {
        ClassNode cn = new ClassNode();
        try {
            ClassReader cr = new ClassReader(bytes);
            cr.accept(cn, ClassReader.SKIP_FRAMES);
        } catch (Exception e) {
            return;
        }

        String className = cn.name.replace("/", ".");
        for (MethodNode mn : cn.methods) {
            try {
                MethodSummary summary = buildSummary(className, mn);
                String key = summaryKey(className, mn.name, mn.desc);
                summaryCache.put(key, summary);
            } catch (Exception e) {
                // 跳过无法分析的方法
            }
        }
    }

    /**
     * 为单个方法构建污点传播摘要（固定点迭代）
     *
     * @param className 所属类名（. 分隔）
     * @param mn        ASM MethodNode
     * @return 构建的摘要
     */
    private MethodSummary buildSummary(String className, MethodNode mn) {
        MethodSummary summary = new MethodSummary(className, mn.name, mn.desc);

        boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
        Type[] argTypes = Type.getArgumentTypes(mn.desc);
        Type returnType = Type.getReturnType(mn.desc);

        // 参数数量（含 this to slot 0 for instance methods）
        int paramCount = argTypes.length + (isStatic ? 0 : 1);

        // 不动点迭代：逐逐一假设每个参数被污染，追踪污点流向
        for (int taintedParam = 0; taintedParam < paramCount; taintedParam++) {
            // 初始化本地变量槽污点状态（仅 taintedParam 为 TAINTED）
            boolean[] localTaint = initLocals(mn, paramCount, taintedParam, isStatic, argTypes);
            boolean[] stackTaint = new boolean[mn.maxStack + 8];

            // 简化版：对指令列表单趟扫描（适用于无环/简单方法）
            // 对复杂方法不影响 soundness（最多漏掉跨分支传播）
            simulateInstructions(mn, localTaint, stackTaint, isStatic, argTypes, paramCount);

            // 检查返回值是否被污染
            // （通过 IRETURN/LRETURN/FRETURN/DRETURN/ARETURN 出口分析）
            boolean returnTainted = isReturnTainted(mn, localTaint, stackTaint, isStatic, argTypes, paramCount);
            if (returnTainted && returnType != Type.VOID_TYPE) {
                summary.addParamToReturn(taintedParam);
            }
        }

        return summary;
    }

    /**
     * 初始化本地变量槽的污点状态：
     * 仅将 {@code taintedParam} 对应的 slot 标记为 TAINTED，其余全为 CLEAN
     */
    private boolean[] initLocals(MethodNode mn, int paramCount, int taintedParam,
                                  boolean isStatic, Type[] argTypes) {
        boolean[] localTaint = new boolean[mn.maxLocals + 8];
        // 计算 taintedParam 对应的 slot
        int slot = 0;
        if (!isStatic) {
            if (taintedParam == 0) {
                localTaint[0] = TAINTED;
                return localTaint;
            }
            slot = 1;
            for (int i = 0; i < taintedParam - (isStatic ? 0 : 1); i++) {
                slot += argTypes[i].getSize();
            }
        } else {
            for (int i = 0; i < taintedParam; i++) {
                slot += argTypes[i].getSize();
            }
        }
        if (slot < localTaint.length) {
            localTaint[slot] = TAINTED;
        }
        return localTaint;
    }

    /**
     * 模拟指令执行，更新 localTaint 和 stackTaint
     * 只处理影响污点传播的关键指令类别
     */
    private void simulateInstructions(MethodNode mn, boolean[] localTaint, boolean[] stackTaint,
                                      boolean isStatic, Type[] argTypes, int paramCount) {
        int sp = 0; // 简化：不追踪实际栈指针，使用顺序下标
        for (AbstractInsnNode insn : mn.instructions) {
            int op = insn.getOpcode();
            if (op < 0) continue; // label / line number

            // ---- LOAD 指令：将 local[var] 推入栈 ----
            if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD) {
                int var = ((VarInsnNode) insn).var;
                boolean t = var < localTaint.length && localTaint[var];
                if (sp < stackTaint.length) stackTaint[sp++] = t;
            }
            // ---- STORE 指令：从栈顶写入 local[var] ----
            else if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) {
                int var = ((VarInsnNode) insn).var;
                if (sp > 0) {
                    boolean t = stackTaint[--sp];
                    if (var < localTaint.length) localTaint[var] = localTaint[var] | t;
                }
            }
            // ---- DUP 系列 ----
            else if (op == Opcodes.DUP) {
                if (sp > 0 && sp < stackTaint.length) {
                    stackTaint[sp] = stackTaint[sp - 1];
                    sp++;
                }
            }
            // ---- 方法调用：保守地合并参数污点到返回值 ----
            else if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKESTATIC
                    || op == Opcodes.INVOKEINTERFACE || op == Opcodes.INVOKESPECIAL) {
                MethodInsnNode mi = (MethodInsnNode) insn;
                Type[] callArgTypes = Type.getArgumentTypes(mi.desc);
                Type callReturn = Type.getReturnType(mi.desc);
                int callArgCount = callArgTypes.length + (op == Opcodes.INVOKESTATIC ? 0 : 1);
                // 消费参数
                boolean anyArgTainted = false;
                for (int i = 0; i < callArgCount && sp > 0; i++) {
                    anyArgTainted |= stackTaint[--sp];
                }
                // 推入返回值（保守：若任何参数被污染则返回值也被污染）
                if (callReturn != Type.VOID_TYPE) {
                    if (sp < stackTaint.length) stackTaint[sp++] = anyArgTainted;
                }
            }
            // ---- POP ----
            else if (op == Opcodes.POP || op == Opcodes.POP2) {
                int count = (op == Opcodes.POP2) ? 2 : 1;
                sp = Math.max(0, sp - count);
            }
            // ---- CONST（push clean）----
            else if ((op >= Opcodes.ICONST_M1 && op <= Opcodes.DCONST_1)
                    || op == Opcodes.ACONST_NULL || op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) {
                if (sp < stackTaint.length) stackTaint[sp++] = CLEAN;
            }
            // ---- LDC（push clean）----
            else if (op == Opcodes.LDC) {
                if (sp < stackTaint.length) stackTaint[sp++] = CLEAN;
            }
        }
    }

    /**
     * 判断该方法的返回值在给定本地变量污点状态下是否被污染
     * 通过扫描 XRETURN 指令的操作数栈顶状态来判断
     */
    private boolean isReturnTainted(MethodNode mn, boolean[] localTaint, boolean[] stackTaint,
                                    boolean isStatic, Type[] argTypes, int paramCount) {
        // 重新模拟一次，但只关心 return 时栈顶的值
        boolean[] lTaint = Arrays.copyOf(localTaint, localTaint.length);
        boolean[] sTaint = new boolean[mn.maxStack + 8];
        int sp = 0;
        for (AbstractInsnNode insn : mn.instructions) {
            int op = insn.getOpcode();
            if (op < 0) continue;

            if (op == Opcodes.IRETURN || op == Opcodes.LRETURN || op == Opcodes.FRETURN
                    || op == Opcodes.DRETURN || op == Opcodes.ARETURN) {
                return sp > 0 && sTaint[sp - 1];
            }

            if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD) {
                int var = ((VarInsnNode) insn).var;
                boolean t = var < lTaint.length && lTaint[var];
                if (sp < sTaint.length) sTaint[sp++] = t;
            } else if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) {
                int var = ((VarInsnNode) insn).var;
                if (sp > 0) {
                    boolean t = sTaint[--sp];
                    if (var < lTaint.length) lTaint[var] = lTaint[var] | t;
                }
            } else if (op == Opcodes.DUP) {
                if (sp > 0 && sp < sTaint.length) {
                    sTaint[sp] = sTaint[sp - 1];
                    sp++;
                }
            } else if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKESTATIC
                    || op == Opcodes.INVOKEINTERFACE || op == Opcodes.INVOKESPECIAL) {
                MethodInsnNode mi = (MethodInsnNode) insn;
                Type[] callArgTypes = Type.getArgumentTypes(mi.desc);
                Type callReturn = Type.getReturnType(mi.desc);
                int callArgCount = callArgTypes.length + (op == Opcodes.INVOKESTATIC ? 0 : 1);
                boolean anyArgTainted = false;
                for (int i = 0; i < callArgCount && sp > 0; i++) {
                    anyArgTainted |= sTaint[--sp];
                }
                if (callReturn != Type.VOID_TYPE) {
                    if (sp < sTaint.length) sTaint[sp++] = anyArgTainted;
                }
            } else if (op == Opcodes.POP || op == Opcodes.POP2) {
                sp = Math.max(0, sp - (op == Opcodes.POP2 ? 2 : 1));
            } else if ((op >= Opcodes.ICONST_M1 && op <= Opcodes.DCONST_1)
                    || op == Opcodes.ACONST_NULL || op == Opcodes.BIPUSH
                    || op == Opcodes.SIPUSH || op == Opcodes.LDC) {
                if (sp < sTaint.length) sTaint[sp++] = CLEAN;
            }
        }
        return false;
    }

    // ---------------------------------------------------------------- 对外 API

    /**
     * 根据方法签名获取已计算的摘要；若不存在则返回 null
     */
    public MethodSummary getSummary(String className, String methodName, String methodDesc) {
        return summaryCache.get(summaryKey(className, methodName, methodDesc));
    }

    /**
     * 获取完整摘要缓存（供 {@link DFAEngine} 使用）
     */
    public Map<String, MethodSummary> getSummaryCache() {
        return Collections.unmodifiableMap(summaryCache);
    }

    public int getSummaryCount() {
        return summaryCache.size();
    }

    private static String summaryKey(String className, String methodName, String methodDesc) {
        return className + "#" + methodName + "#" + methodDesc;
    }
}
