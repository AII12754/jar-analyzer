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

import java.util.*;

/**
 * 方法摘要（Method Summary）
 * <p>
 * 记录在过程间分析中，一个方法对污点的传播规则：
 * <ul>
 *   <li>{@link #paramToParam}：若第 i 个参数（0-based，this=0 表示虚参数）被污点污染，
 *       则第 j 个参数也会被污染（用于引用参数修改场景）</li>
 *   <li>{@link #paramToReturn}：若第 i 个参数被污染，返回值也被污染</li>
 *   <li>{@link #isAlwaysTainted}：此方法的返回值无条件被污染（如 source 方法）</li>
 *   <li>{@link #isSink}：此方法是危险 sink（污点到达则报告）</li>
 *   <li>{@link #isSanitizer}：此方法是净化函数（污点消除）</li>
 * </ul>
 * </p>
 * <p>
 * 传播关系采用 {@code Set<Integer>} 表示：{@code paramToReturn.get(i)} 非空且包含
 * {@link #RETURN_INDEX} 时，表示参数 i 污染了返回值。
 * </p>
 */
public class MethodSummary {

    /** 虚拟 slot：代表方法返回值 */
    public static final int RETURN_INDEX = -1;

    /** className 用 . 分隔 */
    private final String className;
    private final String methodName;
    private final String methodDesc;

    /**
     * key = 源参数下标（0=this，1=第1参数 ...）
     * value = 该源参数能污染到的目标参数下标集合
     */
    private final Map<Integer, Set<Integer>> paramToParam = new HashMap<>();

    /**
     * 若第 i 个参数被污染，则返回值也被污染
     * 存储为参数下标 → true/false 映射
     */
    private final Set<Integer> paramToReturn = new HashSet<>();

    private boolean isAlwaysTainted = false;
    private boolean isSink = false;
    private boolean isSanitizer = false;

    public MethodSummary(String className, String methodName, String methodDesc) {
        this.className = className;
        this.methodName = methodName;
        this.methodDesc = methodDesc;
    }

    // ---------------------------------------------------------------- 添加规则

    public void addParamToParamEdge(int from, int to) {
        paramToParam.computeIfAbsent(from, k -> new HashSet<>()).add(to);
    }

    public void addParamToReturn(int fromParam) {
        paramToReturn.add(fromParam);
    }

    // ---------------------------------------------------------------- 传播逻辑

    /**
     * 给定当前调用点的污点状态，计算调用该方法后：
     * <ol>
     *   <li>返回值是否被污染</li>
     *   <li>哪些参数 slot 新增污染</li>
     * </ol>
     *
     * @param taintedArgs 调用点实参的污点状态  index=0 代表 this（若非 static），
     *                    index=1 代表第1参数 ...
     * @return 传播结果，包含 returnTainted 和 newTaintedArgIndices
     */
    public PropagationResult propagate(Set<Integer> taintedArgs) {
        boolean returnTainted = isAlwaysTainted;
        Set<Integer> newTaint = new HashSet<>();

        if (isSanitizer) {
            return new PropagationResult(false, Collections.emptySet());
        }

        for (int taintedIdx : taintedArgs) {
            // 参数 → 返回值
            if (paramToReturn.contains(taintedIdx)) {
                returnTainted = true;
            }
            // 参数 → 参数
            Set<Integer> targets = paramToParam.get(taintedIdx);
            if (targets != null) {
                newTaint.addAll(targets);
            }
        }

        return new PropagationResult(returnTainted, newTaint);
    }

    // ---------------------------------------------------------------- Getters

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getMethodDesc() {
        return methodDesc;
    }

    public boolean isAlwaysTainted() {
        return isAlwaysTainted;
    }

    public void setAlwaysTainted(boolean alwaysTainted) {
        isAlwaysTainted = alwaysTainted;
    }

    public boolean isSink() {
        return isSink;
    }

    public void setSink(boolean sink) {
        isSink = sink;
    }

    public boolean isSanitizer() {
        return isSanitizer;
    }

    public void setSanitizer(boolean sanitizer) {
        isSanitizer = sanitizer;
    }

    /**
     * 传播结果：
     */
    public static class PropagationResult {
        private final boolean returnTainted;
        private final Set<Integer> newTaintedArgs;

        public PropagationResult(boolean returnTainted, Set<Integer> newTaintedArgs) {
            this.returnTainted = returnTainted;
            this.newTaintedArgs = newTaintedArgs;
        }

        public boolean isReturnTainted() {
            return returnTainted;
        }

        public Set<Integer> getNewTaintedArgs() {
            return newTaintedArgs;
        }
    }

    @Override
    public String toString() {
        return "MethodSummary{" + className + "#" + methodName + methodDesc +
                ", sink=" + isSink + ", source=" + isAlwaysTainted + "}";
    }
}
