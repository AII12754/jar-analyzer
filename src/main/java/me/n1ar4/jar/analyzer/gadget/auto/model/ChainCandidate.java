/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.gadget.auto.model;

import me.n1ar4.jar.analyzer.entity.MethodResult;

import java.util.List;

/**
 * 候选利用链
 * 代表一条从反序列化触发点到危险 Sink 的完整调用路径
 */
public class ChainCandidate {

    /** 触发类（实现了 Serializable 的类） */
    private String triggerClass;

    /** 触发方法（readObject / readResolve / hashCode 等） */
    private String triggerMethod;

    /** Sink 类名（点分隔） */
    private String sinkClass;

    /** Sink 方法名 */
    private String sinkMethod;

    /** Sink 的危险描述（如 "RCE via Runtime.exec"） */
    private String sinkDescription;

    /** 调用链深度（方法数量） */
    private int depth;

    /** 完整调用路径，从触发方法到 Sink 方法 */
    private List<MethodResult> path;

    public String getTriggerClass() {
        return triggerClass;
    }

    public void setTriggerClass(String triggerClass) {
        this.triggerClass = triggerClass;
    }

    public String getTriggerMethod() {
        return triggerMethod;
    }

    public void setTriggerMethod(String triggerMethod) {
        this.triggerMethod = triggerMethod;
    }

    public String getSinkClass() {
        return sinkClass;
    }

    public void setSinkClass(String sinkClass) {
        this.sinkClass = sinkClass;
    }

    public String getSinkMethod() {
        return sinkMethod;
    }

    public void setSinkMethod(String sinkMethod) {
        this.sinkMethod = sinkMethod;
    }

    public String getSinkDescription() {
        return sinkDescription;
    }

    public void setSinkDescription(String sinkDescription) {
        this.sinkDescription = sinkDescription;
    }

    public int getDepth() {
        return depth;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public List<MethodResult> getPath() {
        return path;
    }

    public void setPath(List<MethodResult> path) {
        this.path = path;
    }

    /**
     * 生成人类可读的链摘要
     *
     * @return 形如 "TriggerClass#readObject -> ... -> Runtime#exec" 的字符串
     */
    public String toSummary() {
        if (path == null || path.isEmpty()) {
            return "(empty chain)";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < path.size(); i++) {
            MethodResult m = path.get(i);
            String shortClass = m.getClassName();
            int dot = shortClass.lastIndexOf('.');
            if (dot >= 0) {
                shortClass = shortClass.substring(dot + 1);
            }
            sb.append(shortClass).append("#").append(m.getMethodName());
            if (i < path.size() - 1) {
                sb.append(" -> ");
            }
        }
        return sb.toString();
    }
}
