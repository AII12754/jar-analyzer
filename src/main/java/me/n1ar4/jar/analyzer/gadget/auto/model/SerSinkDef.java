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

/**
 * 危险 Sink 定义
 * 描述一类危险方法调用，作为链挖掘的目标终点
 */
public class SerSinkDef {

    /** 目标方法所在类（JVM 内部名称，使用 / 分隔） */
    private final String className;

    /** 目标方法名 */
    private final String methodName;

    /** 人类可读的危险描述 */
    private final String description;

    public SerSinkDef(String className, String methodName, String description) {
        this.className = className;
        this.methodName = methodName;
        this.description = description;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description + " (" + className + "#" + methodName + ")";
    }
}
