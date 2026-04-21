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

/**
 * DFA 分析进度回调接口
 */
public interface DFAProgressCallback {
    /**
     * 分析过程进度回调
     *
     * @param message 进度描述
     */
    void onProgress(String message);
}
