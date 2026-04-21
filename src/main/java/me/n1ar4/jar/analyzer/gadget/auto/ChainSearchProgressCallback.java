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

/**
 * 链挖掘进度回调接口
 * 供 UI 层接收进度消息并更新进度显示
 */
public interface ChainSearchProgressCallback {
    /**
     * 收到进度消息
     *
     * @param message 进度描述文本
     */
    void onProgress(String message);
}
