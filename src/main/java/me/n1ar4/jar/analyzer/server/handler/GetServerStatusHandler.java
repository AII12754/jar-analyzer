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
import me.n1ar4.jar.analyzer.gui.GlobalOptions;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.oneclick.OneClickAnalyzer;
import me.n1ar4.jar.analyzer.server.ServerConfig;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.server.NanoHTTPD;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GetServerStatusHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        CoreEngine engine = MainForm.getEngine();
        boolean engineReady = engine != null && engine.isEnabled();
        List<String> jars = engineReady ? engine.getJarsPath() : Collections.emptyList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("engine_ready", engineReady);
        result.put("jar_count", jars.size());
        result.put("jars", jars);
        result.put("one_click_cached", OneClickAnalyzer.hasRun);
        result.put("dfa_count", OneClickAnalyzer.lastDfaFindings.size());
        result.put("gadget_count", OneClickAnalyzer.lastGadgetCandidates.size());

        ServerConfig serverConfig = GlobalOptions.getServerConfig();
        if (serverConfig != null) {
            result.put("auth_enabled", serverConfig.isAuth());
            result.put("bind", serverConfig.getBind());
            result.put("port", serverConfig.getPort());
        } else {
            result.put("auth_enabled", false);
            result.put("bind", "0.0.0.0");
            result.put("port", 10032);
        }

        if (engineReady) {
            result.put("message", "分析引擎已就绪，可以直接在浏览器中执行查询、DFS 与报告生成。");
        } else {
            result.put("message", "尚未检测到已加载的 JAR/WAR 或数据库构建结果。请先在客户端完成导入与构建。");
        }
        return buildJSON(JSON.toJSONString(result));
    }
}