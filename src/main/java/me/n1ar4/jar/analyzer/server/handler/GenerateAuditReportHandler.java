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
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.oneclick.OneClickAnalyzer;
import me.n1ar4.jar.analyzer.report.AuditReportBuilder;
import me.n1ar4.jar.analyzer.report.LLMConfig;
import me.n1ar4.jar.analyzer.report.MarkdownReportRenderer;
import me.n1ar4.jar.analyzer.server.LatestAuditReportStore;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.server.NanoHTTPD;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class GenerateAuditReportHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        List<String> logs = new ArrayList<>();
        try {
            CoreEngine engine = MainForm.getEngine();
            if (engine == null || !engine.isEnabled()) {
                return buildResult(false,
                        "引擎未就绪，请先在客户端中加载 JAR/WAR 并完成数据库构建。",
                        "",
                        logs,
                        false,
                        false,
                        0,
                        0,
                        "当前未加载项目");
            }

            String endpoint = getParam(session, "endpoint");
            String apiKey = getParam(session, "api_key");
            String model = getParam(session, "model");
            boolean analyzeFirst = Boolean.parseBoolean(getParam(session, "analyze_first", "false"));

            LLMConfig config = new LLMConfig(endpoint, apiKey, model);
            if (!config.isValid()) {
                return buildResult(false,
                        "请填写完整的 LLM 配置：endpoint / api_key / model。",
                        "",
                        logs,
                        false,
                        false,
                        OneClickAnalyzer.lastDfaFindings.size(),
                        OneClickAnalyzer.lastGadgetCandidates.size(),
                        buildTargetName(engine.getJarsPath()));
            }

            OneClickAnalyzer.AnalysisResult analysisResult = null;
            boolean usedCache = false;
            if (analyzeFirst) {
                addLog(logs, "【阶段 1/3】开始执行整项目自动分析...");
                analysisResult = OneClickAnalyzer.analyzeProject(logs::add);
                addLog(logs, "【阶段 2/3】自动分析完成，准备生成审计报告...");
            } else if (OneClickAnalyzer.hasRun) {
                usedCache = true;
                addLog(logs, "检测到一键分析缓存，本次将直接复用缓存生成报告。");
            } else {
                addLog(logs, "未检测到一键分析缓存，将基于当前已有结果直接尝试生成报告。");
            }

            AuditReportBuilder builder = new AuditReportBuilder(config);
            String targetName = buildTargetName(engine.getJarsPath());
            builder.setTargetJarName(targetName);
            if (analysisResult != null) {
                builder.setDfaFindings(analysisResult.getDfaFindings());
                builder.setGadgetCandidates(analysisResult.getGadgetCandidates());
            } else if (OneClickAnalyzer.hasRun) {
                builder.setDfaFindings(OneClickAnalyzer.lastDfaFindings);
                builder.setGadgetCandidates(OneClickAnalyzer.lastGadgetCandidates);
            }

            addLog(logs, "【阶段 3/3】调用 LLM 生成最终审计报告...");
            String markdown = builder.generate();
            boolean success = markdown != null && !markdown.startsWith("ERROR:");
            if (success) {
                addLog(logs, "报告生成完成，浏览器预览已就绪。");
            } else {
                addLog(logs, "报告生成失败，请检查模型配置、网络或本地 LLM 服务状态。");
            }
            return buildResult(success,
                    success ? "报告生成完成" : markdown,
                    markdown,
                    logs,
                    analyzeFirst,
                    usedCache,
                    OneClickAnalyzer.lastDfaFindings.size(),
                    OneClickAnalyzer.lastGadgetCandidates.size(),
                    targetName);
        } catch (Exception ex) {
            addLog(logs, "ERROR: " + ex.getMessage());
            return buildResult(false,
                    ex.getMessage(),
                    "ERROR: " + ex.getMessage(),
                    logs,
                    false,
                    false,
                    OneClickAnalyzer.lastDfaFindings.size(),
                    OneClickAnalyzer.lastGadgetCandidates.size(),
                    "当前项目");
        }
    }

    private void addLog(List<String> logs, String message) {
        if (message != null && !message.trim().isEmpty()) {
            logs.add(message);
        }
    }

    private String buildTargetName(List<String> jars) {
        if (jars == null || jars.isEmpty()) {
            return "当前项目";
        }
        if (jars.size() == 1) {
            return new File(jars.get(0)).getName();
        }
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(jars.size(), 3);
        for (int i = 0; i < limit; i++) {
            if (i > 0) {
                sb.append(" + ");
            }
            sb.append(new File(jars.get(i)).getName());
        }
        if (jars.size() > limit) {
            sb.append(" 等 ").append(jars.size()).append(" 个包");
        }
        return sb.toString();
    }

    private NanoHTTPD.Response buildResult(boolean success,
                                           String message,
                                           String markdown,
                                           List<String> logs,
                                           boolean analyzedNow,
                                           boolean usedCache,
                                           int dfaCount,
                                           int gadgetCount,
                                           String targetName) {
        Map<String, Object> result = new LinkedHashMap<>();
        String safeMarkdown = markdown == null ? "" : markdown;
        String html;
        if (safeMarkdown.isEmpty()) {
            html = MarkdownReportRenderer.renderDocument("# 审计报告预览\n\n当前没有可展示的内容。");
        } else if (safeMarkdown.startsWith("ERROR:")) {
            html = MarkdownReportRenderer.renderDocument("# 审计报告生成失败\n\n```text\n" + safeMarkdown + "\n```");
        } else {
            html = MarkdownReportRenderer.renderDocument(safeMarkdown);
        }
        result.put("success", success);
        result.put("message", message == null ? "" : message);
        result.put("target_name", targetName);
        result.put("markdown", safeMarkdown);
        result.put("html", html);
        result.put("logs", logs == null ? new ArrayList<>() : logs);
        result.put("analyzed_now", analyzedNow);
        result.put("used_cache", usedCache);
        result.put("dfa_count", dfaCount);
        result.put("gadget_count", gadgetCount);
        LatestAuditReportStore.update(html, safeMarkdown, targetName);
        return buildJSON(JSON.toJSONString(result));
    }
}