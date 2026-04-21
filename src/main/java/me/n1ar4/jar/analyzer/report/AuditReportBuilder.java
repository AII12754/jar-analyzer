/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.report;

import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.gadget.auto.model.ChainCandidate;
import me.n1ar4.jar.analyzer.taint.TaintCache;
import me.n1ar4.jar.analyzer.taint.TaintResult;
import me.n1ar4.jar.analyzer.taint.dfa.DFAEngine;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 审计报告生成器
 * <p>
 * 工作流程：
 * <ol>
 *   <li>收集当前分析会话的所有安全发现（DFS 链、污点分析结果、DFA 路径、反序列化链候选）</li>
 *   <li>将发现整合为结构化的安全摘要文本（Markdown 格式）</li>
 *   <li>调用 {@link LLMClient} 将摘要发送给 LLM，请求生成专业安全报告</li>
 *   <li>返回 LLM 生成的报告文本（Markdown 或 HTML 格式）</li>
 * </ol>
 * </p>
 */
public class AuditReportBuilder {

    private static final Logger logger = LogManager.getLogger();

    /** 系统提示词：定义 LLM 角色 */
    private static final String SYSTEM_PROMPT =
            "你是一位专业的 Java 安全审计专家，擅长分析反序列化漏洞、SQL 注入、XSS、JNDI 注入等常见 Java 安全问题。\n" +
            "用户将提供来自 jar-analyzer 工具的静态分析结果，包括调用链、污点传播路径、反序列化利用链候选等。\n" +
            "请你：\n" +
            "1. 对每个安全发现进行风险评级（严重/高/中/低）\n" +
            "2. 解释漏洞的技术原理\n" +
            "3. 提供具体的修复建议（包含代码示例）\n" +
            "4. 生成一份格式化的 Markdown 安全审计报告\n\n" +
            "报告结构为：\n" +
            "# Java 安全审计报告\n" +
            "## 执行摘要\n" +
            "## 发现的安全问题（按严重程度排序）\n" +
            "### [严重程度] 漏洞名称\n" +
            "- 技术分析\n" +
            "- 受影响代码路径\n" +
            "- 修复建议\n" +
            "## 总体安全评分\n" +
            "## 修复优先级建议\n";

    private final LLMConfig config;
    private List<DFAEngine.DFAFinding> dfaFindings;
    private List<ChainCandidate> gadgetCandidates;
    private String targetJarName = "未知";

    public AuditReportBuilder(LLMConfig config) {
        this.config = config;
    }

    public void setDfaFindings(List<DFAEngine.DFAFinding> dfaFindings) {
        this.dfaFindings = dfaFindings;
    }

    public void setGadgetCandidates(List<ChainCandidate> gadgetCandidates) {
        this.gadgetCandidates = gadgetCandidates;
    }

    public void setTargetJarName(String name) {
        this.targetJarName = name;
    }

    /**
     * 执行报告生成
     *
     * @return 生成的报告文本（Markdown）；发生错误时返回以 "ERROR:" 开头的字符串
     */
    public String generate() {
        logger.info("开始生成 LLM 安全审计报告...");

        String summary = buildFindingsSummary();
        logger.info("安全发现摘要已构建，长度: {} 字符", summary.length());

        LLMClient client = new LLMClient(config);
        String report = client.chatComplete(SYSTEM_PROMPT, summary);

        if (report.startsWith("ERROR:")) {
            logger.error("LLM 报告生成失败: {}", report);
        } else {
            logger.info("LLM 安全审计报告生成完成，长度 {} 字符", report.length());
        }
        return report;
    }

    /**
     * 将所有安全发现整合为提交给 LLM 的结构化摘要文本
     */
    String buildFindingsSummary() {
        StringBuilder sb = new StringBuilder();
        String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("# jar-analyzer 静态分析结果摘要\n\n");
        sb.append("**分析目标**: ").append(targetJarName).append("\n");
        sb.append("**分析时间**: ").append(date).append("\n\n");

        // 1. 过程间 DFA 数据流分析结果
        appendDFAFindings(sb);

        // 2. DFS 漏洞链 + 污点分析结果（从 TaintCache 获取）
        appendTaintFindings(sb);

        // 3. 反序列化利用链候选
        appendGadgetFindings(sb);

        sb.append("\n---\n");
        sb.append("请根据以上分析结果生成专业的安全审计报告，重点关注高危发现并提供可操作的修复建议。\n");

        return sb.toString();
    }

    private void appendDFAFindings(StringBuilder sb) {
        sb.append("## 一、过程间数据流分析（DFA）发现\n\n");
        if (dfaFindings == null || dfaFindings.isEmpty()) {
            sb.append("（无 DFA 分析结果，请先运行过程间 DFA 分析）\n\n");
            return;
        }
        sb.append("共发现 **").append(dfaFindings.size()).append("** 条潜在污点路径：\n\n");
        int idx = 1;
        for (DFAEngine.DFAFinding f : dfaFindings) {
            if (idx > 30) {
                sb.append("... 还有 ").append(dfaFindings.size() - 30).append(" 条（已截断）\n\n");
                break;
            }
            sb.append("### DFA-").append(idx++).append(": ").append(f.getSinkDescription()).append("\n");
            sb.append("- **Sink**: `").append(f.getSinkClass()).append("#").append(f.getSinkMethod()).append("`\n");
            sb.append("- **Source**: `").append(f.getSourceMethod()).append("`\n");
            sb.append("- **路径深度**: ").append(f.getPathDepth()).append("\n");
            sb.append("- **传播链**: `").append(f.toSummary()).append("`\n");
            // 详细路径（最多10步）
            List<MethodResult> path = f.getPath();
            if (path != null && !path.isEmpty()) {
                sb.append("- **详细路径**:\n");
                for (int i = 0; i < Math.min(path.size(), 10); i++) {
                    MethodResult m = path.get(i);
                    sb.append("  ").append(i + 1).append(". `")
                            .append(m.getClassName()).append("#").append(m.getMethodName()).append("`\n");
                }
                if (path.size() > 10) {
                    sb.append("  ...（共 ").append(path.size()).append(" 步）\n");
                }
            }
            sb.append("\n");
        }
    }

    private void appendTaintFindings(StringBuilder sb) {
        List<TaintResult> taintResults = new ArrayList<>(TaintCache.cache);
        sb.append("## 二、DFS + 污点分析结果\n\n");
        if (taintResults == null || taintResults.isEmpty()) {
            sb.append("（无污点分析结果，请先运行 chains 模块的 DFS + 污点分析）\n\n");
            return;
        }
        sb.append("共发现 **").append(taintResults.size()).append("** 条污点传播路径：\n\n");
        int idx = 1;
        for (TaintResult r : taintResults) {
            if (idx > 20) {
                sb.append("... 还有 ").append(taintResults.size() - 20).append(" 条（已截断）\n\n");
                break;
            }
            sb.append("### TAINT-").append(idx++).append(":\n");
            // TaintResult 为路径格式，使用 toString 或 getText
            String text = r.getTaintText();
            if (text != null && !text.isEmpty()) {
                // 截取前 500 字符
                String preview = text.length() > 500 ? text.substring(0, 500) + "..." : text;
                sb.append("```\n").append(preview).append("\n```\n\n");
            }
        }
    }

    private void appendGadgetFindings(StringBuilder sb) {
        sb.append("## 三、反序列化利用链候选\n\n");
        if (gadgetCandidates == null || gadgetCandidates.isEmpty()) {
            sb.append("（无利用链候选，请先运行反序列化利用链自动挖掘）\n\n");
            return;
        }
        sb.append("共发现 **").append(gadgetCandidates.size()).append("** 条候选利用链：\n\n");
        int idx = 1;
        for (ChainCandidate c : gadgetCandidates) {
            if (idx > 20) {
                sb.append("... 还有 ").append(gadgetCandidates.size() - 20).append(" 条（已截断）\n\n");
                break;
            }
            sb.append("### GADGET-").append(idx++).append(": ").append(c.getSinkDescription()).append("\n");
            sb.append("- **触发类**: `").append(c.getTriggerClass()).append("`\n");
            sb.append("- **触发方法**: `").append(c.getTriggerMethod()).append("`\n");
            sb.append("- **Sink**: `").append(c.getSinkClass()).append("#").append(c.getSinkMethod()).append("`\n");
            sb.append("- **链深度**: ").append(c.getDepth()).append("\n");
            sb.append("- **调用链摘要**: `").append(c.toSummary()).append("`\n\n");
        }
    }
}
