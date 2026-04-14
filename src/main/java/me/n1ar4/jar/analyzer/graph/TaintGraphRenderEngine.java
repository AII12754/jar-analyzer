/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.graph;

import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.taint.TaintResult;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class TaintGraphRenderEngine {
    private static final Logger logger = LogManager.getLogger();

    private static String getShortClassName(String fullClassName) {
        if (fullClassName == null) return "";
        fullClassName = fullClassName.replace("/", ".");
        return fullClassName.substring(fullClassName.lastIndexOf('.') + 1);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public static String buildChainsJson(List<TaintResult> taintResults) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int c = 0; c < taintResults.size(); c++) {
            TaintResult tr = taintResults.get(c);
            if (c > 0) sb.append(",");
            sb.append("{");
            sb.append("\"tainted\":").append(tr.isSuccess()).append(",");
            sb.append("\"depth\":").append(tr.getDfsResult().getDepth()).append(",");
            sb.append("\"taintText\":\"").append(escapeJson(tr.getTaintText())).append("\",");
            sb.append("\"methods\":[");
            List<MethodReference.Handle> methods = tr.getDfsResult().getMethodList();
            if (methods != null) {
                for (int i = 0; i < methods.size(); i++) {
                    MethodReference.Handle m = methods.get(i);
                    if (i > 0) sb.append(",");
                    String className = m.getClassReference() != null
                            ? m.getClassReference().getName() : "";
                    String taintStatus;
                    if (i == 0) {
                        taintStatus = "source";
                    } else if (i == methods.size() - 1) {
                        taintStatus = "sink";
                    } else {
                        taintStatus = tr.isSuccess() ? "tainted" : "clean";
                    }
                    sb.append("{");
                    sb.append("\"className\":\"").append(escapeJson(className)).append("\",");
                    sb.append("\"methodName\":\"").append(escapeJson(m.getName())).append("\",");
                    sb.append("\"methodDesc\":\"").append(escapeJson(m.getDesc())).append("\",");
                    sb.append("\"taintStatus\":\"").append(taintStatus).append("\"");
                    sb.append("}");
                }
            }
            sb.append("]}");
        }
        sb.append("]");
        return sb.toString();
    }

    public static String processGraph(List<TaintResult> taintResults) {
        String chainsJson = buildChainsJson(taintResults);
        String html = HtmlGraphUtil.renderTaintGraph(chainsJson);
        if (html == null) {
            logger.error("failed to render taint graph");
            return null;
        }
        try {
            String fileName = String.format("jar-analyzer-taint-%d.html", System.currentTimeMillis());
            Files.write(Paths.get(fileName), html.getBytes());
            return fileName;
        } catch (Exception ex) {
            logger.error("failed to write taint graph file: {}", ex.getMessage());
        }
        return null;
    }
}
