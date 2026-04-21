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

import me.n1ar4.jar.analyzer.report.MarkdownReportRenderer;
import me.n1ar4.jar.analyzer.server.LatestAuditReportStore;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.server.NanoHTTPD;

public class GetLatestAuditReportPageHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        String html = LatestAuditReportStore.getLatestHtml();
        if (html == null || html.trim().isEmpty()) {
            html = MarkdownReportRenderer.renderDocument(
                    "# 审计报告预览\n\n当前还没有生成独立报告。\n\n请先回到主页面执行报告生成，然后再打开这个页面。");
        }
        NanoHTTPD.Response response = NanoHTTPD.newFixedLengthResponse(
                NanoHTTPD.Response.Status.OK, "text/html", html);
        response.addHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.addHeader("Pragma", "no-cache");
        return response;
    }
}