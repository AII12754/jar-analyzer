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

import me.n1ar4.jar.analyzer.dfs.DFSEngine;
import me.n1ar4.jar.analyzer.dfs.DFSResult;
import me.n1ar4.jar.analyzer.engine.CoreEngine;
import me.n1ar4.jar.analyzer.graph.HtmlGraphUtil;
import me.n1ar4.jar.analyzer.graph.TaintGraphRenderEngine;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.jar.analyzer.taint.TaintAnalyzer;
import me.n1ar4.jar.analyzer.taint.TaintResult;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import me.n1ar4.server.NanoHTTPD;

import java.util.ArrayList;
import java.util.List;

public class TaintGraphHandler extends BaseHandler implements HttpHandler {
    private static final Logger logger = LogManager.getLogger();

    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        try {
            CoreEngine engine = MainForm.getEngine();
            if (engine == null || !engine.isEnabled()) {
                return error();
            }

            String sinkClass = getParam(session, "sink_class");
            String sinkMethod = getParam(session, "sink_method");
            String sinkDesc = getParam(session, "sink_method_desc");
            String sourceClass = getParam(session, "source_class");
            String sourceMethod = getParam(session, "source_method");
            String sourceDesc = getParam(session, "source_method_desc");

            boolean fromSink = Boolean.parseBoolean(getParam(session, "from_sink"));
            boolean searchNullSource = Boolean.parseBoolean(getParam(session, "search_null_source"));

            int depth;
            try {
                depth = Integer.parseInt(getParam(session, "depth"));
            } catch (NumberFormatException e) {
                depth = 8;
            }
            int limit;
            try {
                limit = Integer.parseInt(getParam(session, "limit"));
            } catch (NumberFormatException e) {
                limit = 10;
            }

            sinkClass = sinkClass.replace('.', '/');
            sourceClass = sourceClass.replace('.', '/');

            DFSEngine dfsEngine = new DFSEngine(null, fromSink, searchNullSource, depth);
            dfsEngine.setMaxLimit(limit);
            dfsEngine.setSink(sinkClass, sinkMethod, sinkDesc);
            dfsEngine.setSource(sourceClass, sourceMethod, sourceDesc);

            logger.info("taint graph: running DFS analysis");
            dfsEngine.doAnalyze();
            List<DFSResult> dfsResults = dfsEngine.getResults();

            if (dfsResults == null || dfsResults.isEmpty()) {
                String emptyJson = "[]";
                String html = HtmlGraphUtil.renderTaintGraph(emptyJson);
                if (html == null) {
                    return errorMsg("failed to render template");
                }
                return NanoHTTPD.newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", html);
            }

            logger.info("taint graph: running taint analysis on {} chains", dfsResults.size());
            List<TaintResult> taintResults;
            try {
                taintResults = TaintAnalyzer.analyze(dfsResults);
            } catch (Exception ex) {
                logger.warn("taint analysis failed, showing DFS results only: {}", ex.getMessage());
                taintResults = new ArrayList<>();
                for (DFSResult dr : dfsResults) {
                    TaintResult tr = new TaintResult();
                    tr.setDfsResult(dr);
                    tr.setSuccess(false);
                    tr.setTaintText("Taint analysis unavailable: " + ex.getMessage());
                    taintResults.add(tr);
                }
            }

            String chainsJson = TaintGraphRenderEngine.buildChainsJson(taintResults);
            String html = HtmlGraphUtil.renderTaintGraph(chainsJson);
            if (html == null) {
                return errorMsg("failed to render taint graph template");
            }

            return NanoHTTPD.newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "text/html", html);
        } catch (Exception ex) {
            logger.error("taint graph handler error: {}", ex.getMessage());
            return errorMsg(ex.getMessage());
        }
    }

    private String getParam(NanoHTTPD.IHTTPSession session, String name) {
        List<String> p = session.getParameters().get(name);
        if (p == null || p.isEmpty()) {
            return "";
        }
        return p.get(0);
    }
}
