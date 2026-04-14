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

import me.n1ar4.jar.analyzer.gui.GlobalOptions;
import me.n1ar4.jar.analyzer.server.handler.CSSHandler;
import me.n1ar4.jar.analyzer.utils.IOUtil;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;

import java.io.InputStream;

public class HtmlGraphUtil {
    private static final Logger logger = LogManager.getLogger();

    private static final String D3DS_STR = "__D3JS__";
    private static final String NODES_STR = "__NODES__";
    private static final String LINKS_STR = "__LINKS__";
    private static final String CURRENT_STR = "__CURRENT_NODE__";
    private static final String PORT_STR = "__PORT__";
    private static final String CHAINS_DATA_STR = "__CHAINS_DATA__";

    private static String getTemplate() {
        InputStream is = CSSHandler.class.getClassLoader().getResourceAsStream("graph-interactive.html.temp");
        if (is == null) {
            is = CSSHandler.class.getClassLoader().getResourceAsStream("graph.html.temp");
        }
        if (is == null) {
            return null;
        }
        return IOUtil.readString(is);
    }

    private static String getTaintTemplate() {
        InputStream is = CSSHandler.class.getClassLoader().getResourceAsStream("taint-graph.html.temp");
        if (is == null) {
            return null;
        }
        return IOUtil.readString(is);
    }

    public static String render(GraphData data) {
        String temp = getTemplate();
        if (temp == null) {
            logger.error("templates is null");
            return null;
        }

        int port = GlobalOptions.getServerConfig().getPort();
        String d3dsPath = String.format("http://127.0.0.1:%d/static/d3v6.js", port);
        String htmlOutput = temp.replace(D3DS_STR, d3dsPath);
        // 示例：
        // 注意单引号逗号结尾有换行
        //    { id: 'A', name: 'Method A' },
        //    { id: 'B', name: 'Method B' },
        htmlOutput = htmlOutput.replace(NODES_STR, data.getNodes());
        // 示例：
        // 注意单引号逗号结尾有换行
        //    { source: 'A', target: 'B' },
        //    { source: 'A', target: 'C' },
        htmlOutput = htmlOutput.replace(LINKS_STR, data.getLinks());
        // 示例：
        // 注意无需有引号
        // A
        htmlOutput = htmlOutput.replace(CURRENT_STR, data.getCurrentNodeId());
        htmlOutput = htmlOutput.replace(PORT_STR, String.valueOf(port));

        return htmlOutput;
    }

    public static String renderTaintGraph(String chainsJson) {
        String temp = getTaintTemplate();
        if (temp == null) {
            logger.error("taint graph template is null");
            return null;
        }
        int port = GlobalOptions.getServerConfig().getPort();
        String d3dsPath = String.format("http://127.0.0.1:%d/static/d3v6.js", port);
        String htmlOutput = temp.replace(D3DS_STR, d3dsPath);
        htmlOutput = htmlOutput.replace(CHAINS_DATA_STR, chainsJson);
        return htmlOutput;
    }
}
