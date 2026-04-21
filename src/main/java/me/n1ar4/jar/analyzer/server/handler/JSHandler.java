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

import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.jar.analyzer.utils.IOUtil;
import me.n1ar4.server.NanoHTTPD;

import java.io.InputStream;

public class JSHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        String resource = "report/BT_JS.js";
        if ("/static/dashboard.js".equals(session.getUri())) {
            resource = "server/dashboard.js";
        }
        InputStream is = CSSHandler.class.getClassLoader().getResourceAsStream(resource);
        if (is == null) {
            return errorMsg("could not find js resource: " + resource);
        }
        String js = IOUtil.readString(is);
        return NanoHTTPD.newFixedLengthResponse(NanoHTTPD.Response.Status.OK, "text/javascript", js);
    }
}

