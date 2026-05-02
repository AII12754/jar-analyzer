/*
 * GPLv3 License
 */

package me.n1ar4.jar.analyzer.server.handler;

import me.n1ar4.jar.analyzer.engine.CoreEngine;
import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.graph.RenderEngine;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.jar.analyzer.utils.StringUtil;
import me.n1ar4.server.NanoHTTPD;

import java.util.List;

public class MethodGraphHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        CoreEngine engine = MainForm.getEngine();
        if (engine == null || !engine.isEnabled()) {
            return error();
        }
        String className = getClassName(session);
        String methodName = getMethodName(session);
        String methodDesc = getMethodDesc(session);
        if (StringUtil.isNull(className)) {
            return needParam("class");
        }
        if (StringUtil.isNull(methodName)) {
            return needParam("method");
        }

        MethodResult current = new MethodResult(className, methodName, methodDesc);
        List<MethodResult> callers = engine.getCallers(className, methodName, methodDesc);
        List<MethodResult> callees = engine.getCallee(className, methodName, methodDesc);
        String html = RenderEngine.renderHtml(current, callers, callees);
        if (html == null) {
            return errorMsg("failed to render method graph");
        }
        return NanoHTTPD.newFixedLengthResponse(NanoHTTPD.Response.Status.OK, "text/html", html);
    }
}