/*
 * GPLv3 License
 */

package me.n1ar4.jar.analyzer.server.handler;

import com.alibaba.fastjson2.JSON;
import me.n1ar4.jar.analyzer.server.ProjectBuildManager;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.server.NanoHTTPD;

import java.util.LinkedHashMap;
import java.util.Map;

public class GetBuildStatusHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        ProjectBuildManager.BuildSnapshot snapshot = ProjectBuildManager.snapshot();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("running", snapshot.isRunning());
        result.put("finished", snapshot.isFinished());
        result.put("build_success", snapshot.isSuccess());
        result.put("progress", snapshot.getProgress());
        result.put("message", snapshot.getMessage());
        result.put("error_message", snapshot.getErrorMessage());
        result.put("source_name", snapshot.getSourceName());
        result.put("source_path", snapshot.getSourcePath());
        result.put("source_type", snapshot.getSourceType());
        result.put("started_at", snapshot.getStartedAt());
        result.put("finished_at", snapshot.getFinishedAt());
        result.put("logs", snapshot.getLogs());
        result.put("engine_ready", snapshot.isEngineReady());
        result.put("db_path", snapshot.getDbPath());
        result.put("db_exists", snapshot.isDbExists());
        result.put("db_size", snapshot.getDbSize());
        return buildJSON(JSON.toJSONString(result));
    }
}