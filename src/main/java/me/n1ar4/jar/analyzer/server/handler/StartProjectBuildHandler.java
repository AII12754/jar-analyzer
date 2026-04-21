/*
 * GPLv3 License
 */

package me.n1ar4.jar.analyzer.server.handler;

import com.alibaba.fastjson2.JSON;
import me.n1ar4.jar.analyzer.server.ProjectBuildManager;
import me.n1ar4.jar.analyzer.server.handler.base.BaseHandler;
import me.n1ar4.jar.analyzer.server.handler.base.HttpHandler;
import me.n1ar4.jar.analyzer.starter.Const;
import me.n1ar4.server.NanoHTTPD;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class StartProjectBuildHandler extends BaseHandler implements HttpHandler {
    @Override
    public NanoHTTPD.Response handle(NanoHTTPD.IHTTPSession session) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (!"POST".equalsIgnoreCase(session.getMethod())) {
            result.put("success", false);
            result.put("message", "start_project_build 仅支持 POST");
            return buildJSON(JSON.toJSONString(result));
        }

        try {
            String sourcePath = getParam(session, "source_path");
            boolean fixClass = Boolean.parseBoolean(getParam(session, "fix_class", "false"));
            boolean quickMode = Boolean.parseBoolean(getParam(session, "quick_mode", "false"));
            boolean cleanBeforeBuild = Boolean.parseBoolean(getParam(session, "clean_before_build", "true"));
            String rtJarPath = getParam(session, "rt_jar_path");

            Path jarPath;
            String sourceType;
            String sourceName;
            if (!sourcePath.isEmpty()) {
                jarPath = Paths.get(sourcePath).toAbsolutePath();
                if (!Files.exists(jarPath)) {
                    result.put("success", false);
                    result.put("message", "source_path 不存在: " + jarPath);
                    return buildJSON(JSON.toJSONString(result));
                }
                sourceType = "server-path";
                sourceName = jarPath.getFileName() == null ? jarPath.toString() : jarPath.getFileName().toString();
            } else {
                byte[] body = readBodyBytes(session);
                String fileName = getHeader(session, "X-File-Name");
                if (body.length == 0 || fileName.isEmpty()) {
                    result.put("success", false);
                    result.put("message", "请提供 source_path，或使用原始二进制上传并带上 X-File-Name Header。");
                    return buildJSON(JSON.toJSONString(result));
                }
                Path uploadDir = Paths.get(Const.downDir, "browser-upload");
                Files.createDirectories(uploadDir);
                String safeName = fileName.replace('\\', '_').replace('/', '_');
                jarPath = uploadDir.resolve(System.currentTimeMillis() + "-" + safeName).toAbsolutePath();
                Files.write(jarPath, body);
                sourceType = "upload";
                sourceName = safeName;
            }

            Path rtPath = rtJarPath.isEmpty() ? null : Paths.get(rtJarPath).toAbsolutePath();
            if (rtPath != null && !Files.exists(rtPath)) {
                result.put("success", false);
                result.put("message", "rt_jar_path 不存在: " + rtPath);
                return buildJSON(JSON.toJSONString(result));
            }

            boolean started = ProjectBuildManager.start(jarPath, rtPath, fixClass, quickMode,
                    cleanBeforeBuild, sourceType, sourceName);
            result.put("success", started);
            result.put("started", started);
            result.put("source_type", sourceType);
            result.put("source_name", sourceName);
            result.put("source_path", jarPath.toString());
            result.put("message", started
                    ? "浏览器构建任务已启动，请轮询 /api/build_status 查看进度。"
                    : "当前已有构建任务在执行，请稍后重试。");
            return buildJSON(JSON.toJSONString(result));
        } catch (Exception ex) {
            result.put("success", false);
            result.put("message", ex.getMessage());
            return buildJSON(JSON.toJSONString(result));
        }
    }
}