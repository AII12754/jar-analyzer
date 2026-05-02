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

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;
import okhttp3.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * LLM HTTP 客户端
 * <p>
 * 封装对 OpenAI-compatible Chat Completion API 的调用：
 * <ul>
 *   <li>支持任意兼容 OpenAI 接口格式的服务（OpenAI、Azure、Ollama、本地推理服务等）</li>
 *   <li>使用 OkHttp3 发起 HTTP/HTTPS 请求</li>
 *   <li>使用 Fastjson2 序列化请求 / 解析响应</li>
 *   <li>API Key 通过 Authorization: Bearer 头传递</li>
 * </ul>
 * </p>
 *
 * <h3>安全注意事项</h3>
 * <ul>
 *   <li>API Key 仅在内存中持有，不持久化到磁盘</li>
 *   <li>不通过代码记录 API Key 到日志</li>
 *   <li>支持自定义 endpoint，请确保使用 HTTPS</li>
 * </ul>
 */
public class LLMClient {

    private static final Logger logger = LogManager.getLogger();

    private static final MediaType JSON_TYPE = MediaType.parse("application/json; charset=utf-8");

    private final LLMConfig config;
    private final OkHttpClient httpClient;

    public LLMClient(LLMConfig config) {
        this.config = config;
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(config.getTimeoutSeconds(), TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    /**
     * 发送单轮对话请求
     *
     * @param systemPrompt 系统提示词（描述角色和任务）
     * @param userMessage  用户消息（包含待分析的安全数据）
     * @return LLM 返回的文本；失败时返回以 "ERROR:" 开头的错误描述
     */
    public String chatComplete(String systemPrompt, String userMessage) {
        if (!config.isValid()) {
            return "ERROR: LLM 配置不完整，请填写 Endpoint、API Key 和 Model";
        }

        // 构造请求体（OpenAI Chat Completions 格式）
        JSONObject requestBody = new JSONObject();
        requestBody.put("model", config.getModel());
        requestBody.put("max_tokens", config.getMaxTokens());
        requestBody.put("temperature", config.getTemperature());

        JSONArray messages = new JSONArray();
        JSONObject sysMsg = new JSONObject();
        sysMsg.put("role", "system");
        sysMsg.put("content", systemPrompt);
        messages.add(sysMsg);

        JSONObject userMsg = new JSONObject();
        userMsg.put("role", "user");
        userMsg.put("content", userMessage);
        messages.add(userMsg);

        requestBody.put("messages", messages);

        String bodyJson = requestBody.toJSONString();
        RequestBody body = RequestBody.create(bodyJson, JSON_TYPE);

        // 注意：仅记录请求的模型和 endpoint，不记录 API Key 或请求体
        logger.info("LLM 请求: endpoint={}, model={}", config.getEndpoint(), config.getModel());

        Request request = new Request.Builder()
                .url(config.getEndpoint())
                .addHeader("Authorization", "Bearer " + config.getApiKey())
                .addHeader("Content-Type", "application/json")
                .post(body)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errBody = response.body() != null ? response.body().string() : "(no body)";
                logger.error("LLM API 响应错误: HTTP {}, body={}", response.code(), errBody);
                return "ERROR: HTTP " + response.code() + " - " + truncate(errBody, 300);
            }

            String responseBody = response.body() != null ? response.body().string() : "";
            return parseResponse(responseBody);

        } catch (IOException e) {
            logger.error("LLM HTTP 请求失败: {}", e.getMessage());
            return "ERROR: 网络请求失败 - " + e.getMessage();
        }
    }

    /**
     * 解析 OpenAI Chat Completion 响应，提取 assistant 的回复内容
     */
    private String parseResponse(String responseBody) {
        try {
            JSONObject resp = JSON.parseObject(responseBody);
            JSONArray choices = resp.getJSONArray("choices");
            if (choices == null || choices.isEmpty()) {
                return "ERROR: 响应中 choices 为空";
            }
            JSONObject firstChoice = choices.getJSONObject(0);
            JSONObject message = firstChoice.getJSONObject("message");
            if (message == null) {
                return "ERROR: 响应中 message 为空";
            }
            String content = message.getString("content");
            if (content == null) {
                return "ERROR: LLM 返回内容为空";
            }
            return content;
        } catch (Exception e) {
            logger.error("LLM 响应解析失败: {}, body={}", e.getMessage(), truncate(responseBody, 200));
            return "ERROR: 响应解析失败 - " + e.getMessage();
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }
}
