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

/**
 * LLM 接入配置
 * <p>
 * 支持任何兼容 OpenAI API 格式的服务端（OpenAI、Azure OpenAI、本地 Ollama、DeepSeek 等）。
 * </p>
 */
public class LLMConfig {

    /** API 终结点，默认为 OpenAI 官方地址 */
    private String endpoint = "https://api.openai.com/v1/chat/completions";

    /** API Key（Bearer 认证） */
    private String apiKey = "";

    /** 模型名称 */
    private String model = "gpt-4o-mini";

    /** 请求超时（秒）*/
    private int timeoutSeconds = 120;

    /** 最大 token 数 */
    private int maxTokens = 4096;

    /** 温度参数 [0.0, 2.0] */
    private double temperature = 0.3;

    public LLMConfig() {
    }

    public LLMConfig(String endpoint, String apiKey, String model) {
        this.endpoint = endpoint;
        this.apiKey = apiKey;
        this.model = model;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }

    public double getTemperature() {
        return temperature;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public boolean isValid() {
        return endpoint != null && !endpoint.trim().isEmpty()
                && apiKey != null && !apiKey.trim().isEmpty()
                && model != null && !model.trim().isEmpty();
    }
}
