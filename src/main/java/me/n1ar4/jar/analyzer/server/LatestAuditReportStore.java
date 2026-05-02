/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.server;

public final class LatestAuditReportStore {
    private static volatile String latestHtml = "";
    private static volatile String latestMarkdown = "";
    private static volatile String latestTargetName = "当前项目";
    private static volatile long latestUpdatedAt = 0L;

    private LatestAuditReportStore() {
    }

    public static void update(String html, String markdown, String targetName) {
        latestHtml = html == null ? "" : html;
        latestMarkdown = markdown == null ? "" : markdown;
        latestTargetName = targetName == null || targetName.trim().isEmpty() ? "当前项目" : targetName;
        latestUpdatedAt = System.currentTimeMillis();
    }

    public static String getLatestHtml() {
        return latestHtml;
    }

    public static String getLatestMarkdown() {
        return latestMarkdown;
    }

    public static String getLatestTargetName() {
        return latestTargetName;
    }

    public static long getLatestUpdatedAt() {
        return latestUpdatedAt;
    }

    public static boolean hasReport() {
        return latestHtml != null && !latestHtml.trim().isEmpty();
    }
}