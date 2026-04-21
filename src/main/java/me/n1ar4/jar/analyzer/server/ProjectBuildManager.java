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

import me.n1ar4.jar.analyzer.core.CoreRunner;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.starter.Const;
import me.n1ar4.jar.analyzer.utils.DirUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public final class ProjectBuildManager {
    private static final Object LOCK = new Object();
    private static final int MAX_LOGS = 160;
    private static final LinkedList<String> LOGS = new LinkedList<>();

    private static volatile boolean running;
    private static volatile boolean finished;
    private static volatile boolean success;
    private static volatile int progress;
    private static volatile String message = "等待浏览器发起构建任务。";
    private static volatile String sourceName = "";
    private static volatile String sourcePath = "";
    private static volatile String sourceType = "";
    private static volatile String errorMessage = "";
    private static volatile long startedAt;
    private static volatile long finishedAt;

    private ProjectBuildManager() {
    }

    public static boolean start(Path jarPath,
                                Path rtJarPath,
                                boolean fixClass,
                                boolean quickMode,
                                boolean cleanBeforeBuild,
                                String taskSourceType,
                                String taskSourceName) {
        synchronized (LOCK) {
            if (running) {
                return false;
            }
            resetState(taskSourceType, taskSourceName, jarPath);
            Thread worker = new Thread(() -> runBuild(jarPath, rtJarPath, fixClass, quickMode, cleanBeforeBuild),
                    "browser-project-build");
            worker.setDaemon(true);
            worker.start();
            return true;
        }
    }

    public static BuildSnapshot snapshot() {
        BuildSnapshot snapshot = new BuildSnapshot();
        snapshot.setRunning(running);
        snapshot.setFinished(finished);
        snapshot.setSuccess(success);
        snapshot.setSourceName(sourceName);
        snapshot.setSourcePath(sourcePath);
        snapshot.setSourceType(sourceType);
        snapshot.setProgress(resolveProgress());
        snapshot.setMessage(resolveMessage(snapshot.getProgress()));
        snapshot.setErrorMessage(errorMessage);
        snapshot.setStartedAt(startedAt);
        snapshot.setFinishedAt(finishedAt);
        snapshot.setLogs(copyLogs());
        snapshot.setEngineReady(MainForm.getEngine() != null && MainForm.getEngine().isEnabled());
        snapshot.setDbPath(Const.dbFile);
        snapshot.setDbExists(new File(Const.dbFile).exists());
        snapshot.setDbSize(displayDbSize());
        return snapshot;
    }

    private static void resetState(String taskSourceType, String taskSourceName, Path jarPath) {
        running = true;
        finished = false;
        success = false;
        progress = 0;
        message = "浏览器构建任务已创建。";
        errorMessage = "";
        sourceType = taskSourceType == null ? "" : taskSourceType;
        sourceName = taskSourceName == null ? "" : taskSourceName;
        sourcePath = jarPath == null ? "" : jarPath.toAbsolutePath().toString();
        startedAt = System.currentTimeMillis();
        finishedAt = 0L;
        LOGS.clear();
        addLog("浏览器构建任务已接收: " + sourceName);
    }

    private static void runBuild(Path jarPath,
                                 Path rtJarPath,
                                 boolean fixClass,
                                 boolean quickMode,
                                 boolean cleanBeforeBuild) {
        try {
            if (cleanBeforeBuild) {
                progress = 5;
                message = "正在清理旧数据库和临时目录。";
                addLog(message);
                cleanupPreviousBuild();
            }

            progress = 10;
            message = "开始构建数据库，请稍候。";
            addLog("开始执行 CoreRunner.runBrowser");
            CoreRunner.runBrowser(jarPath, rtJarPath, fixClass, quickMode);

            success = true;
            progress = 100;
            message = "构建完成，分析引擎已刷新。";
            addLog(message);
        } catch (Exception ex) {
            success = false;
            errorMessage = ex.getMessage() == null ? ex.toString() : ex.getMessage();
            message = "构建失败: " + errorMessage;
            addLog(message);
        } finally {
            running = false;
            finished = true;
            finishedAt = System.currentTimeMillis();
            progress = resolveProgress();
        }
    }

    private static void cleanupPreviousBuild() throws Exception {
        Files.deleteIfExists(Paths.get(Const.dbFile));
        DirUtil.removeDir(new File(Const.tempDir));
    }

    private static int resolveProgress() {
        if (MainForm.getInstance() != null && MainForm.getInstance().getBuildBar() != null) {
            int uiValue = MainForm.getInstance().getBuildBar().getValue();
            if (uiValue > progress) {
                progress = uiValue;
            }
        }
        if (success) {
            return 100;
        }
        return progress;
    }

    private static String resolveMessage(int currentProgress) {
        if (running) {
            if (currentProgress >= 100) {
                return "构建完成，等待收尾。";
            }
            if (currentProgress >= 90) {
                return "正在刷新索引与引擎状态。";
            }
            if (currentProgress >= 80) {
                return "正在保存字符串、Spring 与 Web 组件信息。";
            }
            if (currentProgress >= 70) {
                return "正在写入方法调用关系。";
            }
            if (currentProgress >= 60) {
                return "正在处理继承与实现关系。";
            }
            if (currentProgress >= 40) {
                return "正在构建调用图与方法关系。";
            }
            if (currentProgress >= 30) {
                return "正在保存方法与类元信息。";
            }
            if (currentProgress >= 15) {
                return "正在解析 class 并落库。";
            }
        }
        return message;
    }

    private static void addLog(String value) {
        synchronized (LOCK) {
            LOGS.add(String.format("[%tT] %s", System.currentTimeMillis(), value));
            while (LOGS.size() > MAX_LOGS) {
                LOGS.removeFirst();
            }
        }
    }

    private static List<String> copyLogs() {
        synchronized (LOCK) {
            return new ArrayList<>(LOGS);
        }
    }

    private static String displayDbSize() {
        File file = new File(Const.dbFile);
        if (!file.exists()) {
            return "0 MB";
        }
        double fileSizeMB = (double) file.length() / (1024 * 1024);
        return String.format("%.2f MB", fileSizeMB);
    }

    public static final class BuildSnapshot {
        private boolean running;
        private boolean finished;
        private boolean success;
        private int progress;
        private String message;
        private String errorMessage;
        private String sourceName;
        private String sourcePath;
        private String sourceType;
        private long startedAt;
        private long finishedAt;
        private List<String> logs;
        private boolean engineReady;
        private String dbPath;
        private boolean dbExists;
        private String dbSize;

        public boolean isRunning() { return running; }
        public void setRunning(boolean running) { this.running = running; }
        public boolean isFinished() { return finished; }
        public void setFinished(boolean finished) { this.finished = finished; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public int getProgress() { return progress; }
        public void setProgress(int progress) { this.progress = progress; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        public String getSourceName() { return sourceName; }
        public void setSourceName(String sourceName) { this.sourceName = sourceName; }
        public String getSourcePath() { return sourcePath; }
        public void setSourcePath(String sourcePath) { this.sourcePath = sourcePath; }
        public String getSourceType() { return sourceType; }
        public void setSourceType(String sourceType) { this.sourceType = sourceType; }
        public long getStartedAt() { return startedAt; }
        public void setStartedAt(long startedAt) { this.startedAt = startedAt; }
        public long getFinishedAt() { return finishedAt; }
        public void setFinishedAt(long finishedAt) { this.finishedAt = finishedAt; }
        public List<String> getLogs() { return logs; }
        public void setLogs(List<String> logs) { this.logs = logs; }
        public boolean isEngineReady() { return engineReady; }
        public void setEngineReady(boolean engineReady) { this.engineReady = engineReady; }
        public String getDbPath() { return dbPath; }
        public void setDbPath(String dbPath) { this.dbPath = dbPath; }
        public boolean isDbExists() { return dbExists; }
        public void setDbExists(boolean dbExists) { this.dbExists = dbExists; }
        public String getDbSize() { return dbSize; }
        public void setDbSize(String dbSize) { this.dbSize = dbSize; }
    }
}