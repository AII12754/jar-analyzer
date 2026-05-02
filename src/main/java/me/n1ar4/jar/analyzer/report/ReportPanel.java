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

import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.oneclick.OneClickAnalyzer;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * LLM 安全审计报告生成面板
 * <p>
 * 通过 {@link #show()} 打开对话框，提供以下功能：
 * <ul>
 *   <li>填写 LLM API 配置（Endpoint / API Key / 模型名）</li>
 *   <li>在当前页一键分析整个项目并生成审计报告</li>
 *   <li>内置网页化预览页，支持目录导航、风险摘要卡片</li>
 *   <li>导出报告到 .md 文件</li>
 *   <li>导出报告到 .html 文件并在浏览器中打开</li>
 *   <li>复制全文到剪贴板</li>
 * </ul>
 * </p>
 */
public class ReportPanel extends JDialog {

    private JTextField endpointField;
    private JPasswordField apiKeyField;
    private JTextField modelField;
    private JButton analyzeAndGenerateBtn;
    private JButton generateBtn;
    private JButton exportBtn;
    private JButton exportHtmlBtn;
    private JButton browserBtn;
    private JButton copyBtn;
    private JLabel statusLabel;
    private JLabel cacheStatusLabel;
    private JTextArea analysisLogArea;
    private JTextArea markdownArea;
    private JEditorPane previewPane;
    private String currentMarkdown = "";
    private String currentHtml = "";

    public ReportPanel(JFrame parent) {
        super(parent, "LLM 智能安全审计报告生成", false);
        initUI();
        setSize(1360, 880);
        setLocationRelativeTo(parent);
    }

    public static void openDialog() {
        JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(
                MainForm.getInstance().getMasterPanel());
        ReportPanel dialog = new ReportPanel(frame);
        dialog.setVisible(true);
    }

    private void initUI() {
        setLayout(new BorderLayout(5, 5));

        // ---- 顶部 LLM 配置区 ----
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("LLM 接口配置"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("API Endpoint:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        endpointField = new JTextField("https://api.openai.com/v1/chat/completions", 50);
        configPanel.add(endpointField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        configPanel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(50);
        apiKeyField.setToolTipText("API Key，不会被记录到日志或持久化到磁盘");
        configPanel.add(apiKeyField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        configPanel.add(new JLabel("模型名称:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        modelField = new JTextField("gpt-4o-mini", 30);
        configPanel.add(modelField, gbc);

        // 按钮行
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        analyzeAndGenerateBtn = new JButton("★ 一键分析整个项目并生成报告");
        analyzeAndGenerateBtn.setBackground(new Color(197, 98, 32));
        analyzeAndGenerateBtn.setForeground(Color.WHITE);
        generateBtn = new JButton("生成审计报告");
        generateBtn.setBackground(new Color(50, 140, 50));
        generateBtn.setForeground(Color.WHITE);
        exportBtn = new JButton("导出 .md 文件");
        exportBtn.setEnabled(false);
        exportHtmlBtn = new JButton("导出 .html 文件");
        exportHtmlBtn.setEnabled(false);
        browserBtn = new JButton("浏览器预览");
        browserBtn.setEnabled(false);
        copyBtn = new JButton("复制到剪贴板");
        copyBtn.setEnabled(false);
        statusLabel = new JLabel("就绪");
        statusLabel.setForeground(Color.GRAY);
        btnRow.add(analyzeAndGenerateBtn);
        btnRow.add(generateBtn);
        btnRow.add(exportBtn);
        btnRow.add(exportHtmlBtn);
        btnRow.add(browserBtn);
        btnRow.add(copyBtn);
        btnRow.add(new JSeparator(SwingConstants.VERTICAL));
        btnRow.add(statusLabel);
        configPanel.add(btnRow, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        cacheStatusLabel = new JLabel();
        cacheStatusLabel.setForeground(new Color(90, 90, 90));
        configPanel.add(cacheStatusLabel, gbc);

        add(configPanel, BorderLayout.NORTH);

        // ---- 提示区 ----
        JPanel hintPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel hint = new JLabel("<html><b>数据来源</b>：报告将自动聚合 chains 模块的 DFS+污点分析、" +
                "过程间DFA分析、反序列化利用链挖掘的全部结果，发送给 LLM 进行智能分析。" +
                "<br/>支持任何兼容 OpenAI API 格式的服务，如 OpenAI、Azure、Ollama、DeepSeek 等。</html>");
        hint.setForeground(new Color(80, 80, 160));
        hintPanel.add(hint);
        add(hintPanel, BorderLayout.SOUTH);

        JPanel analysisPanel = new JPanel(new BorderLayout(6, 6));
        analysisPanel.setBorder(BorderFactory.createTitledBorder("项目分析控制台"));
        JLabel analysisHint = new JLabel("<html><b>推荐入口</b>：点击上方“★ 一键分析整个项目并生成报告”，系统会在当前页依次执行 DFA、利用链挖掘和 LLM 报告生成。</html>");
        analysisHint.setForeground(new Color(60, 60, 90));
        analysisPanel.add(analysisHint, BorderLayout.NORTH);

        analysisLogArea = new JTextArea();
        analysisLogArea.setEditable(false);
        analysisLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        analysisLogArea.setBackground(new Color(28, 32, 35));
        analysisLogArea.setForeground(new Color(186, 248, 198));
        analysisLogArea.setText("等待操作中...\n");
        analysisPanel.add(new JScrollPane(analysisLogArea), BorderLayout.CENTER);

        // ---- 报告内容区 ----
        markdownArea = new JTextArea();
        markdownArea.setEditable(false);
        markdownArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        markdownArea.setLineWrap(true);
        markdownArea.setWrapStyleWord(true);
        JScrollPane markdownScroll = new JScrollPane(markdownArea);

        previewPane = new JEditorPane();
        previewPane.setEditable(false);
        previewPane.setContentType("text/html");
        previewPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        previewPane.addHyperlinkListener(this::onPreviewLinkActivated);
        previewPane.setCaretPosition(0);
        JScrollPane previewScroll = new JScrollPane(previewPane);

        JTabbedPane reportTabs = new JTabbedPane();
        reportTabs.addTab("网页预览", previewScroll);
        reportTabs.addTab("Markdown 源文", markdownScroll);
        reportTabs.setBorder(BorderFactory.createTitledBorder("审计报告"));

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, analysisPanel, reportTabs);
        centerSplit.setResizeWeight(0.28);
        add(centerSplit, BorderLayout.CENTER);

        // ---- 事件绑定 ----
        analyzeAndGenerateBtn.addActionListener(e -> onAnalyzeAndGenerate());
        generateBtn.addActionListener(e -> onGenerate());
        exportBtn.addActionListener(e -> onExport());
        exportHtmlBtn.addActionListener(e -> onExportHtml());
        browserBtn.addActionListener(e -> onOpenInBrowser());
        copyBtn.addActionListener(e -> onCopy());

        updateCacheStatusLabel();
        setReportContent(buildWelcomeMarkdown());
    }

    private void onAnalyzeAndGenerate() {
        if (!validateConfig()) {
            return;
        }

        analysisLogArea.setText("");
        appendAnalysisLog("准备开始一键分析整个项目并生成报告...");
        setBusyState("正在执行项目分析并生成报告...", "# 正在执行整项目分析并生成报告\n\n"
                + "- 阶段 1：过程间 DFA\n"
                + "- 阶段 2：反序列化利用链挖掘\n"
                + "- 阶段 3：调用 LLM 生成最终报告\n\n"
                + "请在左侧控制台查看实时进度。\n");

        LLMConfig config = buildConfig();
        new Thread(() -> {
            try {
                OneClickAnalyzer.AnalysisResult analysisResult = OneClickAnalyzer.analyzeProject(this::appendAnalysisLog);
                appendAnalysisLog("");
                appendAnalysisLog("【阶段 3/3】开始调用 LLM 生成审计报告...");
                AuditReportBuilder builder = createReportBuilder(config, analysisResult);
                String report = builder.generate();
                appendAnalysisLog(report.startsWith("ERROR:") ? "✘ 报告生成失败" : "✔ 报告生成完成，正在刷新网页预览...");
                applyReportGenerationResult(report);
            } catch (Exception ex) {
                appendAnalysisLog("ERROR: " + ex.getMessage());
                applyReportGenerationResult("ERROR: " + ex.getMessage());
            }
        }, "report-page-analyze-generate").start();
    }

    private void onGenerate() {
        if (!validateConfig()) {
            return;
        }

        appendAnalysisLog("开始基于当前缓存结果生成审计报告...");
        if (!OneClickAnalyzer.hasRun) {
            appendAnalysisLog("提示：未检测到一键分析缓存，本次将使用当前已存在的 DFS/污点数据以及任何已缓存的结果。\n"
                    + "如果希望自动补齐 DFA 和利用链结果，请点击上方“★ 一键分析整个项目并生成报告”。");
        }
        setBusyState("正在生成报告，请稍候...", "# 正在生成审计报告\n\n请稍候，系统正在汇总分析结果并请求 LLM。\n");

        LLMConfig config = buildConfig();

        new Thread(() -> {
            try {
                AuditReportBuilder builder = createReportBuilder(config, null);
                String report = builder.generate();
                appendAnalysisLog(report.startsWith("ERROR:") ? "✘ 报告生成失败" : "✔ 报告生成完成");
                applyReportGenerationResult(report);
            } catch (Exception ex) {
                appendAnalysisLog("ERROR: " + ex.getMessage());
                applyReportGenerationResult("ERROR: " + ex.getMessage());
            }
        }, "ReportGenerator-Thread").start();
    }

    private void onExport() {
        if (currentMarkdown == null || currentMarkdown.isEmpty()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("security-audit-report.md"));
        int result = chooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                Files.write(file.toPath(), currentMarkdown.getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "报告已导出到: " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage(), "错误",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onExportHtml() {
        if (currentHtml == null || currentHtml.isEmpty()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("security-audit-report.html"));
        int result = chooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                Files.write(file.toPath(), currentHtml.getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "HTML 报告已导出到: " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "导出失败: " + ex.getMessage(), "错误",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onOpenInBrowser() {
        if (currentHtml == null || currentHtml.isEmpty()) {
            return;
        }
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            JOptionPane.showMessageDialog(this, "当前环境不支持浏览器预览，请改用导出 HTML 文件。", "提示",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        try {
            File tempFile = File.createTempFile("jar-analyzer-report-", ".html");
            tempFile.deleteOnExit();
            Files.write(tempFile.toPath(), currentHtml.getBytes(StandardCharsets.UTF_8));
            Desktop.getDesktop().browse(tempFile.toURI());
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "打开浏览器失败: " + ex.getMessage(), "错误",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onCopy() {
        String text = currentMarkdown;
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
            statusLabel.setText("已复制到剪贴板");
            statusLabel.setForeground(new Color(0, 150, 0));
        }
    }

    private void onPreviewLinkActivated(HyperlinkEvent event) {
        if (event.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
            return;
        }
        if (event.getDescription() != null && event.getDescription().startsWith("#")) {
            previewPane.scrollToReference(event.getDescription().substring(1));
            return;
        }
        if (event.getURL() != null && Desktop.isDesktopSupported()
                && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            try {
                Desktop.getDesktop().browse(event.getURL().toURI());
            } catch (Exception ignored) {
            }
        }
    }

    private boolean validateConfig() {
        if (endpointField.getText().trim().isEmpty()
                || new String(apiKeyField.getPassword()).trim().isEmpty()
                || modelField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "请填写完整的 API 配置（Endpoint / API Key / 模型名）");
            return false;
        }
        return true;
    }

    private LLMConfig buildConfig() {
        return new LLMConfig(
                endpointField.getText().trim(),
                new String(apiKeyField.getPassword()).trim(),
                modelField.getText().trim());
    }

    private AuditReportBuilder createReportBuilder(LLMConfig config,
                                                   OneClickAnalyzer.AnalysisResult analysisResult) {
        AuditReportBuilder builder = new AuditReportBuilder(config);
        if (MainForm.getInstance() != null) {
            builder.setTargetJarName("当前已加载 JAR");
        }
        if (analysisResult != null) {
            builder.setDfaFindings(analysisResult.getDfaFindings());
            builder.setGadgetCandidates(analysisResult.getGadgetCandidates());
            return builder;
        }
        if (OneClickAnalyzer.hasRun) {
            builder.setDfaFindings(OneClickAnalyzer.lastDfaFindings);
            builder.setGadgetCandidates(OneClickAnalyzer.lastGadgetCandidates);
        }
        return builder;
    }

    private void setBusyState(String statusText, String previewMarkdown) {
        analyzeAndGenerateBtn.setEnabled(false);
        generateBtn.setEnabled(false);
        exportBtn.setEnabled(false);
        exportHtmlBtn.setEnabled(false);
        browserBtn.setEnabled(false);
        copyBtn.setEnabled(false);
        statusLabel.setText(statusText);
        statusLabel.setForeground(new Color(0, 100, 200));
        setReportContent(previewMarkdown);
    }

    private void applyReportGenerationResult(String report) {
        SwingUtilities.invokeLater(() -> {
            setReportContent(report);
            boolean success = report != null && !report.startsWith("ERROR:");
            statusLabel.setText(success ? "报告生成完成（" + report.length() + " 字符）" : "生成失败，请检查配置或网络");
            statusLabel.setForeground(success ? new Color(0, 150, 0) : Color.RED);
            analyzeAndGenerateBtn.setEnabled(true);
            generateBtn.setEnabled(true);
            exportBtn.setEnabled(success);
            exportHtmlBtn.setEnabled(success);
            browserBtn.setEnabled(success);
            copyBtn.setEnabled(success);
            updateCacheStatusLabel();
        });
    }

    private void setReportContent(String markdown) {
        currentMarkdown = markdown == null ? "" : markdown;
        currentHtml = renderPreview(currentMarkdown);
        markdownArea.setText(currentMarkdown);
        markdownArea.setCaretPosition(0);
        previewPane.setText(currentHtml);
        previewPane.setCaretPosition(0);
    }

    private void appendAnalysisLog(String message) {
        if (message == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            analysisLogArea.append(message + "\n");
            analysisLogArea.setCaretPosition(analysisLogArea.getDocument().getLength());
        });
    }

    private void updateCacheStatusLabel() {
        String text;
        if (OneClickAnalyzer.hasRun) {
            text = "<html><b>缓存状态：</b>已检测到最近一次一键分析结果，DFA "
                    + OneClickAnalyzer.lastDfaFindings.size() + " 条，利用链 "
                    + OneClickAnalyzer.lastGadgetCandidates.size()
                    + " 条。现在可以直接点击“生成审计报告”复用缓存，也可以重新执行整项目分析。</html>";
        } else {
            text = "<html><b>缓存状态：</b>尚未检测到一键分析缓存。你可以直接生成报告，也可以点击“★ 一键分析整个项目并生成报告”让系统先自动跑完整分析。</html>";
        }
        cacheStatusLabel.setText(text);
    }

    private String buildWelcomeMarkdown() {
        return "# LLM 智能安全审计报告页\n\n"
                + "这个页面现在已经是一个完整的报告工作台，而不只是 Markdown 文本框。\n\n"
                + "## 推荐工作流\n\n"
                + "1. 在上方填写 API Endpoint、API Key 和模型名称\n"
                + "2. 点击 **★ 一键分析整个项目并生成报告**\n"
                + "3. 在左侧控制台查看 DFA、利用链挖掘和报告生成进度\n"
                + "4. 在右侧直接查看网页化审计报告，支持目录导航和风险卡片\n\n"
                + "## 当前支持\n\n"
                + "- 面板内网页预览\n"
                + "- Markdown 源文查看\n"
                + "- HTML 导出\n"
                + "- 浏览器完整预览\n";
    }

    private String renderPreview(String markdown) {
        if (markdown == null || markdown.trim().isEmpty()) {
            return MarkdownReportRenderer.renderDocument("# 审计报告预览\n\n当前没有可展示的内容。");
        }
        if (markdown.startsWith("ERROR:")) {
            return MarkdownReportRenderer.renderDocument("# 审计报告生成失败\n\n```text\n" + markdown + "\n```");
        }
        return MarkdownReportRenderer.renderDocument(markdown);
    }
}
