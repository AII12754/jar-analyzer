/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.oneclick;

import me.n1ar4.jar.analyzer.gadget.auto.SerializableChainFinder;
import me.n1ar4.jar.analyzer.gadget.auto.model.ChainCandidate;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.report.ReportPanel;
import me.n1ar4.jar.analyzer.taint.dfa.DFAEngine;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.function.Consumer;

/**
 * 一键智能安全扫描编排器
 *
 * <p>工作流程：
 * <ol>
 *   <li>检查引擎是否就绪（JAR 已加载并完成数据库构建）</li>
 *   <li>弹出带进度信息的模态等待对话框</li>
 *   <li>在后台线程中依次执行：
 *       <ul>
 *         <li>过程间数据流分析（DFA，基于 Worklist 算法）</li>
 *         <li>反序列化利用链自动挖掘（Gadget Chain Mining）</li>
 *       </ul>
 *   </li>
 *   <li>结果缓存到静态字段，供 {@link ReportPanel} / {@link me.n1ar4.jar.analyzer.report.AuditReportBuilder} 直接读取</li>
 *   <li>自动打开 LLM 审计报告面板</li>
 * </ol>
 * </p>
 */
public class OneClickAnalyzer {

    private static final Logger logger = LogManager.getLogger();

    /** 上次一键扫描得到的 DFA 分析结果（全局缓存，线程可见） */
    public static volatile List<DFAEngine.DFAFinding> lastDfaFindings = new ArrayList<>();

    /** 上次一键扫描得到的反序列化利用链候选（全局缓存，线程可见） */
    public static volatile List<ChainCandidate> lastGadgetCandidates = new ArrayList<>();

    /** 是否已完成过一次一键扫描 */
    public static volatile boolean hasRun = false;

    public static final class AnalysisResult {
        private final List<DFAEngine.DFAFinding> dfaFindings;
        private final List<ChainCandidate> gadgetCandidates;

        private AnalysisResult(List<DFAEngine.DFAFinding> dfaFindings,
                               List<ChainCandidate> gadgetCandidates) {
            this.dfaFindings = Collections.unmodifiableList(new ArrayList<>(dfaFindings));
            this.gadgetCandidates = Collections.unmodifiableList(new ArrayList<>(gadgetCandidates));
        }

        public List<DFAEngine.DFAFinding> getDfaFindings() {
            return dfaFindings;
        }

        public List<ChainCandidate> getGadgetCandidates() {
            return gadgetCandidates;
        }
    }

    // -------  进度日志 UI 引用  -------
    private static JTextArea logArea;
    private static JDialog progressDialog;

    /**
     * 触发一键安全扫描。必须在 EDT 调用，内部会开启后台线程。
     */
    public static void run() {
        if (MainForm.getEngine() == null || !MainForm.getEngine().isEnabled()) {
            JOptionPane.showMessageDialog(
                    MainForm.getInstance().getMasterPanel(),
                    "请先导入 JAR/WAR 并完成数据库构建（Build Database）",
                    "引擎未就绪",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 创建进度对话框
        progressDialog = buildProgressDialog();

        // 先启动后台线程，再显示非模态进度窗，避免修改已显示对话框的模态状态
        Thread worker = new Thread(OneClickAnalyzer::doAnalyze, "one-click-analyzer");
        worker.setDaemon(true);
        worker.start();
        progressDialog.setVisible(true);
    }

    // -------  私有实现  -------

    public static AnalysisResult analyzeProject(Consumer<String> progressConsumer) throws Exception {
        hasRun = false;
        lastDfaFindings = new ArrayList<>();
        lastGadgetCandidates = new ArrayList<>();

        emitProgress(progressConsumer, "【阶段 1/2】过程间数据流分析（DFA）启动...");
        emitProgress(progressConsumer, "  构建方法摘要中，请稍候...");

        DFAEngine dfaEngine = new DFAEngine(msg -> emitProgress(progressConsumer, "  " + msg));
        List<DFAEngine.DFAFinding> dfaFindings = dfaEngine.analyze();
        lastDfaFindings = new ArrayList<>(dfaFindings);
        emitProgress(progressConsumer, "✔ DFA 分析完成，发现 " + dfaFindings.size() + " 条潜在漏洞路径");
        emitProgress(progressConsumer, "");

        emitProgress(progressConsumer, "【阶段 2/2】反序列化利用链自动挖掘启动...");
        SerializableChainFinder finder = new SerializableChainFinder(msg -> emitProgress(progressConsumer, "  " + msg));
        List<ChainCandidate> gadgets = finder.findChains();
        lastGadgetCandidates = new ArrayList<>(gadgets);
        emitProgress(progressConsumer, "✔ 利用链挖掘完成，发现 " + gadgets.size() + " 条候选链");
        emitProgress(progressConsumer, "");

        hasRun = true;
        emitProgress(progressConsumer, "========================================");
        emitProgress(progressConsumer, "一键项目分析完成，结果已缓存，可直接用于报告生成。");
        emitProgress(progressConsumer, "========================================");

        return new AnalysisResult(lastDfaFindings, lastGadgetCandidates);
    }

    private static void doAnalyze() {
        try {
            analyzeProject(OneClickAnalyzer::log);
            log("========================================");
            log("一键扫描完成！正在打开 LLM 审计报告面板...");
            log("========================================");

            // 等待半秒让用户看到完成信息
            Thread.sleep(600);

            // ---- 阶段 3：打开报告面板 ----
            SwingUtilities.invokeLater(() -> {
                if (progressDialog != null) {
                    progressDialog.dispose();
                }
                ReportPanel.openDialog();
            });

        } catch (Exception ex) {
            logger.error("一键扫描发生异常: " + ex.getMessage());
            log("ERROR: " + ex.getMessage());
            SwingUtilities.invokeLater(() -> {
                if (progressDialog != null) {
                    progressDialog.dispose();
                }
                JOptionPane.showMessageDialog(
                        MainForm.getInstance().getMasterPanel(),
                        "一键扫描发生异常：\n" + ex.getMessage(),
                        "扫描失败",
                        JOptionPane.ERROR_MESSAGE);
            });
        }
    }

    private static void log(String msg) {
        logger.info(msg);
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }

    private static void emitProgress(Consumer<String> progressConsumer, String msg) {
        logger.info(msg);
        if (progressConsumer != null) {
            progressConsumer.accept(msg);
        }
    }

    private static JDialog buildProgressDialog() {
        Window owner = SwingUtilities.getWindowAncestor(MainForm.getInstance().getMasterPanel());
        JDialog dialog = new JDialog(owner, "一键智能安全扫描", Dialog.ModalityType.MODELESS);
        dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        dialog.setSize(680, 480);
        dialog.setLocationRelativeTo(owner);
        dialog.setLayout(new BorderLayout(8, 8));

        // 标题
        JLabel title = new JLabel(
                "<html><b style='font-size:13px'>正在执行全量自动化安全扫描，请勿关闭此窗口...</b></html>",
                SwingConstants.CENTER);
        title.setBorder(BorderFactory.createEmptyBorder(10, 10, 4, 10));
        dialog.add(title, BorderLayout.NORTH);

        // 日志区
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(180, 255, 180));
        logArea.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        logArea.setText("准备启动自动化安全扫描...\n");
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("扫描进度日志"));
        dialog.add(scrollPane, BorderLayout.CENTER);

        // 阶段提示
        JPanel stepsPanel = new JPanel(new GridLayout(1, 2, 8, 0));
        stepsPanel.setBorder(BorderFactory.createEmptyBorder(4, 10, 10, 10));
        JLabel step1 = new JLabel("<html>① 过程间 DFA 污点分析<br/><small>追踪 Source→Sink 数据流</small></html>",
                SwingConstants.CENTER);
        JLabel step2 = new JLabel("<html>② 反序列化利用链挖掘<br/><small>DFS 搜索危险调用链</small></html>",
                SwingConstants.CENTER);
        step1.setBorder(BorderFactory.createEtchedBorder());
        step2.setBorder(BorderFactory.createEtchedBorder());
        stepsPanel.add(step1);
        stepsPanel.add(step2);
        dialog.add(stepsPanel, BorderLayout.SOUTH);

        return dialog;
    }
}
