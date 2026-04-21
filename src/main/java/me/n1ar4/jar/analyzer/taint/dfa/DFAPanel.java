/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.taint.dfa;

import me.n1ar4.jar.analyzer.entity.MethodResult;
import me.n1ar4.jar.analyzer.gui.MainForm;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 过程间数据流分析面板
 * <p>
 * 通过 {@link #show()} 打开独立对话框，展示数据流分析（DFA）结果。
 * 包含进度日志、结果表格、详情展示三个区域。
 * </p>
 */
public class DFAPanel extends JDialog {

    private JButton startBtn;
    private JLabel progressLabel;
    private JTextArea logArea;
    private JTable resultTable;
    private DefaultTableModel tableModel;
    private JTextArea detailArea;

    private final List<DFAEngine.DFAFinding> findings = new ArrayList<>();

    private DFAPanel(JFrame parent) {
        super(parent, "过程间数据流分析（Interprocedural DFA）", false);
        initUI();
        setSize(1150, 750);
        setLocationRelativeTo(parent);
    }

    public static void openDialog() {
        JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(
                MainForm.getInstance().getMasterPanel());
        DFAPanel dialog = new DFAPanel(frame);
        dialog.setVisible(true);
    }

    private void initUI() {
        setLayout(new BorderLayout(5, 5));

        // ---- 顶部工具栏 ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        startBtn = new JButton("开始 DFA 分析");
        progressLabel = new JLabel("就绪（需先在主界面加载 JAR）");
        progressLabel.setForeground(Color.GRAY);
        topPanel.add(startBtn);
        topPanel.add(new JSeparator(SwingConstants.VERTICAL));
        topPanel.add(progressLabel);

        JLabel hintLabel = new JLabel("  提示：支持 Servlet API 与 Spring MVC Controller 入口，分析会扫描所有字节码，耗时较长");
        hintLabel.setForeground(new Color(150, 80, 0));
        topPanel.add(hintLabel);
        add(topPanel, BorderLayout.NORTH);

        // ---- 中部：左侧日志 + 右侧表格 ----
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.28);

        // 左侧日志区
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logArea.setText("分析日志将在此显示...");
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("分析日志"));
        mainSplit.setLeftComponent(logScroll);

        // 右侧：上方结果表格 + 下方详情
        String[] columns = {"#", "漏洞类型", "Source 方法", "Sink 方法", "路径深度", "路径摘要"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        resultTable = new JTable(tableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.getColumnModel().getColumn(0).setMaxWidth(45);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(160);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(4).setMaxWidth(60);
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(450);

        JScrollPane tableScroll = new JScrollPane(resultTable);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        detailArea.setText("点击结果行查看完整数据流路径");
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("污点传播路径详情"));
        detailScroll.setPreferredSize(new Dimension(800, 200));

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        rightSplit.setResizeWeight(0.65);
        mainSplit.setRightComponent(rightSplit);

        add(mainSplit, BorderLayout.CENTER);

        // ---- 事件绑定 ----
        startBtn.addActionListener(e -> onStart());

        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = resultTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < findings.size()) {
                        showDetail(findings.get(modelRow));
                    }
                }
            }
        });
    }

    private void onStart() {
        if (MainForm.getEngine() == null || !MainForm.getEngine().isEnabled()) {
            JOptionPane.showMessageDialog(this, "请先在主界面加载并分析 JAR 文件");
            return;
        }
        startBtn.setEnabled(false);
        findings.clear();
        tableModel.setRowCount(0);
        logArea.setText("");
        detailArea.setText("分析中...");

        new Thread(() -> {
            DFAEngine engine = new DFAEngine(msg -> SwingUtilities.invokeLater(() -> {
                logArea.append(msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
                progressLabel.setText(msg.length() > 60 ? msg.substring(0, 60) + "..." : msg);
            }));

            List<DFAEngine.DFAFinding> results = engine.analyze();

            SwingUtilities.invokeLater(() -> {
                findings.addAll(results);
                int idx = 1;
                for (DFAEngine.DFAFinding f : results) {
                    tableModel.addRow(new Object[]{
                            idx++,
                            f.getSinkDescription(),
                            shortMethod(f.getSourceMethod()),
                            shortMethod(f.getSinkClass() + "#" + f.getSinkMethod()),
                            f.getPathDepth(),
                            f.toSummary()
                    });
                }
                progressLabel.setText("分析完成，共发现 " + results.size() + " 个潜在漏洞路径");
                startBtn.setEnabled(true);
                if (results.isEmpty()) {
                    detailArea.setText("未发现污点路径。\n\n可能原因：\n"
                            + "1. 项目中无可识别的 Web 入口（如 HttpServletRequest.getParameter / Spring MVC Controller 参数）\n"
                            + "2. Source→Sink 调用链超出了分析范围\n"
                            + "3. JAR 尚未加载或分析");
                } else {
                    detailArea.setText("点击结果行查看完整数据流路径");
                }
            });
        }, "DFAEngine-Thread").start();
    }

    private void showDetail(DFAEngine.DFAFinding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 过程间污点传播路径 ===\n\n");
        sb.append("漏洞类型  : ").append(f.getSinkDescription()).append("\n");
        sb.append("Sink 类   : ").append(f.getSinkClass()).append("\n");
        sb.append("Sink 方法  : ").append(f.getSinkMethod()).append("\n");
        sb.append("路径深度  : ").append(f.getPathDepth()).append("\n\n");
        sb.append("完整污点传播路径:\n");
        sb.append("─".repeat(60)).append("\n");
        List<MethodResult> path = f.getPath();
        for (int i = 0; i < path.size(); i++) {
            MethodResult m = path.get(i);
            String tag;
            if (i == 0) tag = "[SOURCE]";
            else if (i == path.size() - 1) tag = "[ SINK ]";
            else tag = "[  →   ]";
            sb.append("  ").append(tag).append(" ")
                    .append(m.getClassName()).append("#").append(m.getMethodName());
            if (m.getMethodDesc() != null && !m.getMethodDesc().isEmpty()) {
                sb.append(" ").append(m.getMethodDesc());
            }
            sb.append("\n");
            if (i < path.size() - 1) sb.append("           ↓\n");
        }
        sb.append("─".repeat(60)).append("\n\n");
        sb.append("建议修复：\n");
        sb.append(getRemediationHint(f.getSinkDescription()));
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private String getRemediationHint(String sinkDesc) {
        if (sinkDesc.contains("SQL")) {
            return "使用参数化查询（PreparedStatement）而非字符串拼接，避免 SQL 注入。";
        } else if (sinkDesc.contains("RCE") || sinkDesc.contains("exec")) {
            return "避免将用户输入直接传递给 Runtime.exec() 或 ProcessBuilder。\n如需执行系统命令，使用白名单校验，并避免 shell 形式调用。";
        } else if (sinkDesc.contains("JNDI")) {
            return "禁用远程类加载（com.sun.jndi.rmi.object.trustURLCodebase=false），\n并对 lookup() 参数进行严格校验和白名单限制。";
        } else if (sinkDesc.contains("Path") || sinkDesc.contains("File")) {
            return "对文件路径进行规范化（Path.normalize()）并验证是否在允许的目录内。";
        } else if (sinkDesc.contains("SSRF")) {
            return "使用 URL 白名单验证，限制可访问的域名和协议（禁止 file://、dict:// 等）。";
        } else if (sinkDesc.contains("XSS")) {
            return "对用户输入进行 HTML 编码（OWASP Java Encoder），\n使用 CSP 策略，避免直接将用户数据写入响应。";
        } else if (sinkDesc.contains("Script") || sinkDesc.contains("EL")) {
            return "不要将用户输入作为脚本或表达式求值，使用沙箱或静态表达式。";
        } else if (sinkDesc.contains("Deserialization")) {
            return "使用 ObjectInputFilter 实现白名单，或替换为安全的序列化格式（JSON/Protobuf）。";
        }
        return "对用户输入进行严格的输入验证和输出编码，遵循最小权限原则。";
    }

    private String shortMethod(String fullMethod) {
        if (fullMethod == null) return "";
        int dot = fullMethod.lastIndexOf('.');
        return dot >= 0 ? fullMethod.substring(dot + 1) : fullMethod;
    }
}
