/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.gui;

import com.formdev.flatlaf.FlatLaf;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.dfs.DFSResult;
import me.n1ar4.jar.analyzer.gui.render.ZebraTableCellRenderer;
import me.n1ar4.jar.analyzer.taint.Sanitizer;
import me.n1ar4.jar.analyzer.taint.SanitizerRule;
import me.n1ar4.jar.analyzer.taint.TaintResult;
import me.n1ar4.log.LogManager;
import me.n1ar4.log.Logger;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

@SuppressWarnings("all")
public class TaintResultDialog extends JFrame {
    private static final Logger logger = LogManager.getLogger();

    private JTable resultTable;
    private JEditorPane detailPane;
    private JLabel summaryLabel;
    private JLabel sanitizerCountLabel;
    private JTable sanitizerTable;
    private DefaultTableModel resultTableModel;
    private DefaultTableModel sanitizerTableModel;

    // 保存原始数据用于详情显示
    private final List<TaintResult> originalTaintResults;

    public TaintResultDialog(Frame parent, List<TaintResult> taintResults) {
        super("污点分析结果详情");
        this.originalTaintResults = taintResults;
        initializeComponents();
        setupLayout();
        loadData(taintResults);
        setupEventHandlers();

        setSize(1200, 800);
        setLocationRelativeTo(parent);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);

        setResizable(true);
        setMinimumSize(new Dimension(800, 600));

        // 首先设置为最上层
        setAlwaysOnTop(true);
        setVisible(true);
    }

    private void initializeComponents() {
        // 创建结果表格
        String[] resultColumns = {"序号", "Source类", "Source方法", "Sink类", "Sink方法", "调用链深度", "分析结果"};
        resultTableModel = new DefaultTableModel(resultColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable = new JTable(resultTableModel);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.getTableHeader().setReorderingAllowed(false);
        resultTable.setDefaultRenderer(Object.class, new ZebraTableCellRenderer());

        // 设置表格列宽
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(150);
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        resultTable.getColumnModel().getColumn(6).setPreferredWidth(100);

        // 创建详情面板（HTML 渲染）
        detailPane = new JEditorPane();
        detailPane.setEditable(false);
        detailPane.setContentType("text/html");
        detailPane.setText("<html><body style='font-family:monospaced;padding:8px'>"
                + "<i><font color='#888888'>请选择一行查看详细的污点分析过程...</font></i>"
                + "</body></html>");

        // 创建统计标签
        summaryLabel = new JLabel();
        summaryLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        if (FlatLaf.isLafDark()) {
            summaryLabel.setForeground(new Color(100, 200, 100));
        } else {
            summaryLabel.setForeground(new Color(0, 100, 0));
        }

        sanitizerCountLabel = new JLabel();
        sanitizerCountLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        if (FlatLaf.isLafDark()) {
            sanitizerCountLabel.setForeground(new Color(100, 150, 255));
        } else {
            sanitizerCountLabel.setForeground(new Color(0, 0, 150));
        }

        // 创建Sanitizer规则表格
        String[] sanitizerColumns = {"类名", "方法名", "方法描述", "参数索引"};
        sanitizerTableModel = new DefaultTableModel(sanitizerColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        sanitizerTable = new JTable(sanitizerTableModel);
        sanitizerTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sanitizerTable.getTableHeader().setReorderingAllowed(false);
        sanitizerTable.setDefaultRenderer(Object.class, new ZebraTableCellRenderer());

        // 设置Sanitizer表格列宽
        sanitizerTable.getColumnModel().getColumn(0).setPreferredWidth(300);
        sanitizerTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        sanitizerTable.getColumnModel().getColumn(2).setPreferredWidth(250);
        sanitizerTable.getColumnModel().getColumn(3).setPreferredWidth(80);
    }

    private void setupLayout() {
        setLayout(new BorderLayout());

        // 顶部统计信息面板
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(new TitledBorder("统计信息"));
        topPanel.add(summaryLabel);
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(sanitizerCountLabel);

        // 中间分割面板
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.4);

        // 上半部分：结果表格
        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.setBorder(new TitledBorder("污点分析结果"));
        JScrollPane resultScrollPane = new JScrollPane(resultTable);
        resultPanel.add(resultScrollPane, BorderLayout.CENTER);

        // 下半部分：详情和Sanitizer规则的分割面板
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplitPane.setResizeWeight(0.6);

        // 左侧：详情面板
        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.setBorder(new TitledBorder("污点分析详情"));
        JScrollPane detailScrollPane = new JScrollPane(detailPane);
        detailPanel.add(detailScrollPane, BorderLayout.CENTER);

        // 右侧：Sanitizer规则表格
        JPanel sanitizerPanel = new JPanel(new BorderLayout());
        sanitizerPanel.setBorder(new TitledBorder("Sanitizer规则"));
        JScrollPane sanitizerScrollPane = new JScrollPane(sanitizerTable);
        sanitizerPanel.add(sanitizerScrollPane, BorderLayout.CENTER);

        bottomSplitPane.setLeftComponent(detailPanel);
        bottomSplitPane.setRightComponent(sanitizerPanel);

        mainSplitPane.setTopComponent(resultPanel);
        mainSplitPane.setBottomComponent(bottomSplitPane);

        // 底部按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton exportButton = new JButton("导出结果");
        JButton closeButton = new JButton("关闭");

        exportButton.addActionListener(e -> exportResults());
        closeButton.addActionListener(e -> dispose());

        buttonPanel.add(exportButton);
        buttonPanel.add(closeButton);

        add(topPanel, BorderLayout.NORTH);
        add(mainSplitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void loadData(List<TaintResult> taintResults) {
        // 加载污点分析结果
        if (taintResults != null && !taintResults.isEmpty()) {
            for (int i = 0; i < taintResults.size(); i++) {
                TaintResult result = taintResults.get(i);
                DFSResult dfsResult = result.getDfsResult();

                if (dfsResult != null) {
                    String sourceClass = "";
                    String sourceMethod = "";
                    String sinkClass = "";
                    String sinkMethod = "";

                    if (dfsResult.getSource() != null) {
                        sourceClass = dfsResult.getSource().getClassReference().getName();
                        sourceMethod = dfsResult.getSource().getName();
                    }

                    if (dfsResult.getSink() != null) {
                        sinkClass = dfsResult.getSink().getClassReference().getName();
                        sinkMethod = dfsResult.getSink().getName();
                    }

                    String analysisResult = result.getTaintText() != null &&
                            result.getTaintText().contains("通过") ? "通过" : "未通过";

                    Object[] rowData = {
                            i + 1,
                            sourceClass,
                            sourceMethod,
                            sinkClass,
                            sinkMethod,
                            dfsResult.getDepth(),
                            analysisResult
                    };

                    resultTableModel.addRow(rowData);
                }
            }

            // 更新统计信息
            long passedCount = taintResults.stream()
                    .filter(r -> r.getTaintText() != null && r.getTaintText().contains("通过"))
                    .count();

            summaryLabel.setText(String.format("总计: %d 条调用链, 通过: %d 条, 未通过: %d 条",
                    taintResults.size(), passedCount, taintResults.size() - passedCount));
        } else {
            summaryLabel.setText("无污点分析结果");
        }

        // 加载Sanitizer规则
        loadSanitizerRules();
    }

    private void loadSanitizerRules() {
        try {
            InputStream sin = getClass().getClassLoader().getResourceAsStream("sanitizer.json");
            if (sin != null) {
                SanitizerRule rule = SanitizerRule.loadJSON(sin);
                if (rule.getRules() != null) {
                    List<Sanitizer> rules = rule.getRules();

                    for (Sanitizer sanitizer : rules) {
                        Object[] rowData = {
                                sanitizer.getClassName(),
                                sanitizer.getMethodName(),
                                sanitizer.getMethodDesc(),
                                sanitizer.getParamIndex()
                        };
                        sanitizerTableModel.addRow(rowData);
                    }

                    sanitizerCountLabel.setText(String.format("Sanitizer规则数量: %d 条", rules.size()));
                } else {
                    sanitizerCountLabel.setText("Sanitizer规则数量: 0 条");
                }
            } else {
                sanitizerCountLabel.setText("无法加载Sanitizer规则");
            }
        } catch (Exception e) {
            logger.error("加载Sanitizer规则失败: {}", e.getMessage());
            sanitizerCountLabel.setText("加载Sanitizer规则失败");
        }
    }

    private void setupEventHandlers() {
        // 结果表格选择事件
        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showDetailForRow(selectedRow);
                }
            }
        });
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private String taintLogToHtml(String taintText) {
        if (taintText == null || taintText.trim().isEmpty()) {
            return "<i><font color='#888888'>无污点分析过程信息</font></i>";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<table width='100%' cellpadding='2' cellspacing='0'>");
        for (String line : taintText.split("\n")) {
            if (line.isEmpty()) continue;
            String color;
            String bg;
            if (line.contains("通过")) {
                color = "#1b5e20"; bg = "#c8e6c9";
            } else if (line.contains("失败") || line.contains("错误")) {
                color = "#b71c1c"; bg = "#ffcdd2";
            } else if (line.contains("开始污点分析")) {
                color = "#0d47a1"; bg = "#bbdefb";
            } else if (line.contains("数据流结果")) {
                color = "#e65100"; bg = "#ffe0b2";
            } else if (line.contains("方法:")) {
                color = "#4527a0"; bg = "#ede7f6";
            } else if (line.contains("接口类型污点")) {
                color = "#1b5e20"; bg = "#f1f8e9";
            } else {
                color = "#424242"; bg = "transparent";
            }
            sb.append("<tr bgcolor='").append(bg).append("'>");
            sb.append("<td><font color='").append(color).append("'><tt>")
              .append(esc(line)).append("</tt></font></td></tr>");
        }
        sb.append("</table>");
        return sb.toString();
    }

    private void showDetailForRow(int row) {
        if (originalTaintResults == null || row >= originalTaintResults.size() || row < 0) {
            detailPane.setText("<html><body><font color='red'>无法获取详细信息</font></body></html>");
            return;
        }

        TaintResult taintResult = originalTaintResults.get(row);
        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:SansSerif;margin:8px'>");

        // 标题
        html.append("<h3><font color='#1565C0'>污点分析详情 #").append(row + 1).append("</font></h3>");

        DFSResult dfsResult = taintResult.getDfsResult();
        if (dfsResult != null) {
            // Source / Sink 信息表
            html.append("<table border='1' cellpadding='4' cellspacing='0' width='100%'>");
            if (dfsResult.getSource() != null) {
                html.append("<tr bgcolor='#E8F5E9'>");
                html.append("<td width='100'><b><font color='#2E7D32'>Source 类</font></b></td>");
                html.append("<td><tt>").append(esc(dfsResult.getSource().getClassReference().getName())).append("</tt></td></tr>");
                html.append("<tr bgcolor='#E8F5E9'>");
                html.append("<td><b><font color='#2E7D32'>Source 方法</font></b></td>");
                html.append("<td><tt>").append(esc(dfsResult.getSource().getName()))
                   .append(esc(dfsResult.getSource().getDesc())).append("</tt></td></tr>");
            }
            if (dfsResult.getSink() != null) {
                html.append("<tr bgcolor='#FFEBEE'>");
                html.append("<td><b><font color='#C62828'>Sink 类</font></b></td>");
                html.append("<td><tt>").append(esc(dfsResult.getSink().getClassReference().getName())).append("</tt></td></tr>");
                html.append("<tr bgcolor='#FFEBEE'>");
                html.append("<td><b><font color='#C62828'>Sink 方法</font></b></td>");
                html.append("<td><tt>").append(esc(dfsResult.getSink().getName()))
                   .append(esc(dfsResult.getSink().getDesc())).append("</tt></td></tr>");
            }
            html.append("<tr><td><b>调用链深度</b></td><td>").append(dfsResult.getDepth()).append("</td></tr>");
            String modeText;
            switch (dfsResult.getMode()) {
                case DFSResult.FROM_SOURCE_TO_SINK: modeText = "从 Source 到 Sink"; break;
                case DFSResult.FROM_SINK_TO_SOURCE: modeText = "从 Sink 到 Source"; break;
                case DFSResult.FROM_SOURCE_TO_ALL:  modeText = "从 Source 到所有可能点"; break;
                default: modeText = "未知模式";
            }
            html.append("<tr><td><b>分析模式</b></td><td>").append(modeText).append("</td></tr>");
            html.append("</table>");

            // 调用链步骤
            List<MethodReference.Handle> methodList = dfsResult.getMethodList();
            if (methodList != null && !methodList.isEmpty()) {
                html.append("<h3><font color='#1565C0'>调用链详情</font></h3>");
                html.append("<table border='1' cellpadding='4' cellspacing='0' width='100%'>");
                for (int i = 0; i < methodList.size(); i++) {
                    MethodReference.Handle m = methodList.get(i);
                    String bg = (i == 0) ? "#E8F5E9" : (i == methodList.size() - 1 ? "#FFEBEE" : "#FFFDE7");
                    String label = (i == 0) ? "SOURCE" : (i == methodList.size() - 1 ? "SINK" : String.valueOf(i + 1));
                    String fc = (i == 0) ? "#2E7D32" : (i == methodList.size() - 1 ? "#C62828" : "#666666");
                    html.append("<tr bgcolor='").append(bg).append("'>");
                    html.append("<td width='60' align='center'><b><font color='").append(fc).append("'>").append(label).append("</font></b></td>");
                    html.append("<td><tt>").append(esc(m.getClassReference().getName())).append(".").append(esc(m.getName())).append(esc(m.getDesc())).append("</tt></td>");
                    html.append("</tr>");
                    if (i < methodList.size() - 1) {
                        html.append("<tr><td colspan='2' align='center'><font color='#90A4AE'>|</font></td></tr>");
                    }
                }
                html.append("</table>");
            }
        }

        // 污点传播过程（着色日志）
        html.append("<h3><font color='#1565C0'>污点传播过程</font></h3>");
        html.append(taintLogToHtml(taintResult.getTaintText()));

        html.append("</body></html>");
        detailPane.setText(html.toString());
        detailPane.setCaretPosition(0);
    }

    private void exportResults() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出污点分析结果");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "文本文件 (*.txt)", "txt"));
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                if (!file.getName().endsWith(".txt")) {
                    file = new java.io.File(file.getAbsolutePath() + ".txt");
                }
                StringBuilder exportContent = new StringBuilder();
                exportContent.append("污点分析结果导出\n");
                exportContent.append("导出时间: ").append(new java.util.Date()).append("\n\n");
                if (originalTaintResults != null) {
                    for (int i = 0; i < originalTaintResults.size(); i++) {
                        exportContent.append("==================== 结果 ").append(i + 1).append(" ===================\n");
                        TaintResult result = originalTaintResults.get(i);

                        if (result.getDfsResult() != null) {
                            DFSResult dfs = result.getDfsResult();
                            if (dfs.getSource() != null) {
                                exportContent.append("Source: ").append(dfs.getSource().getClassReference().getName())
                                        .append(".").append(dfs.getSource().getName()).append("\n");
                            }
                            if (dfs.getSink() != null) {
                                exportContent.append("Sink: ").append(dfs.getSink().getClassReference().getName())
                                        .append(".").append(dfs.getSink().getName()).append("\n");
                            }
                            exportContent.append("深度: ").append(dfs.getDepth()).append("\n");
                        }

                        if (result.getTaintText() != null) {
                            exportContent.append("分析过程:\n").append(result.getTaintText()).append("\n");
                        }
                        exportContent.append("\n");
                    }
                }
                java.nio.file.Files.write(file.toPath(), exportContent.toString().getBytes(StandardCharsets.UTF_8));
                JOptionPane.showMessageDialog(this, "导出成功: " +
                        file.getAbsolutePath(), "导出完成", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                logger.error("导出失败: {}", ex.getMessage());
                JOptionPane.showMessageDialog(this, "导出失败: " +
                        ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // 静态方法用于显示对话框
    public static void showTaintResults(Frame parent, List<TaintResult> taintResults) {
        SwingUtilities.invokeLater(() -> {
            new TaintResultDialog(parent, taintResults);
        });
    }
}