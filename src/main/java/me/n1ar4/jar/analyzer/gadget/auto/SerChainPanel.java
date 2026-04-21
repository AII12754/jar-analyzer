/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.gadget.auto;

import me.n1ar4.jar.analyzer.gadget.auto.model.ChainCandidate;
import me.n1ar4.jar.analyzer.gui.MainForm;
import me.n1ar4.jar.analyzer.entity.MethodResult;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 反序列化利用链自动挖掘面板（以独立对话框形式呈现）
 * <p>
 * 通过 {@link #show()} 静态工厂方法打开对话框；
 * 包含：
 * <ul>
 *   <li>上方工具栏：「开始挖掘」按钮及进度标签</li>
 *   <li>中部：候选链结果表格（Trigger 类、方法、Sink、深度、摘要）</li>
 *   <li>下部：链详情文本区（点击行展开完整调用路径）</li>
 * </ul>
 * </p>
 */
public class SerChainPanel extends JDialog {

    private JButton startBtn;
    private JLabel progressLabel;
    private JTable resultTable;
    private DefaultTableModel tableModel;
    private JTextArea detailArea;

    private final List<ChainCandidate> candidates = new ArrayList<>();

    private SerChainPanel(JFrame parent) {
        super(parent, "反序列化利用链自动挖掘", false);
        initUI();
        setSize(1100, 700);
        setLocationRelativeTo(parent);
    }

    /**
     * 静态工厂方法，打开挖掘对话框
     */
    public static void openDialog() {
        JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(
                MainForm.getInstance().getMasterPanel());
        SerChainPanel dialog = new SerChainPanel(frame);
        dialog.setVisible(true);
    }

    private void initUI() {
        setLayout(new BorderLayout(5, 5));

        // ---- 顶部工具栏 ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        startBtn = new JButton("开始挖掘");
        progressLabel = new JLabel("就绪（需先在主界面加载 JAR）");
        progressLabel.setForeground(Color.GRAY);

        topPanel.add(startBtn);
        topPanel.add(new JSeparator(SwingConstants.VERTICAL));
        topPanel.add(progressLabel);
        add(topPanel, BorderLayout.NORTH);

        // ---- 中部结果表格 ----
        String[] columns = {"#", "触发类", "触发方法", "危险类型", "深度", "调用链摘要"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        resultTable = new JTable(tableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.setShowGrid(true);

        // 列宽设置
        resultTable.getColumnModel().getColumn(0).setMaxWidth(40);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(100);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(160);
        resultTable.getColumnModel().getColumn(4).setMaxWidth(50);
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(500);

        JScrollPane tableScroll = new JScrollPane(resultTable);
        tableScroll.setPreferredSize(new Dimension(1080, 380));

        // ---- 下部详情区 ----
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        detailArea.setText("点击结果行查看完整调用路径");
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setPreferredSize(new Dimension(1080, 220));
        detailScroll.setBorder(BorderFactory.createTitledBorder("调用链详情"));

        // 分割上下区域
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        splitPane.setResizeWeight(0.65);
        add(splitPane, BorderLayout.CENTER);

        // ---- 事件绑定 ----
        startBtn.addActionListener(e -> onStart());

        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultTable.getSelectedRow();
                if (row >= 0 && row < candidates.size()) {
                    int modelRow = resultTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < candidates.size()) {
                        showDetail(candidates.get(modelRow));
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
        candidates.clear();
        tableModel.setRowCount(0);
        detailArea.setText("挖掘中，请稍候...");

        new Thread(() -> {
            SerializableChainFinder finder = new SerializableChainFinder(msg ->
                    SwingUtilities.invokeLater(() -> progressLabel.setText(msg))
            );
            List<ChainCandidate> results = finder.findChains();

            SwingUtilities.invokeLater(() -> {
                candidates.addAll(results);
                int idx = 1;
                for (ChainCandidate c : results) {
                    String shortClass = shortName(c.getTriggerClass());
                    tableModel.addRow(new Object[]{
                            idx++,
                            shortClass,
                            c.getTriggerMethod(),
                            c.getSinkDescription(),
                            c.getDepth(),
                            c.toSummary()
                    });
                }
                progressLabel.setText("挖掘完成，共发现 " + results.size() + " 条候选链");
                startBtn.setEnabled(true);
                if (results.isEmpty()) {
                    detailArea.setText("未发现候选链。\n\n可能原因：\n" +
                            "1. 加载的 JAR 中没有实现 Serializable 的类\n" +
                            "2. Sink 方法未被任何 Serializable 类调用到\n" +
                            "3. 调用链深度超过 " + SerializableChainFinder.MAX_DEPTH + " 层");
                } else {
                    detailArea.setText("点击结果行查看完整调用路径");
                }
            });
        }, "SerChainFinder-Thread").start();
    }

    private void showDetail(ChainCandidate c) {
        if (c == null || c.getPath() == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("=== 反序列化利用链候选 ===\n\n");
        sb.append("触发类    : ").append(c.getTriggerClass()).append("\n");
        sb.append("触发方法  : ").append(c.getTriggerMethod()).append("\n");
        sb.append("危险类型  : ").append(c.getSinkDescription()).append("\n");
        sb.append("链深度    : ").append(c.getDepth()).append("\n\n");
        sb.append("完整调用路径:\n");
        sb.append("─".repeat(60)).append("\n");
        List<MethodResult> path = c.getPath();
        for (int i = 0; i < path.size(); i++) {
            MethodResult m = path.get(i);
            String prefix = (i == 0) ? "  [TRIGGER] " : (i == path.size() - 1) ? "  [  SINK ] " : "  [       ] ";
            sb.append(prefix)
                    .append(m.getClassName()).append("#")
                    .append(m.getMethodName());
            if (m.getMethodDesc() != null && !m.getMethodDesc().isEmpty()) {
                sb.append(" ").append(m.getMethodDesc());
            }
            sb.append("\n");
            if (i < path.size() - 1) {
                sb.append("            ↓\n");
            }
        }
        sb.append("─".repeat(60)).append("\n");
        sb.append("\n提示：在 chains 面板中可对该链进行更精确的 DFS 验证和污点分析。\n");
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private String shortName(String className) {
        if (className == null) return "";
        int dot = className.lastIndexOf('.');
        return dot >= 0 ? className.substring(dot + 1) : className;
    }
}
