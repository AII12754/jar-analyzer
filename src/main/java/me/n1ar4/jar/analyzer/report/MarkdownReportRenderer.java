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

import org.commonmark.Extension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.node.AbstractVisitor;
import org.commonmark.node.Heading;
import org.commonmark.node.Node;
import org.commonmark.node.Text;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.AttributeProvider;
import org.commonmark.renderer.html.AttributeProviderContext;
import org.commonmark.renderer.html.AttributeProviderFactory;
import org.commonmark.renderer.html.HtmlRenderer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MarkdownReportRenderer {
    private static final List<Extension> EXTENSIONS = Arrays.asList(TablesExtension.create());
    private static final Pattern SEVERITY_PATTERN = Pattern.compile("\\[(严重|高危|高|中危|中|低危|低)\\]");

    private static final Parser PARSER = Parser.builder()
            .extensions(EXTENSIONS)
            .build();

    private MarkdownReportRenderer() {
    }

    public static String renderDocument(String markdown) {
        String safeMarkdown = markdown == null || markdown.trim().isEmpty()
                ? "# 审计报告预览\n\n当前没有可展示的内容。"
                : markdown;
        Node document = PARSER.parse(safeMarkdown);
        List<HeadingInfo> headings = collectHeadings(document);
        Map<Node, String> headingIds = assignHeadingIds(headings);
        String body = buildBodyHtml(document, headingIds);
        SeveritySummary severitySummary = collectSeveritySummary(safeMarkdown, headings);
        String tocHtml = buildTocHtml(headings);
        String summaryCards = buildSummaryCards(severitySummary);

        return "<!DOCTYPE html>\n"
                + "<html lang=\"zh-CN\">\n"
                + "<head>\n"
                + "  <meta charset=\"UTF-8\">\n"
                + "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "  <title>jar-analyzer 安全审计报告</title>\n"
                + "  <style>\n"
                + buildStyles()
                + "\n  </style>\n"
                + "</head>\n"
                + "<body>\n"
                + "  <main class=\"page\">\n"
                + "    <section class=\"hero\">\n"
                + "      <div class=\"eyebrow\">jar-analyzer / LLM Security Report</div>\n"
                + "      <h1>安全审计报告</h1>\n"
                + "      <p>这个页面在内嵌预览和新窗口打开时使用同一份响应式排版，便于直接阅读和交付。</p>\n"
                + "    </section>\n"
                + summaryCards + "\n"
                + "    <section class=\"report-shell\">\n"
                + "      <aside class=\"report-sidebar\">\n"
                + "        <div class=\"sidebar-box\">\n"
                + "          <h3>目录导航</h3>\n"
                + tocHtml + "\n"
                + "        </div>\n"
                + "        <div class=\"sidebar-box\">\n"
                + "          <h3>阅读提示</h3>\n"
                + "          <ul>\n"
                + "            <li>点击目录可以跳转到对应章节</li>\n"
                + "            <li>风险摘要会优先突出严重和高危问题</li>\n"
                + "            <li>当前页面适合直接导出或在新窗口中展示</li>\n"
                + "          </ul>\n"
                + "        </div>\n"
                + "      </aside>\n"
                + "      <article class=\"report-body markdown-body\">\n"
                + body + "\n"
                + "      </article>\n"
                + "    </section>\n"
                + "  </main>\n"
                + "</body>\n"
                + "</html>\n";
    }

    private static String buildBodyHtml(Node document, Map<Node, String> headingIds) {
        HtmlRenderer htmlRenderer = HtmlRenderer.builder()
                .extensions(EXTENSIONS)
                .escapeHtml(true)
                .attributeProviderFactory(new AttributeProviderFactory() {
                    @Override
                    public AttributeProvider create(AttributeProviderContext context) {
                        return (node, tagName, attributes) -> {
                            String id = headingIds.get(node);
                            if (id != null) {
                                attributes.put("id", id);
                            }
                        };
                    }
                })
                .build();
        return htmlRenderer.render(document);
    }

    private static List<HeadingInfo> collectHeadings(Node document) {
        List<HeadingInfo> headings = new ArrayList<>();
        document.accept(new AbstractVisitor() {
            @Override
            public void visit(Heading heading) {
                headings.add(new HeadingInfo(heading, heading.getLevel(), extractText(heading)));
                visitChildren(heading);
            }
        });
        return headings;
    }

    private static Map<Node, String> assignHeadingIds(List<HeadingInfo> headings) {
        Map<Node, String> ids = new IdentityHashMap<>();
        Set<String> used = new HashSet<>();
        int index = 1;
        for (HeadingInfo heading : headings) {
            String base = slugify(heading.text);
            if (base.isEmpty()) {
                base = "section-" + index;
            }
            String candidate = base;
            int suffix = 2;
            while (!used.add(candidate)) {
                candidate = base + "-" + suffix++;
            }
            ids.put(heading.node, candidate);
            heading.id = candidate;
            index++;
        }
        return ids;
    }

    private static SeveritySummary collectSeveritySummary(String markdown, List<HeadingInfo> headings) {
        SeveritySummary summary = new SeveritySummary();
        Matcher matcher = SEVERITY_PATTERN.matcher(markdown);
        while (matcher.find()) {
            String value = matcher.group(1);
            if ("严重".equals(value)) {
                summary.severe++;
            } else if ("高危".equals(value) || "高".equals(value)) {
                summary.high++;
            } else if ("中危".equals(value) || "中".equals(value)) {
                summary.medium++;
            } else if ("低危".equals(value) || "低".equals(value)) {
                summary.low++;
            }
        }
        for (HeadingInfo heading : headings) {
            if (heading.level == 3) {
                summary.totalFindings++;
            }
        }
        int severitySum = summary.severe + summary.high + summary.medium + summary.low;
        if (severitySum > 0) {
            summary.totalFindings = Math.max(summary.totalFindings, severitySum);
        }
        return summary;
    }

    private static String buildTocHtml(List<HeadingInfo> headings) {
        if (headings.isEmpty()) {
            return "<p>当前没有可导航的标题。</p>";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<ul class=\"toc-list\">");
        for (HeadingInfo heading : headings) {
            if (heading.level > 3 || heading.id == null) {
                continue;
            }
            String cssClass = heading.level == 3 ? " class=\"toc-child\"" : "";
            sb.append("<li").append(cssClass).append("><a href=\"#")
                    .append(heading.id)
                    .append("\">")
                    .append(escapeHtml(heading.text))
                    .append("</a></li>");
        }
        sb.append("</ul>");
        return sb.toString();
    }

    private static String buildSummaryCards(SeveritySummary summary) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"summary-grid\">");
        appendCard(sb, "summary-card-total", "总发现", summary.totalFindings);
        appendCard(sb, "summary-card-severe", "严重", summary.severe);
        appendCard(sb, "summary-card-high", "高危", summary.high);
        appendCard(sb, "summary-card-medium", "中危", summary.medium);
        appendCard(sb, "summary-card-low", "低危", summary.low);
        sb.append("</section>");
        return sb.toString();
    }

    private static void appendCard(StringBuilder sb, String cssClass, String label, int value) {
        sb.append("<article class=\"summary-card ")
                .append(cssClass)
                .append("\"><span class=\"card-label\">")
                .append(escapeHtml(label))
                .append("</span><span class=\"card-value\">")
                .append(value)
                .append("</span></article>");
    }

    private static String buildStyles() {
        return "    :root {\n"
                + "      --bg-accent: rgba(15, 118, 110, 0.12);\n"
                + "      --panel: rgba(255, 252, 247, 0.94);\n"
                + "      --panel-strong: #ffffff;\n"
                + "      --text: #1f2522;\n"
                + "      --muted: #5e6b64;\n"
                + "      --accent: #0f766e;\n"
                + "      --accent-soft: #e8f5f3;\n"
                + "      --border: #d9d3c8;\n"
                + "      --border-strong: rgba(15, 118, 110, 0.18);\n"
                + "      --code-bg: #1f2522;\n"
                + "      --code-text: #eff6f2;\n"
                + "      --shadow: 0 22px 70px rgba(30, 41, 59, 0.12);\n"
                + "      --shadow-soft: 0 12px 26px rgba(31, 37, 34, 0.08);\n"
                + "    }\n"
                + "    * { box-sizing: border-box; }\n"
                + "    html { scroll-behavior: smooth; }\n"
                + "    body {\n"
                + "      margin: 0;\n"
                + "      padding: 36px 18px 48px;\n"
                + "      font-family: 'Segoe UI Variable Text', 'PingFang SC', 'Microsoft YaHei', sans-serif;\n"
                + "      color: var(--text);\n"
                + "      background:\n"
                + "        radial-gradient(circle at 10% 10%, var(--bg-accent), transparent 26%),\n"
                + "        radial-gradient(circle at 90% 12%, rgba(200, 111, 43, 0.12), transparent 24%),\n"
                + "        linear-gradient(180deg, #f7f3ec 0%, #f2ece2 52%, #f8f4ed 100%);\n"
                + "    }\n"
                + "    .page {\n"
                + "      max-width: 1380px;\n"
                + "      margin: 0 auto;\n"
                + "      padding: 30px;\n"
                + "      background: var(--panel);\n"
                + "      border: 1px solid var(--border);\n"
                + "      border-radius: 30px;\n"
                + "      box-shadow: var(--shadow);\n"
                + "      backdrop-filter: blur(16px);\n"
                + "    }\n"
                + "    .hero {\n"
                + "      background: linear-gradient(135deg, rgba(232, 245, 243, 0.95), rgba(255, 250, 244, 0.9));\n"
                + "      border: 1px solid #cde5df;\n"
                + "      padding: 24px 26px;\n"
                + "      border-radius: 22px;\n"
                + "      margin-bottom: 18px;\n"
                + "    }\n"
                + "    .eyebrow { color: #0f766e; font-size: 12px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; }\n"
                + "    .hero h1 { margin: 12px 0 10px; font-size: clamp(34px, 4vw, 52px); line-height: 1.05; }\n"
                + "    .hero p { color: var(--muted); margin: 0; max-width: 760px; line-height: 1.8; }\n"
                + "    .summary-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 20px; }\n"
                + "    .summary-card { padding: 16px 18px; border-radius: 18px; border: 1px solid var(--border); background: rgba(255, 255, 255, 0.8); box-shadow: var(--shadow-soft); }\n"
                + "    .card-label { display: block; color: var(--muted); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }\n"
                + "    .card-value { display: block; font-size: 30px; font-weight: 700; margin-top: 8px; }\n"
                + "    .summary-card-total { background: #eff8ff; border-color: #bed7ea; }\n"
                + "    .summary-card-severe { background: #fff1f1; border-color: #e4b3b3; }\n"
                + "    .summary-card-high { background: #fff6ee; border-color: #edc8a6; }\n"
                + "    .summary-card-medium { background: #fffbe9; border-color: #ead79a; }\n"
                + "    .summary-card-low { background: #f2faf1; border-color: #bfd7bc; }\n"
                + "    .report-shell { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 20px; align-items: start; }\n"
                + "    .report-sidebar { position: sticky; top: 24px; }\n"
                + "    .sidebar-box { background: rgba(248, 244, 238, 0.88); border: 1px solid var(--border); border-radius: 18px; padding: 16px 18px; margin-bottom: 14px; }\n"
                + "    .sidebar-box h3 { margin: 0 0 12px; font-size: 16px; }\n"
                + "    .sidebar-box ul { margin: 0; padding-left: 18px; }\n"
                + "    .sidebar-box li { margin: 7px 0; }\n"
                + "    .toc-list { list-style: none; padding: 0; margin: 0; }\n"
                + "    .toc-list li + li { margin-top: 8px; }\n"
                + "    .toc-list a { display: block; padding: 8px 10px; border-radius: 12px; color: var(--text); background: rgba(255,255,255,0.56); border: 1px solid transparent; text-decoration: none; }\n"
                + "    .toc-list a:hover { color: var(--accent); border-color: var(--border-strong); background: var(--accent-soft); }\n"
                + "    .toc-child a { margin-left: 12px; }\n"
                + "    .report-body { min-width: 0; background: var(--panel-strong); border: 1px solid var(--border); border-radius: 22px; padding: 28px 30px; box-shadow: var(--shadow-soft); }\n"
                + "    .report-body > :first-child { margin-top: 0; }\n"
                + "    h1, h2, h3, h4 { color: #15211c; line-height: 1.25; margin-top: 1.65em; margin-bottom: 0.65em; scroll-margin-top: 32px; }\n"
                + "    h1 { font-size: 2.2rem; margin-top: 0; }\n"
                + "    h2 { font-size: 1.48rem; padding-bottom: 10px; border-bottom: 1px solid var(--border); }\n"
                + "    h3 { font-size: 1.16rem; }\n"
                + "    p, li { line-height: 1.78; font-size: 15px; }\n"
                + "    p { margin: 0.85em 0; }\n"
                + "    ul, ol { padding-left: 1.5rem; }\n"
                + "    a { color: var(--accent); text-decoration: none; }\n"
                + "    a:hover { text-decoration: underline; }\n"
                + "    blockquote { margin: 1.25rem 0; padding: 0.95rem 1.1rem; border-left: 4px solid var(--accent); background: var(--accent-soft); color: #24423b; border-radius: 0 14px 14px 0; }\n"
                + "    code { font-family: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace; background: rgba(15, 118, 110, 0.08); padding: 0.15em 0.42em; border-radius: 8px; font-size: 0.95em; overflow-wrap: anywhere; }\n"
                + "    pre { background: var(--code-bg); color: var(--code-text); padding: 18px 20px; border-radius: 18px; overflow: auto; box-shadow: inset 0 1px 0 rgba(255,255,255,0.04); white-space: pre-wrap; word-break: break-word; }\n"
                + "    pre code { background: transparent; padding: 0; color: inherit; word-break: normal; }\n"
                + "    table { width: 100%; display: block; overflow-x: auto; border-collapse: collapse; margin: 1.1rem 0 1.5rem; background: var(--panel-strong); border-radius: 16px; box-shadow: 0 10px 24px rgba(31, 37, 34, 0.06); }\n"
                + "    th, td { border: 1px solid var(--border); padding: 12px 14px; text-align: left; vertical-align: top; min-width: 120px; }\n"
                + "    th { background: #f1f6f4; font-weight: 700; }\n"
                + "    img { max-width: 100%; height: auto; border-radius: 16px; }\n"
                + "    hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }\n"
                + "    @media (max-width: 1120px) {\n"
                + "      .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n"
                + "      .report-shell { grid-template-columns: 1fr; }\n"
                + "      .report-sidebar { position: static; }\n"
                + "    }\n"
                + "    @media (max-width: 720px) {\n"
                + "      body { padding: 16px 10px 24px; }\n"
                + "      .page { padding: 18px; border-radius: 22px; }\n"
                + "      .hero { padding: 18px; }\n"
                + "      .hero h1 { font-size: 1.9rem; }\n"
                + "      .summary-grid { grid-template-columns: 1fr; }\n"
                + "      .report-body { padding: 20px 18px; }\n"
                + "      h2 { font-size: 1.28rem; }\n"
                + "    }";
    }

    private static String slugify(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char ch : text.toLowerCase(Locale.ROOT).toCharArray()) {
            if (Character.isLetterOrDigit(ch)) {
                sb.append(ch);
            } else if (Character.isWhitespace(ch) || ch == '-' || ch == '_') {
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '-') {
                    sb.append('-');
                }
            }
        }
        while (sb.length() > 0 && sb.charAt(sb.length() - 1) == '-') {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    private static String extractText(Node node) {
        StringBuilder sb = new StringBuilder();
        node.accept(new AbstractVisitor() {
            @Override
            public void visit(Text text) {
                sb.append(text.getLiteral());
            }
        });
        return sb.toString().trim();
    }

    private static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static final class HeadingInfo {
        private final Node node;
        private final int level;
        private final String text;
        private String id;

        private HeadingInfo(Node node, int level, String text) {
            this.node = node;
            this.level = level;
            this.text = text == null || text.isEmpty() ? "未命名章节" : text;
        }
    }

    private static final class SeveritySummary {
        private int totalFindings;
        private int severe;
        private int high;
        private int medium;
        private int low;
    }
}