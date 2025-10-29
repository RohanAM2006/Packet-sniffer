package app;

import org.knowm.xchart.CategoryChart;
import org.knowm.xchart.CategoryChartBuilder;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class TopTalkersChart extends JPanel {

    private CategoryChart chart;
    private XChartPanel<CategoryChart> chartPanel;

    public TopTalkersChart() {
        setLayout(new BorderLayout());

        chart = new CategoryChartBuilder()
                .width(400)
                .height(300)
                .title("Top Talkers")
                .xAxisTitle("Source IP")
                .yAxisTitle("Packet Count")
                .build();

        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setXAxisLabelRotation(45);
        chart.getStyler().setXAxisTickMarkSpacingHint(50);
        chart.getStyler().setPlotMargin(10);
        chart.getStyler().setPlotContentSize(0.9);
        chart.getStyler().setChartFontColor(Color.DARK_GRAY);
        chart.getStyler().setAxisTickLabelsFont(new Font("SansSerif", Font.PLAIN, 10));
        chart.getStyler().setAxisTitleFont(new Font("SansSerif", Font.BOLD, 11));
        chart.getStyler().setToolTipsEnabled(true);

        List<String> dummyIPs = new ArrayList<>();
        List<Integer> dummyCounts = new ArrayList<>();
        dummyIPs.add("0.0.0.0");
        dummyCounts.add(0);
        chart.addSeries("Packets", dummyIPs, dummyCounts);

        chartPanel = new XChartPanel<>(chart);
        chartPanel.setPreferredSize(new Dimension(400, 300));
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateChart(Connection conn, String table, int startRow, int endRow) {
        List<String> ips = new ArrayList<>();
        List<Integer> counts = new ArrayList<>();

        String sql = "SELECT src_ip, COUNT(*) AS cnt FROM (" +
                " SELECT src_ip FROM " + table +
                " WHERE id BETWEEN ? AND ? " +
                ") AS sub " +
                "GROUP BY src_ip " +
                "ORDER BY cnt DESC " +
                "LIMIT 10";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, endRow - startRow + 1);
            stmt.setInt(2, startRow - 1);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String ip = rs.getString("src_ip");
                if (ip == null || ip.isBlank()) ip = "0.0.0.0";

                String shortLabel;
                if (ip.matches("^(\\d+\\.){3}\\d+$")) {
                    String[] parts = ip.split("\\.");
                    shortLabel = parts[3]; // last octet
                } else {
                    shortLabel = ip.length() > 3 ? ip.substring(ip.length() - 3) : ip;
                }

                ips.add(shortLabel);
                counts.add(rs.getInt("cnt"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (ips.isEmpty()) {
            ips.add("0.0.0.0");
            counts.add(0);
        }

        chart.getSeriesMap().clear();
        chart.addSeries("Packets", ips, counts);

        chartPanel.revalidate();
        chartPanel.repaint();
    }
}
