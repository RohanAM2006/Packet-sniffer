package app;

import org.knowm.xchart.PieChart;
import org.knowm.xchart.PieChartBuilder;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

public class ProtocolPieChart extends JPanel {

    private PieChart chart;
    private XChartPanel<PieChart> chartPanel;

    public ProtocolPieChart() {
        setLayout(new BorderLayout());

        chart = new PieChartBuilder()
                .width(400)
                .height(300)
                .title("Protocol Distribution")
                .build();

        chart.addSeries("No Data", 1);

        chartPanel = new XChartPanel<>(chart);
        chartPanel.setPreferredSize(new Dimension(400, 300));
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateChart(Connection conn, String table, int startRow, int endRow) {
        Map<String, Integer> protocolCounts = new HashMap<>();
        String sql = "SELECT protocol, COUNT(*) AS cnt FROM (" +
                " SELECT protocol FROM " + table +
                " ORDER BY id ASC LIMIT ? OFFSET ?" +
                ") AS sub GROUP BY protocol ORDER BY cnt DESC";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, endRow - startRow + 1);
            stmt.setInt(2, startRow - 1);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String proto = rs.getString("protocol");
                if (proto == null || proto.trim().isEmpty()) {
                    proto = "Unknown";
                }
                protocolCounts.put(proto, rs.getInt("cnt"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        chart.getSeriesMap().clear();

        if (protocolCounts.isEmpty()) {
            chart.addSeries("No Data", 1);
        } else {
            protocolCounts.forEach((proto, count) -> {
                try {
                    chart.addSeries(proto, count);
                } catch (Exception e) {
                    System.err.println("Error adding series: " + proto);
                }
            });
        }
        chartPanel.revalidate();
        chartPanel.repaint();
    }
}
