package app;

import org.knowm.xchart.XYChart;
import org.knowm.xchart.XYChartBuilder;
import org.knowm.xchart.XYSeries;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.*;
import java.util.*;

public class ProtocolTimeGraph extends JPanel {

    private final XYChart chart;
    private final XChartPanel<XYChart> chartPanel;

    public ProtocolTimeGraph() {
        setLayout(new BorderLayout());

        chart = new XYChartBuilder()
                .width(600)
                .height(300)
                .title("Packets/sec by Protocol")
                .xAxisTitle("Time (s)")
                .yAxisTitle("Packets/sec")
                .build();

        chart.getStyler().setDefaultSeriesRenderStyle(XYSeries.XYSeriesRenderStyle.Line);
        chart.getStyler().setLegendVisible(true);
        chart.getStyler().setMarkerSize(2);
        chart.getStyler().setXAxisDecimalPattern("0");

        chart.addSeries("No Data", new double[]{0}, new double[]{0});

        chartPanel = new XChartPanel<>(chart);
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateGraph(Connection conn, int startRow, int endRow) {
        String sql = "SELECT timestamp, protocol FROM packets_archive " +
                "WHERE id BETWEEN ? AND ? ORDER BY timestamp ASC";

        Map<String, Map<Long, Integer>> counts = new HashMap<>();

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, startRow);
            stmt.setInt(2, endRow);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                double ts = rs.getDouble("timestamp");
                String proto = rs.getString("protocol");
                if (proto == null || proto.isBlank()) proto = "UNKNOWN";

                long secBucket = (long) ts; // truncate to 1-second bins

                counts.putIfAbsent(proto, new TreeMap<>());
                Map<Long, Integer> protoCounts = counts.get(proto);
                protoCounts.put(secBucket, protoCounts.getOrDefault(secBucket, 0) + 1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return;
        }

        chart.getSeriesMap().clear();

        if (counts.isEmpty()) {
            chart.addSeries("No Data", new double[]{0}, new double[]{0});
        } else {
            for (Map.Entry<String, Map<Long, Integer>> entry : counts.entrySet()) {
                String proto = entry.getKey();
                Map<Long, Integer> data = entry.getValue();

                double[] x = data.keySet().stream().mapToDouble(Long::doubleValue).toArray();
                double[] y = data.values().stream().mapToDouble(Integer::doubleValue).toArray();

                chart.addSeries(proto, x, y);
            }
        }

        chartPanel.revalidate();
        chartPanel.repaint();
    }
}
