package app;

import org.knowm.xchart.XYChart;
import org.knowm.xchart.XYChartBuilder;
import org.knowm.xchart.XYSeries;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.*;

public class TimeGraph extends JPanel {

    private final XYChart chart;
    private final XChartPanel<XYChart> chartPanel;

    public TimeGraph() {
        setLayout(new BorderLayout());

        chart = new XYChartBuilder()
                .width(600)
                .height(300)
                .title("Packets per Second")
                .xAxisTitle("Time (s)")
                .yAxisTitle("Packets/s")
                .build();

        chart.getStyler().setDefaultSeriesRenderStyle(XYSeries.XYSeriesRenderStyle.Line);
        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setXAxisTicksVisible(false);
        chart.getStyler().setYAxisTicksVisible(false);
        chart.getStyler().setMarkerSize(2);

        chart.addSeries("Packets/s", new double[]{0}, new double[]{0});

        chartPanel = new XChartPanel<>(chart);
        chartPanel.setPreferredSize(new Dimension(600, 300));
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateGraph(Connection conn, int startRow, int endRow) {
        String sql = "SELECT timestamp FROM packets_archive " +
                "WHERE id BETWEEN ? AND ? ORDER BY timestamp ASC";

        Map<Long, Integer> perSecondCounts = new TreeMap<>();

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, startRow);
            stmt.setInt(2, endRow);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                double ts = rs.getDouble("timestamp");
                long sec = (long) ts; // bucketize by integer seconds
                perSecondCounts.put(sec, perSecondCounts.getOrDefault(sec, 0) + 1);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        chart.getSeriesMap().clear();

        if (perSecondCounts.isEmpty()) {
            chart.addSeries("Packets/s", new double[]{0}, new double[]{0});
        } else {
            // use relative time starting from t0
            long first = perSecondCounts.keySet().iterator().next();
            double[] x = perSecondCounts.keySet().stream().mapToDouble(sec -> sec - first).toArray();
            double[] y = perSecondCounts.values().stream().mapToDouble(Integer::doubleValue).toArray();

            chart.addSeries("Packets/s", x, y);
        }

        chartPanel.revalidate();
        chartPanel.repaint();
    }
}
