package app;

import org.knowm.xchart.XYChart;
import org.knowm.xchart.XYChartBuilder;
import org.knowm.xchart.XYSeries.XYSeriesRenderStyle;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class PayloadSizeGraph extends JPanel {

    private XYChart chart;
    private XChartPanel<XYChart> chartPanel;

    public PayloadSizeGraph() {
        setLayout(new BorderLayout());

        chart = new XYChartBuilder()
                .width(600)
                .height(300)
                .title("Payload Size Over Time")
                .xAxisTitle("Time (s)")
                .yAxisTitle("Payload Size (bytes)")
                .build();

        chart.getStyler().setDefaultSeriesRenderStyle(XYSeriesRenderStyle.Line);

        chart.addSeries("Payload", List.of(0.0), List.of(0.0));

        chartPanel = new XChartPanel<>(chart);
        chartPanel.setPreferredSize(new Dimension(600, 300));
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateGraph(Connection conn, int startRow, int endRow) {
        List<Double> timestamps = new ArrayList<>();
        List<Double> payloadSizes = new ArrayList<>();

        String sql = "SELECT timestamp, payload_size FROM packets_archive ORDER BY id ASC LIMIT ? OFFSET ?";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, endRow - startRow + 1);
            stmt.setInt(2, startRow - 1);

            ResultSet rs = stmt.executeQuery();
            double t0 = -1;

            while (rs.next()) {
                double ts = rs.getDouble("timestamp");
                if (t0 < 0) t0 = ts;

                timestamps.add(ts - t0); // relative time
                payloadSizes.add((double) rs.getInt("payload_size"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        chart.updateXYSeries("Payload", timestamps, payloadSizes, null);
        chartPanel.revalidate();
        chartPanel.repaint();
    }
}
