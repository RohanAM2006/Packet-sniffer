package app;

import org.knowm.xchart.Histogram;
import org.knowm.xchart.XYChart;
import org.knowm.xchart.XYChartBuilder;
import org.knowm.xchart.XChartPanel;

import javax.swing.*;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class PacketSizeHistogram extends JPanel {

    private XYChart chart;
    private XChartPanel<XYChart> chartPanel;

    public PacketSizeHistogram() {
        setLayout(new BorderLayout());

        chart = new XYChartBuilder()
                .width(400)
                .height(300)
                .title("Packet Size Distribution")
                .xAxisTitle("Size (bytes)")
                .yAxisTitle("Count")
                .build();

        // Dummy series to prevent empty chart error
        List<Double> dummyX = new ArrayList<>();
        List<Double> dummyY = new ArrayList<>();
        dummyX.add(0.0);
        dummyY.add(0.0);
        chart.addSeries("Histogram", dummyX, dummyY);

        chartPanel = new XChartPanel<>(chart);
        chartPanel.setPreferredSize(new Dimension(400, 300));
        add(chartPanel, BorderLayout.CENTER);
    }

    public void updateChart(Connection conn, String table, int startRow, int endRow) {
        List<Double> sizes = new ArrayList<>();

        String sql = "SELECT payload_size FROM " + table + " ORDER BY id ASC LIMIT ? OFFSET ?";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, endRow - startRow + 1);
            stmt.setInt(2, startRow - 1);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                sizes.add((double) rs.getInt("payload_size")); // packet size in bytes
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        if (sizes.isEmpty()) {
            // Use dummy data to avoid empty Y-axis
            List<Double> dummyX = new ArrayList<>();
            List<Double> dummyY = new ArrayList<>();
            dummyX.add(0.0);
            dummyY.add(0.0);
            chart.updateXYSeries("Histogram", dummyX, dummyY, null);
        } else {
            Histogram hist = new Histogram(sizes, 20); // 20 bins
            chart.updateXYSeries("Histogram", hist.getxAxisData(), hist.getyAxisData(), null);
        }

        chartPanel.revalidate();
        chartPanel.repaint();
    }
}

