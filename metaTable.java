package app;

import java.sql.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class metaTable {

    public static JTable loadSessionsTable() {
        String[] columnNames = {
            "ID", "Name", "Start Row", "Entry Count", "Start Datetime", "End Datetime"
        };
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);

        String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
        String user = "root";
        String password = "pass";
        String sql = "SELECT id, name, start_row, entry_count, start_datetime, end_datetime FROM archive_metadata";

        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Object[] row = {
                    rs.getInt("id"),
                    rs.getString("name"),
                    rs.getInt("start_row"),
                    rs.getInt("entry_count"),
                    rs.getTimestamp("start_datetime"),
                    rs.getTimestamp("end_datetime")
                };
                model.addRow(row);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        return table;
    }

    public static JTable loadPacketsTable() {
        String[] columnNames = {
            "ID", "Timestamp", "Src IP", "Dst IP", "Protocol"
        };
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);

        String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
        String user = "root";
        String password = "pass";
        String sql = "SELECT id, timestamp, src_ip, dst_ip, protocol FROM packets_live";

        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Object[] row = {
                    rs.getInt("id"),
                    rs.getDouble("timestamp"),
                    rs.getString("src_ip"),
                    rs.getString("dst_ip"),
                    rs.getString("protocol")
                };
                model.addRow(row);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        return table;
    }
}
