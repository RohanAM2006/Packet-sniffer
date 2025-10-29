package app;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.sql.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

public class index {
    static boolean running = false;
    static Process mainSniffprocess;
    static Thread liveThread;
    static String savedName = null;
    static String searchedName = null;
    static String filter = null;

    private static JPanel chartPanelContainer;

    private static TimeGraph timeGraph2;
    private static ProtocolTimeGraph protocolTimeGraph;
    private static ProtocolPieChart protocolPieChart;
    private static TopTalkersChart topTalkersChart;
    private static PacketSizeHistogram packetSizeHistogram;
    private static PayloadSizeGraph payloadSizeGraph;

    private static JComboBox<String> chartSelector;
    private JButton generateButton;

    private static Connection conn;
    private static int chartStartRow = 0;
    private static int chartEndRow = 0;


    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Packet Sniffer");
            JTabbedPane tabbedPane = new JTabbedPane();

            JPanel homeTab = new JPanel();
            homeTab.setLayout(null);

            JButton liveSniffToggle = new JButton("Sniff");
            liveSniffToggle.setBackground(java.awt.Color.GREEN);
            liveSniffToggle.setForeground(java.awt.Color.WHITE);
            liveSniffToggle.setBounds(10, 10, 75, 25);
            liveSniffToggle.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(liveSniffToggle);

            JTextArea terminal = new JTextArea();
            terminal.setEditable(false);
            terminal.setFont(new Font("Monospaced", Font.PLAIN, 12));
            terminal.setBackground(Color.BLACK);
            terminal.setForeground(Color.WHITE);

            JScrollPane scrollPane = new JScrollPane(terminal);
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
            scrollPane.setBounds(10, 45, 1515, 200);
            homeTab.add(scrollPane);

            liveSniffToggle.addActionListener((ActionEvent e) -> {
                if (!running){
                    startPython(terminal);
                    appendText(terminal, "Stating Capture...");
                    SwingUtilities.invokeLater(() -> liveSniffToggle.setText("Stop"));
                    liveSniffToggle.setBackground(java.awt.Color.RED);
                }
                else{ 
                    stopPython();
                    SwingUtilities.invokeLater(() -> liveSniffToggle.setText("Sniff"));
                    liveSniffToggle.setBackground(java.awt.Color.GREEN);
                }
            });

            JButton restartLive = new JButton("Reset");
            restartLive.addActionListener((ActionEvent e) -> {
                stopPython();
                SwingUtilities.invokeLater(() -> liveSniffToggle.setText("Sniff"));
                liveSniffToggle.setBackground(java.awt.Color.GREEN);
                clearDB("packets_live");
                terminal.setText("");

            });
            restartLive.setBounds(95, 10, 75, 25);
            restartLive.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(restartLive);

            JButton dumpLive = new JButton("Dump");
            dumpLive.addActionListener((ActionEvent e) -> {

            });
            dumpLive.setBounds(1450, 10, 75, 25);
            dumpLive.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(dumpLive);

            JButton saveSession = new JButton("Save");
            saveSession.addActionListener((ActionEvent e) -> {
                JDialog dialog = new JDialog(frame, "Enter Name", true);
                dialog.setSize(300, 150);
                dialog.setLayout(null);
                dialog.setLocationRelativeTo(frame);

                JLabel label = new JLabel("Name:");
                label.setBounds(20, 20, 80, 25);
                dialog.add(label);

                JTextField nameField = new JTextField();
                nameField.setBounds(80, 20, 180, 25);
                dialog.add(nameField);

                JButton saveButton = new JButton("Save");
                saveButton.setBounds(100, 60, 80, 30);
                dialog.add(saveButton);

                saveButton.addActionListener(ev -> {
                    savedName = nameField.getText().trim();
                    dialog.dispose();
                    System.out.println("Saved Name: " + savedName);
                });

                dialog.setVisible(true);


                stopPython();
                SwingUtilities.invokeLater(() -> liveSniffToggle.setText("Sniff"));
                liveSniffToggle.setBackground(java.awt.Color.GREEN);
                
                String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
                String user = "root";
                String password = "pass";

                try (Connection conn = DriverManager.getConnection(url, user, password)) {
                    int lastId = 0;
                    try (Statement stmt = conn.createStatement();
                        
                        ResultSet rs = stmt.executeQuery("SELECT id FROM packets_archive ORDER BY id DESC LIMIT 1")) {
                        if(rs.next()) lastId = rs.getInt("id");
                    }

                    try (Statement stmt = conn.createStatement()) {
                        String i2ar = "INSERT INTO packets_archive ("
                                + "timestamp, src_mac, dst_mac, eth_type, ip_version, ihl, tos, ip_id, frag_flags, ip_options, "
                                + "src_ip, dst_ip, protocol, src_port, dst_port, tcp_window, tcp_seq, tcp_ack, tcp_urgptr, tcp_options, "
                                + "udp_len, udp_chksum, payload_size, payload_hex"
                                + ") "
                                + "SELECT "
                                + "timestamp, src_mac, dst_mac, eth_type, ip_version, ihl, tos, ip_id, frag_flags, ip_options, "
                                + "src_ip, dst_ip, protocol, src_port, dst_port, tcp_window, tcp_seq, tcp_ack, tcp_urgptr, tcp_options, "
                                + "udp_len, udp_chksum, payload_size, payload_hex "
                                + "FROM packets_live";
                        stmt.executeUpdate(i2ar);
                    }

                    int totalRows = 0;
                    try (Statement stmt = conn.createStatement();
                        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) AS total FROM packets_live")) {
                        if(rs.next()) totalRows = rs.getInt("total");
                    }

                    double startts = 0, endts = 0; java.sql.Timestamp sts = null, ets = null;
                    try (Statement stmt = conn.createStatement()) {
                        ResultSet rsStart = stmt.executeQuery("SELECT timestamp FROM packets_live ORDER BY id ASC LIMIT 1");
                        if(rsStart.next()) {
                            startts = rsStart.getDouble("timestamp");
                            long smillis = (long) (startts * 1000);
                            sts = new java.sql.Timestamp(smillis);
                        }
                        rsStart.close();

                        ResultSet rsEnd = stmt.executeQuery("SELECT timestamp FROM packets_live ORDER BY id DESC LIMIT 1");
                        if(rsEnd.next()) {
                            endts = rsEnd.getDouble("timestamp");
                            long emillis = (long) (endts * 1000);
                            ets = new java.sql.Timestamp(emillis);
                        }
                        rsEnd.close();
                    }


                String sql = "INSERT INTO archive_metadata (name, start_row, entry_count, start_datetime, end_datetime) VALUES (?, ?, ?, ?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setString(1, savedName);
                    pstmt.setInt(2, lastId+1);
                    pstmt.setInt(3, totalRows);
                    pstmt.setTimestamp(4, sts);
                    pstmt.setTimestamp(5, ets);
                    pstmt.executeUpdate();
                }

                dialog.dispose();

                } catch (SQLException e1) {
                    e1.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Failed to save session: " + e1.getMessage());
                }
                dialog.setVisible(true);
            });

            saveSession.setBounds(1365, 10, 75, 25);
            saveSession.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(saveSession);

            JTextField seshNameF = new JTextField(20);
            String placeholder = "Enter Session Name";

            seshNameF.setForeground(Color.GRAY);
            seshNameF.setText(placeholder);

            seshNameF.addFocusListener(new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (seshNameF.getText().equals(placeholder)) {
                        seshNameF.setText("");
                        seshNameF.setForeground(Color.BLACK);
                    }
                }

                public void focusLost(FocusEvent e) {
                    if (seshNameF.getText().isEmpty()) {
                        seshNameF.setForeground(Color.GRAY);
                        seshNameF.setText(placeholder);
                    }
                }
            });
            seshNameF.setBounds(95, 255, 255, 25);
            homeTab.add(seshNameF);

            JTextField FilterTx = new JTextField(20);
            String placeholder2 = "Enter Filter to Apply";

            FilterTx.setForeground(Color.GRAY);
            FilterTx.setText(placeholder2);

            FilterTx.addFocusListener(new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (FilterTx.getText().equals(placeholder2)) {
                        FilterTx.setText("");
                        FilterTx.setForeground(Color.BLACK);
                    }
                }

                public void focusLost(FocusEvent e) {
                    if (FilterTx.getText().isEmpty()) {
                        FilterTx.setForeground(Color.GRAY);
                        FilterTx.setText(placeholder2);
                    }
                }
            });
            FilterTx.setBounds(445, 255, 255, 25);
            homeTab.add(FilterTx);

            String[] columnNames = {"ID", "Timestamp", "Src IP", "Dst IP", "Protocol"};
            DefaultTableModel model = new DefaultTableModel(columnNames, 0);
            //---------------------------------

            int offset = 50;
            int limit = 50;

            String sql = "SELECT * FROM packets_live ORDER BY id ASC LIMIT ? OFFSET ?";
            String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
            String user = "root";
            String password = "pass";

            try (Connection conn = DriverManager.getConnection(url, user, password)){
                PreparedStatement stmt = conn.prepareStatement(sql);

                stmt.setInt(1, limit);
                stmt.setInt(2, offset);

                ResultSet rs = stmt.executeQuery();

                while (rs.next()) {
                    Object[] rowData = {
                        rs.getInt("id"),
                        rs.getTimestamp("timestamp"),
                        rs.getString("src_ip"),
                        rs.getString("dst_ip"),
                        rs.getString("protocol")
                    };
                    model.addRow(rowData);
                }
            }catch(Exception eeee){
                eeee.printStackTrace();
            }
            JTable ptable = new JTable(model);
            JScrollPane scrollPaneptable = new JScrollPane(ptable);
            TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
            ptable.setRowSorter(sorter);
            scrollPaneptable.setBounds(10, 285, 1115, 450);
            ptable.getColumnModel().getColumn(0).setMinWidth(50);
            ptable.getColumnModel().getColumn(0).setMaxWidth(50);
            homeTab.add(scrollPaneptable);

            JTextArea info = new JTextArea();
            info.setFont(new Font("Consolas", Font.BOLD, 14));
            info.setEditable(false);
            info.setLineWrap(true);
            info.setWrapStyleWord(true);
            JScrollPane scrollPaneI = new JScrollPane(info);
            scrollPaneI.setBounds(1135, 285, 360, 450);
            homeTab.add(scrollPaneI);
            
            ptable.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    int row = ptable.getSelectedRow();
                    if (row != -1) {
                        Object idValue = ptable.getValueAt(row, 0);
                        if (idValue == null) return;

                        String idStr = idValue.toString();
  
                        String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
                        String user = "root";
                        String password = "pass";
                        String sql = "SELECT * FROM packets_archive WHERE id = ?";

                        try (Connection conn = DriverManager.getConnection(url, user, password);
                            PreparedStatement stmt = conn.prepareStatement(sql)) {

                            stmt.setInt(1, Integer.parseInt(idStr));
                            ResultSet rs = stmt.executeQuery();

                            if (rs.next()) {
                                StringBuilder sb = new StringBuilder();

                                sb.append("\nPACKET DETAILS\n");
                                sb.append(String.format("%-20s: %s%n", " Timestamp", rs.getDouble("timestamp")));
                                sb.append(String.format("%-20s: %s%n", " Source MAC", rs.getString("src_mac")));
                                sb.append(String.format("%-20s: %s%n", " Destination MAC", rs.getString("dst_mac")));
                                sb.append(String.format("%-20s: %s%n", " EtherType", rs.getInt("eth_type")));
                                sb.append(String.format("%-20s: %s%n", " IP Version", rs.getInt("ip_version")));
                                sb.append(String.format("%-20s: %s%n", " Protocol", rs.getString("protocol")));
                                sb.append(String.format("%-20s: %s%n", " Source IP", rs.getString("src_ip")));
                                sb.append(String.format("%-20s: %s%n", " Destination IP", rs.getString("dst_ip")));
                                sb.append(String.format("%-20s: %s%n", " Source Port", rs.getInt("src_port")));
                                sb.append(String.format("%-20s: %s%n", " Destination Port", rs.getInt("dst_port")));
                                sb.append(String.format("%-20s: %s%n", " Payload Size", rs.getInt("payload_size")));

                                sb.append("\nTCP/UDP DETAILS\n");
                                sb.append(String.format("%-20s: %s%n", " TCP Window", rs.getInt("tcp_window")));
                                sb.append(String.format("%-20s: %s%n", " TCP Sequence", rs.getLong("tcp_seq")));
                                sb.append(String.format("%-20s: %s%n", " TCP Ack", rs.getLong("tcp_ack")));
                                sb.append(String.format("%-20s: %s%n", " UDP Length", rs.getInt("udp_len")));
                                sb.append(String.format("%-20s: %s%n", " UDP Checksum", rs.getInt("udp_chksum")));

                                sb.append("\nRAW PAYLOAD (HEX)\n");

                                String payload = rs.getString("payload_hex");
                                if (payload != null) {
                                    if (payload.length() > 1024) {
                                        sb.append(payload.substring(0, 1024))
                                        .append("\n...[truncated] (")
                                        .append(payload.length())
                                        .append(" chars total)");
                                    } else {
                                        sb.append(payload);
                                    }
                                } else {
                                    sb.append("(no payload data)");
                                }

                                info.setFont(new Font("Consolas", Font.PLAIN, 12));
                                info.setText(sb.toString());
                            }
                            else {
                                info.setText("No row found with timestamp: " + idStr);
                            }


                        } catch (SQLException ex) {
                            ex.printStackTrace();
                            info.setText("Database error.");
                        } catch (NumberFormatException ex) {
                            info.setText("Invalid ID format.");
                        }
                    }
                }
            });


            JButton pSearch = new JButton("Search");
            pSearch.addActionListener((ActionEvent e) -> {
                String searchedName = seshNameF.getText();
                if (searchedName.equals("Enter Session Name")) {
                    searchedName = "";
                }
                
                String sql1 = "SELECT * FROM archive_metadata WHERE name = ?";
                String url1 = "jdbc:mysql://localhost:3306/packetsnifferdb";
                
                try (Connection conn = DriverManager.getConnection(url1, "root", "pass");
                    PreparedStatement stmt = conn.prepareStatement(sql1)) {

                    stmt.setString(1, searchedName);
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        System.out.println("Found row: " + rs.getString("start_row"));
                        updateJTable(ptable, "packetsnifferdb", "packets_archive", rs.getInt("start_row"), rs.getInt("start_row") + rs.getInt("entry_count"), "id", "timestamp", "src_ip", "dst_ip", "protocol");
                        ptable.getColumnModel().getColumn(0).setMinWidth(50);
                        ptable.getColumnModel().getColumn(0).setMaxWidth(50);
                    } else {
                        System.out.println("No row with that ID.");
                    }

                } catch (SQLException ex) {
                    ex.printStackTrace();
                } catch (NumberFormatException ex) {
                    System.out.println("Invalid ID entered.");
                }

            });
            pSearch.setBounds(10, 255, 75, 25);
            pSearch.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(pSearch);

            JButton pFilter = new JButton("Filter");
            pFilter.addActionListener((ActionEvent e) -> {
                String filterK = FilterTx.getText();
                if (filterK.equals("Enter Filter to Apply")) {
                    filterK = "";
                }
                
                 if (filterK.trim().length() == 0) {
                        sorter.setRowFilter(null);
                    } else {
                        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + filterK));
                    }

            });
            pFilter.setBounds(360, 255, 75, 25);
            pFilter.setFont(new Font("Arial", Font.BOLD, 12));
            homeTab.add(pFilter);

            tabbedPane.addTab("Home", homeTab);

            


//------------------------------------------------------------------------------------------------------------------------------


            JPanel stat = new JPanel();
            stat.setLayout(null);
            tabbedPane.addTab("Stat", stat);

            TimeGraph timeGraph = new TimeGraph();
            timeGraph.setBounds(800, 400, 600, 300);
            stat.add(timeGraph);

            JTable packetTable = metaTable.loadPacketsTable();
            packetTable.setAutoCreateRowSorter(true);
            packetTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            JScrollPane scrollp = new JScrollPane(packetTable);
            scrollp.setBounds(10,380,720,370);
            stat.add(scrollp);

            JTable sessionsTable = metaTable.loadSessionsTable();
            sessionsTable.setAutoCreateRowSorter(true);
            sessionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            sessionsTable.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    int row = sessionsTable.getSelectedRow();
                    if (row != -1) {
                        Object idValue = sessionsTable.getValueAt(row, 0);
                        if (idValue == null) return;
                    }
                    Object startR = sessionsTable.getValueAt(row,2);
                    Object entryC = sessionsTable.getValueAt(row, 3);
                    int startRow = (startR != null) ? Integer.parseInt(startR.toString()) : 0;  
                    int entryCount = (entryC != null) ? Integer.parseInt(entryC.toString()) : 0;
                    chartStartRow = startRow;
                    chartEndRow = startRow + entryCount;

                    updateJTable(packetTable, "packetsnifferdb", "packets_archive", startRow, startRow + entryCount, "id", "timestamp", "src_ip", "dst_ip", "protocol");
                    String url1 = "jdbc:mysql://localhost:3306/packetsnifferdb";
                    try (Connection con = DriverManager.getConnection(url1, "root", "pass")) {
                        timeGraph.updateGraph(con, startRow, startRow + entryCount);
                    } catch (Exception ee_e) {
                        ee_e.printStackTrace();
                    }
                }
            });

            JScrollPane scrollM = new JScrollPane(sessionsTable);
            scrollM.setBounds(10,10,720,350);
            stat.add(scrollM);

            JPanel controls = new JPanel();
            chartSelector = new JComboBox<>(new String[]{
                    "TimeGraph", "ProtocolTimeGraph", "ProtocolPieChart",
                    "TopTalkersChart", "PacketSizeHistogram", "PayloadSizeGraph"
            });
            JButton generateButton = new JButton("Generate");
            controls.add(chartSelector);
            controls.add(generateButton);
            controls.setBounds(800,10,600,50);
            stat.add(controls);

            chartPanelContainer = new JPanel();
            chartPanelContainer.setLayout(null);
            chartPanelContainer.setBounds(800, 70, 600, 300);
            stat.add(chartPanelContainer);

            timeGraph2 = new TimeGraph();
            protocolTimeGraph = new ProtocolTimeGraph();
            protocolPieChart = new ProtocolPieChart();
            topTalkersChart = new TopTalkersChart();
            packetSizeHistogram = new PacketSizeHistogram();
            payloadSizeGraph = new PayloadSizeGraph();

            generateButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    index ui = new index();
                    String url1 = "jdbc:mysql://localhost:3306/packetsnifferdb";
                    try (Connection conn = DriverManager.getConnection(url1, "root", "pass")) {
                        ui.showSelectedChart(conn, chartStartRow, chartEndRow);
                    } catch (Exception ee_e) {
                        ee_e.printStackTrace();
                    }
                }
            });

            frame.add(tabbedPane);

            frame.setExtendedState(JFrame.MAXIMIZED_BOTH);
            frame.setUndecorated(false);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setVisible(true);
            frame.setResizable(false);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                clearDB("packets_live");
                frame.dispose();
            }
        });
        });
    }

    public static void startPython(JTextArea terminal) {
        try {
            ProcessBuilder pb = new ProcessBuilder("python", "sniffer.py");
            pb.redirectErrorStream(true);
            mainSniffprocess = pb.start();

            running = true;
            BufferedReader reader = new BufferedReader(new InputStreamReader(mainSniffprocess.getInputStream()));

            liveThread = new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null && running) {
                        appendText(terminal, line);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try { reader.close(); } catch (IOException ignored) {}
                }
            });
            liveThread.start();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void appendText(JTextArea textArea, String text) {
        SwingUtilities.invokeLater(() -> {
            textArea.append(text + "\n");
            textArea.setCaretPosition(textArea.getDocument().getLength()); // auto-scroll
        });
    }

    public static void stopPython() {
        running = false;
        if (mainSniffprocess != null && mainSniffprocess.isAlive()) {
            mainSniffprocess.destroy();
        }
        System.out.println("Python stopped.");
    }

    public static void clearDB(String db){
        String url = "jdbc:mysql://localhost:3306/packetsnifferdb";
        String user = "root";
        String password = "pass";
        try {
            Connection conn = DriverManager.getConnection(url, user, password);
            String sql = "TRUNCATE TABLE " + db;
            Statement stmt = conn.createStatement();
            stmt.executeUpdate(sql);
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void updateJTable(JTable jTable, String dbName, String tableName, int startRow, int endRow, String... columns) {

        if (!tableName.matches("[A-Za-z0-9_]+")) {
            throw new IllegalArgumentException("Invalid table name");
        }

        String colList = (columns.length == 0) ? "*" : String.join(",", columns);
        int rowCount = endRow - startRow + 1;

        String url = "jdbc:mysql://localhost:3306/" + dbName;

        String sql = "SELECT " + colList + " FROM " + tableName + " LIMIT ? OFFSET ?";

        try (Connection conn = DriverManager.getConnection(url, "root", "pass");
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, rowCount);
            stmt.setInt(2, startRow - 1);

            ResultSet rs = stmt.executeQuery();
            ResultSetMetaData meta = rs.getMetaData();
            int colCount = meta.getColumnCount();

            DefaultTableModel model = (DefaultTableModel) jTable.getModel();
            model.setRowCount(0);
            model.setColumnCount(0);

            for (int i = 1; i <= colCount; i++) {
                model.addColumn(meta.getColumnName(i));
            }

            while (rs.next()) {
                Object[] row = new Object[colCount];
                for (int i = 1; i <= colCount; i++) {
                    row[i - 1] = rs.getObject(i);
                }
                model.addRow(row);
            }

            jTable.setModel(model);

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void showSelectedChart(Connection conn,int startRow, int endRow) {
        chartPanelContainer.removeAll();

        String selected = (String) chartSelector.getSelectedItem();
        JComponent chartToShow = null;

        switch (selected) {
            case "TimeGraph":
                timeGraph2.updateGraph(conn, startRow, endRow);
                chartToShow = timeGraph2;
                break;
            case "ProtocolTimeGraph":
                protocolTimeGraph.updateGraph(conn, startRow, endRow);
                chartToShow = protocolTimeGraph;
                break;
            case "ProtocolPieChart":
                protocolPieChart.updateChart(conn, "packets_archive", startRow, endRow);
                chartToShow = protocolPieChart;
                break;
            case "TopTalkersChart":
                topTalkersChart.updateChart(conn, "packets_archive", startRow, endRow);
                chartToShow = topTalkersChart;
                break;
            case "PacketSizeHistogram":
                packetSizeHistogram.updateChart(conn, "packets_archive", startRow, endRow);
                chartToShow = packetSizeHistogram;
                break;
            case "PayloadSizeGraph":
                payloadSizeGraph.updateGraph(conn, startRow, endRow);
                chartToShow = payloadSizeGraph;
                break;
        }

        if (chartToShow != null) {

            chartToShow.setBounds(0, 0, chartPanelContainer.getWidth(), chartPanelContainer.getHeight());
            chartPanelContainer.add(chartToShow);
        }

        chartPanelContainer.revalidate();
        chartPanelContainer.repaint();
    }

}
