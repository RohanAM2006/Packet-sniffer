
Project Overview

This project implements a simple network packet sniffer and analytics tool. It captures network traffic, analyses protocols, payload sizes, top talkers, time-based traffic graphs, and presents visualisations of the gathered data.


<img width="1267" height="131" alt="image" src="https://github.com/user-attachments/assets/c39c1121-5326-4db0-b585-9ad3933be9b6" />
<img width="1210" height="711" alt="image" src="https://github.com/user-attachments/assets/1a667da4-859d-45cf-bfdf-05e67368ea7f" />



Key Features

Capture raw network packets using Python/Java components

Support for multiple protocols (e.g., TCP, UDP, ICMP)

Generate analytics:

Histogram of packet sizes

Payload size graph

Pie chart of protocol distributions

Time-based graphs of protocol usage and traffic volume

Top talkers (hosts sending/receiving most packets)

Store captured data in a simple database (or file) for analysis

Visualise results with Java UI components (charts)


Project Structure
Packet-sniffer/
├── sniffer.py                # Python packet capture script  
├── java-folder/              # Java source files for analysis and UI  
│   ├── PacketSizeHistogram.java  
│   ├── PayloadSizeGraph.java  
│   ├── ProtocolPieChart.java  
│   ├── ProtocolTimeGraph.java  
│   ├── TimeGraph.java  
│   ├── TopTalkersChart.java  
│   └── index.java            # Main UI entry point  
├── packetSnifferdb/          # Database or storage files  
└── README.md                 # This file  
