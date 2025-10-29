import mysql.connector
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="pass",
    database="packetsnifferdb"
)
c = conn.cursor()
gap = 0
c.execute('''
CREATE TABLE IF NOT EXISTS packets_live (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DOUBLE,
    src_mac VARCHAR(17),
    dst_mac VARCHAR(17),
    eth_type INT,
    ip_version SMALLINT,
    ihl SMALLINT,
    tos SMALLINT,
    ip_id INT,
    frag_flags INT,
    ip_options TEXT,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    protocol VARCHAR(10),
    src_port INT,
    dst_port INT,
    tcp_window INT,
    tcp_seq BIGINT,
    tcp_ack BIGINT,
    tcp_urgptr INT,
    tcp_options TEXT,
    udp_len INT,
    udp_chksum INT,
    payload_size INT,
    payload_hex LONGTEXT
    )
''')
conn.commit()


def get_tcp_options(tcp):
    if tcp.options:
        return str(tcp.options)
    return None


def process_packet(pkt):
    timestamp = pkt.time

    src_mac = dst_mac = eth_type = None
    ip_version = ihl = tos = ip_id = frag_flags = None
    ip_options = src_ip = dst_ip = protocol = None
    src_port = dst_port = tcp_window = tcp_seq = tcp_ack = tcp_urgptr = None
    tcp_options = udp_len = udp_chksum = None
    payload_size = 0
    payload_hex = ''
    raw_bytes = bytes(pkt)

    if Ether in pkt:
        eth = pkt[Ether]
        src_mac = eth.src
        dst_mac = eth.dst
        eth_type = eth.type

    if IP in pkt:
        ip = pkt[IP]
        ip_version = ip.version
        ihl = ip.ihl
        tos = ip.tos
        ip_id = ip.id
        frag_flags = int(ip.flags)
        ip_options = str(ip.options) if ip.options else None
        src_ip = ip.src
        dst_ip = ip.dst
        if TCP in pkt:
            protocol = 'TCP'
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_window = tcp.window
            tcp_seq = tcp.seq
            tcp_ack = tcp.ack
            tcp_urgptr = tcp.urgptr
            tcp_options = get_tcp_options(tcp)
            if Raw in tcp:
                payload_size = len(tcp[Raw].load)
                payload_hex = tcp[Raw].load.hex()
        elif UDP in pkt:
            protocol = 'UDP'
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            udp_len = udp.len
            udp_chksum = udp.chksum
            if Raw in udp:
                payload_size = len(udp[Raw].load)
                payload_hex = udp[Raw].load.hex()
        elif ICMP in pkt:
            protocol = 'ICMP'
            if Raw in ip:
                payload_size = len(ip[Raw].load)
                payload_hex = ip[Raw].load.hex()
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        ip_version = 6
        ihl = ip6.plen
        tos = ip6.tc
        frag_flags = ip6.fl
        src_ip = ip6.src
        dst_ip = ip6.dst
        if TCP in pkt:
            protocol = 'TCP'
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_window = tcp.window
            tcp_seq = tcp.seq
            tcp_ack = tcp.ack
            tcp_urgptr = tcp.urgptr
            tcp_options = get_tcp_options(tcp)
            if Raw in tcp:
                payload_size = len(tcp[Raw].load)
                payload_hex = tcp[Raw].load.hex()
        elif UDP in pkt:
            protocol = 'UDP'
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            udp_len = udp.len
            udp_chksum = udp.chksum
            if Raw in udp:
                payload_size = len(udp[Raw].load)
                payload_hex = udp[Raw].load.hex()

    sql = '''
    INSERT INTO packets_live (
        timestamp, src_mac, dst_mac, eth_type, ip_version, ihl, tos, ip_id, frag_flags, ip_options,
        src_ip, dst_ip, protocol, src_port, dst_port,
        tcp_window, tcp_seq, tcp_ack, tcp_urgptr, tcp_options,
        udp_len, udp_chksum, payload_size, payload_hex
    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    '''
    values = (
        timestamp, src_mac, dst_mac, eth_type, ip_version, ihl, tos, ip_id, frag_flags, ip_options,
        src_ip, dst_ip, protocol, src_port, dst_port,
        tcp_window, tcp_seq, tcp_ack, tcp_urgptr, tcp_options,
        udp_len, udp_chksum, payload_size, payload_hex
    )
    c.execute(sql, values)
    conn.commit()

    print(f"[{timestamp} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}", end="")
    global gap
    if (gap == 0):
        print()
        gap = 1
    else :
        gap = 0

print("Starting packet capture (IPv4 & IPv6)...")
sniff(prn=process_packet, store=False)
