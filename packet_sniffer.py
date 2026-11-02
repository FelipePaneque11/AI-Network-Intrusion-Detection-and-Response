import scapy.all as scapy
from datetime import datetime, timezone

counter = 0
packets = {}

def process_packets(packet):
    global counter

    #Skip packets without an IPv4 layer.
    if not packet.haslayer(scapy.IP):
        return

    #---------------------------------------------------------
    #Extract source and destination IP Addresses
    #---------------------------------------------------------
    
    source_ip = packet[scapy.IP].src
    destination_ip = packet[scapy.IP].dst
    source_port = None
    destination_port = None
    packet_size = len(packet)
    timestamp = float(packet.time)
    tcp_flags = None

    #timestamp format
    dt_object = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    time = dt_object.strftime(" %H:%M:%S %d-%m-%Y")


    #-------------------------------------------------------
    #TCP Flags
    # [S]	SYN	Initiates a TCP connection
    # [A]	ACK	Acknowledges received data
    # [F]	FIN	Requests connection termination
    # [R]	RST	Resets a connection
    # [P]	PSH	Requests prompt delivery of data
    # [U]	URG	Indicates urgent data
    #-------------------------------------------------------
    

    #---------------------------------------------------------
    # Identify the protocol and extract available ports
    #---------------------------------------------------------

    if packet.haslayer(scapy.TCP):
        protocol = "TCP"
        source_port = packet[scapy.TCP].sport
        destination_port = packet[scapy.TCP].dport
        tcp_flags = str(packet[scapy.TCP].flags)

    elif packet.haslayer(scapy.UDP):
        protocol = "UDP"
        source_port = packet[scapy.UDP].sport
        destination_port = packet[scapy.UDP].dport

    elif packet.haslayer(scapy.ICMP):
        protocol = "ICMP"

    else:
        protocol = "Other"

    counter += 1
    packets[counter] = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "Packet size": packet_size,
        "Time": time,
        "TCP Flag": tcp_flags,
        "Timestamp": timestamp
    }

    print(f"Packet {counter},\n {packets[counter]} \n")


def sniff():
    scapy.sniff(
        store=False,
        prn=process_packets
    )

#show selected interface
print("Selected network interface: " + scapy.conf.iface.name)
#start capturing packets
sniff()
