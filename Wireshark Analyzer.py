import pyshark

# Load the PCAP file
capture = pyshark.FileCapture(r'C:\Users\User\Downloads\capture.pcap')

# Initialize the threat list to hold detected threats
threatlist = []

# Function to add suspicious IPs to the threat list if they meet a certain threshold
def add_to_threatlist(ip, reason):
    threatlist.append(f"Suspicious activity from {ip}: {reason}")

# Function to detect FTP traffic
def detect_ftp_traffic(packets):
    for packet in packets:
        if hasattr(packet, 'ftp'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            add_to_threatlist(src_ip, f"FTP traffic detected to {dst_ip}")

# Function to detect repeated failed connections (SYN flood attempts)
def detect_failed_connections(packets, threshold=5):
    failed_connections = {}
    
    for packet in packets:
        if hasattr(packet, 'tcp') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':  # Check for SYN but no ACK
            src_dst_pair = (packet.ip.src, packet.ip.dst)
            failed_connections[src_dst_pair] = failed_connections.get(src_dst_pair, 0) + 1

            # Add to threat list if it exceeds threshold
            if failed_connections[src_dst_pair] > threshold:
                add_to_threatlist(packet.ip.src, f"Repeated failed connections to {packet.ip.dst}")

# Function to detect ICMP scan
def detect_icmp_scan(packets, threshold=50):
    icmp_count = {}
    
    for packet in packets:
        if hasattr(packet, 'icmp'):
            src_ip = packet.ip.src
            icmp_count[src_ip] = icmp_count.get(src_ip, 0) + 1
            
            # If ICMP packet count from a single IP exceeds threshold, consider it a scan
            if icmp_count[src_ip] > threshold:
                add_to_threatlist(src_ip, f"Potential ICMP scan detected with {icmp_count[src_ip]} packets")

# Run all detection functions on the capture
detect_ftp_traffic(capture)
detect_failed_connections(capture, threshold=5)
detect_icmp_scan(capture, threshold=50)

# Print out the detected threats
if len(threatlist) > 0:
    for threat in threatlist:
        print(threat)
else:
    print("No threats detected.")
