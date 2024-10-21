import pyshark
import pandas as pd
import plotly.express as px
from collections import Counter

# Load the pcap file
cap = pyshark.FileCapture(r'C:\Users\User\Downloads\capture_file.pcap')

# Step 1: Collect packet types
packet_types = Counter()
ip_stats = Counter()
ftp_packets = 0
icmp_port_scans = 0
threat_list = []

for packet in cap:
    # Count packet types
    if hasattr(packet, 'highest_layer'):
        packet_types[packet.highest_layer] += 1

    # Count IP statistics
    if hasattr(packet, 'ip'):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        ip_stats[(src_ip, dst_ip)] += 1

    # Count FTP packets
    if hasattr(packet, 'ftp'):
        ftp_packets += 1

    # Check for ICMP port scans 
    if hasattr(packet, 'icmp'):
        icmp_port_scans += 1  

# Step 3: Create the DataFrame 
df = pd.DataFrame(ip_stats.items(), columns=['IP Pair', 'Count'])
df = df.dropna()  # Drop any NaN values, if present
df['IP Pair'] = df['IP Pair'].apply(lambda x: f"{x[0]} -> {x[1]}")  # Convert to string format
df = df.reset_index(drop=True)  # Reset index

# Print the DataFrame 
print(df.head())

# Step 4: Data Visualization using Plotly
fig = px.bar(df, x='IP Pair', y='Count', title='IP Communication Statistics', 
             labels={'IP Pair': 'IP Pair', 'Count': 'Count'},
             hover_data=['Count'])
fig.update_layout(xaxis_tickangle=-45)  # Rotate x labels 
fig.show()  # Show the interactive plot

# Step 5: Print the threat list
print("Threat List:", threat_list)

# Summary statistics
print("Packet Types:", packet_types)
print("IP Statistics:", ip_stats)
print("FTP Packets:", ftp_packets)
print("ICMP Port Scans:", icmp_port_scans)
