import pyshark
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to add suspicious IPs to the threat list if they meet a certain threshold
def add_to_threatlist(threatlist, ip, reason):
    threatlist.append(f"Suspicious activity from {ip}: {reason}")

# Function to detect FTP traffic
def detect_ftp_traffic(packets, threatlist):
    for packet in packets:
        if hasattr(packet, 'ftp'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            add_to_threatlist(threatlist, src_ip, f"FTP traffic detected to {dst_ip}")

# Function to detect repeated failed connections (SYN flood attempts)
def detect_failed_connections(packets, threatlist, threshold=3):
    failed_connections = {}
    
    for packet in packets:
        if hasattr(packet, 'tcp') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':  # SYN but no ACK
            src_dst_pair = (packet.ip.src, packet.ip.dst)
            failed_connections[src_dst_pair] = failed_connections.get(src_dst_pair, 0) + 1

           
            if failed_connections[src_dst_pair] > threshold:
                add_to_threatlist(threatlist, packet.ip.src, f"Repeated failed connections to {packet.ip.dst}")

# Function to detect ICMP scan
def detect_icmp_scan(packets, threatlist, threshold=50):
    icmp_count = {}
    
    for packet in packets:
        if hasattr(packet, 'icmp'):
            src_ip = packet.ip.src
            icmp_count[src_ip] = icmp_count.get(src_ip, 0) + 1
            
            
            if icmp_count[src_ip] > threshold:
                add_to_threatlist(threatlist, src_ip, f"Potential ICMP scan detected with {icmp_count[src_ip]} packets")

# Function to run all detection functions and summarize results
def analyze_pcap(file_path):
    threatlist = []
    try:
        # Load the PCAP file
        capture = pyshark.FileCapture(file_path)

        # Run detection functions
        detect_ftp_traffic(capture, threatlist)
        detect_failed_connections(capture, threatlist, threshold=3)
        detect_icmp_scan(capture, threatlist, threshold=50)
        capture.close()
        
        # Display the results
        if threatlist:
            results = "\n".join(threatlist)
            messagebox.showinfo("Threat Detection Results", results)
        else:
            messagebox.showinfo("Threat Detection Results", "No threats detected.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while analyzing the file:\n{str(e)}")

# GUI to prompt user for file path
def select_file():
    root = tk.Tk()
    root.withdraw()  
    file_path = filedialog.askopenfilename(
        title="Select a PCAP File",
        filetypes=(("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*"))
    )
    if file_path:
        analyze_pcap(file_path)
    else:
        messagebox.showwarning("No File Selected", "Please select a PCAP file to analyze.")

if __name__ == "__main__":
    select_file()
