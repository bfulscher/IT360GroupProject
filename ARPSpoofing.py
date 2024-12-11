from scapy.all import rdpcap, ARP

def detect_arp_spoofing(pcap_file):
    packets = rdpcap(pcap_file)
    arp_table = {}
    potential_spoofs = []

    for packet in packets:
        if ARP in packet and packet[ARP].op == 1:  #ARP request
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            #Check for spoofing
            if src_ip not in arp_table:
                arp_table[src_ip] = src_mac
            else:
                if arp_table[src_ip] != src_mac:
                    potential_spoofs.append((src_ip, src_mac, arp_table[src_ip]))
                    arp_table[src_ip] = src_mac 

    return potential_spoofs

def main():
    pcap_file = input("Enter the path to the pcap file: ").strip()
    
    try:
        spoofs = detect_arp_spoofing(pcap_file)

        if spoofs:
            print("Potential ARP Spoofing detected:")
            for ip, mac1, mac2 in spoofs:
                print(f"IP: {ip} - MAC1: {mac1} - MAC2: {mac2}")
        else:
            print("No ARP spoofing detected.")
    except FileNotFoundError:
        print("Error: File not found. Please check the path and try again.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
