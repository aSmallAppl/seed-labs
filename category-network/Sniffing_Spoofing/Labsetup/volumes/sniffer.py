from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-f23474d63baf', filter='icmp', prn=print_pkt)
# pkt = sniff(iface='br-f23474d63baf', filter='src 10.9.0.5 and tcp port 80', prn=print_pkt)
# pkt = sniff(iface='br-f23474d63baf', filter='net 192.168.2.0/24', prn=print_pkt)