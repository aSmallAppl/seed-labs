from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-d96734b3a6af', filter='icmp', prn=print_pkt)
# pkt = sniff(iface='br-d96734b3a6af', filter='src 10.9.0.5 and tcp port 23', prn=print_pkt)
# pkt = sniff(iface='br-d96734b3a6af', filter='net 128.230.0.0/16', prn=print_pkt)
