from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-cb7350ebd8ea', filter='icmp', prn=print_pkt)
