from scapy.all import *
a = IP()
a.dst = '10.9.0.5'

b = ICMP()
p = a/b 
send(p, verbose=0)

def print_pkt(pkt):
    if IP in pkt and pkt[ICMP].type == 0:
        pkt.show()

pkt = sniff(iface='br-cb7350ebd8ea', filter='icmp', prn=print_pkt)
