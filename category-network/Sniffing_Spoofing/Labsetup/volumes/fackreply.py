from scapy.all import *
def print_pkt(pkt):
    if IP in pkt and pkt[ICMP].type == 8:  #  只抓请求包，不抓回复包
        pkt.show()
        
        a = IP()
        a.dst = pkt[IP].src
        a.src = pkt[IP].dst
        
        b = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        p = a / b / pkt[Raw].load
        send(p, verbose=0)

sniff(iface='br-cfefbbe8c0e2', filter='icmp', prn=print_pkt)
