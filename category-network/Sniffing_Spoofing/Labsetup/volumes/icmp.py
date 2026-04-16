from scapy.all import *
a = IP()
a.dst = '10.9.0.5'

b = ICMP()
p = a/b 
reply = sr1(p, verbose=0, timeout=1)

reply.show()
