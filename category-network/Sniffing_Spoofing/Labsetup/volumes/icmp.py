import sys
from scapy.all import *
a = IP()
a.dst = sys.argv[1]

b = ICMP()
p = a/b 
reply = sr1(p, verbose=0, timeout=1)

reply.show()
