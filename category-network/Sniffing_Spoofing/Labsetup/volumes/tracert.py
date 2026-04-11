from scapy.all import *

# 目标 IP
target = "8.8.8.8"

print(f"Traceroute to {target}")

# TTL 从 1 到 30
for ttl in range(1, 31):
    # 构造 IP + ICMP 包
    ip = IP(dst=target, ttl=ttl)
    icmp = ICMP()
    pkt = ip/icmp

    #  关键：用 sr1() 发送并等待回复
    reply = sr1(pkt, verbose=0, timeout=1)

    if reply:
        print(f"TTL {ttl}: {reply.src}")
        # 到达目标就停止
        if reply.src == target:
            print(" 已到达目标！")
            break
    else:
        print(f"TTL {ttl}: * 请求超时")
