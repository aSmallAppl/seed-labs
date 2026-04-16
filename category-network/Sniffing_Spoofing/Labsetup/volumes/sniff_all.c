#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

// 以太网帧头长度
#define ETH_HDRLEN 14

// 回调函数：处理每个捕获的数据包
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;
    printf("\n=== 捕获到第 %d 个数据包 ===\n", count++);
    printf("数据包长度: %d 字节\n", header->len);

    // 跳过以太网帧头，指向IP头
    struct ip *ip_hdr = (struct ip *)(packet + ETH_HDRLEN);
    
    // 打印源IP和目的IP
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    printf("源IP: %s\n", src_ip);
    printf("目的IP: %s\n", dst_ip);
    printf("协议: %d (1=ICMP, 6=TCP, 17=UDP)\n", ip_hdr->ip_p);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;

    // TODO: 替换为你的实验网络接口名
    char *dev = "br-cfefbbe8c0e2";
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n",
            errbuf);
        exit(EXIT_FAILURE);
    }

    // Step 1: 打开网络接口
    // 第三个参数：1=开启混杂模式，0=关闭
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开设备 %s: %s\n", dev, errbuf);
        return 1;
    }

    // Step 2: 编译并设置过滤器
    // Task 2.1B: 不同过滤器（每次只启用一个）
    // 1. 捕获两个特定主机之间的ICMP数据包
    char filter_exp[] = "icmp";
    // 2. 捕获目的端口在10-100之间的TCP数据包
    // char filter_exp[] = "tcp dst portrange 10-100";
    // 3. 基础ICMP过滤器
    // char filter_exp[] = "icmp";

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "过滤器编译失败: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("开始在接口 %s 上嗅探，过滤器: %s\n", dev, filter_exp);
    printf("按 Ctrl+C 停止\n");

    // Step 3: 循环捕获数据包
    pcap_loop(handle, -1, got_packet, NULL);

    // 关闭句柄
    pcap_close(handle);
    return 0;
}
