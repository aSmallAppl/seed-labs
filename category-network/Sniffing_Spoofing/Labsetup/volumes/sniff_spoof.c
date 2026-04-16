#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define ETH_HDRLEN 14
#define IP_HDRLEN 20
#define ICMP_HDRLEN 8
#define PACKET_LEN (IP_HDRLEN + ICMP_HDRLEN + 64)

int sockfd; // 全局原始套接字

// 计算校验和
unsigned short checksum(unsigned short *buf, int len) {
    unsigned int sum = 0;
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// 发送伪造的ICMP应答
void send_spoofed_reply(struct ip *req_ip, struct icmphdr *req_icmp, int data_len) {
    char buffer[PACKET_LEN];
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    struct sockaddr_in dest_addr;

    memset(buffer, 0, PACKET_LEN);

    // 构造IP头
    ip_hdr = (struct ip *)buffer;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(IP_HDRLEN + ICMP_HDRLEN + data_len);
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_ICMP;
    // 源IP伪装成请求的目的IP
    ip_hdr->ip_src = req_ip->ip_dst;
    // 目的IP是请求的源IP
    ip_hdr->ip_dst = req_ip->ip_src;
    ip_hdr->ip_sum = 0;

    // 构造ICMP应答头
    icmp_hdr = (struct icmphdr *)(buffer + IP_HDRLEN);
    icmp_hdr->type = ICMP_ECHOREPLY; // ICMP类型：echo应答
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = req_icmp->un.echo.id;       // 匹配请求ID
    icmp_hdr->un.echo.sequence = req_icmp->un.echo.sequence; // 匹配序列号
    // 复制请求的数据
    memcpy(buffer + IP_HDRLEN + ICMP_HDRLEN,
           (u_char *)req_icmp + ICMP_HDRLEN, data_len);
    // 计算ICMP校验和
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, ICMP_HDRLEN + data_len);

    // 设置目的地址
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_hdr->ip_dst;

    // 发送伪造应答
    sendto(sockfd, buffer, IP_HDRLEN + ICMP_HDRLEN + data_len, 0,
           (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    printf("已发送伪造应答：%s -> %s\n",
           inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));
}

// 回调函数：捕获ICMP请求
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 跳过以太网帧头
    struct ip *ip_hdr = (struct ip *)(packet + ETH_HDRLEN);
    int ip_len = ip_hdr->ip_hl * 4;
    
    // 只处理ICMP数据包
    if (ip_hdr->ip_p != IPPROTO_ICMP) return;
    
    // 指向ICMP头
    struct icmphdr *icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + ip_len);
    
    // 只处理ICMP echo请求（类型8）
    if (icmp_hdr->type != ICMP_ECHO) return;

    // 计算数据长度
    int data_len = ntohs(ip_hdr->ip_len) - ip_len - ICMP_HDRLEN;
    
    printf("\n捕获到ICMP请求：%s -> %s\n",
           inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));
    
    // 发送伪造应答
    send_spoofed_reply(ip_hdr, icmp_hdr, data_len);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;

    // TODO: 替换为你的实验网络接口名
    char *dev = "br-cfefbbe8c0e2";

    // 创建原始套接字
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() 失败");
        return 1;
    }

    // 打开网络接口
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "无法打开设备 %s: %s\n", dev, errbuf);
        close(sockfd);
        return 1;
    }

    // 过滤ICMP数据包
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "过滤器编译失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        close(sockfd);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        close(sockfd);
        return 1;
    }

    printf("C语言嗅探并欺骗程序已启动，接口：%s\n", dev);
    printf("将自动回复所有ICMP echo请求\n");
    printf("按 Ctrl+C 停止\n");

    // 循环捕获数据包
    pcap_loop(handle, -1, got_packet, NULL);

    // 清理资源
    pcap_close(handle);
    close(sockfd);
    return 0;
}