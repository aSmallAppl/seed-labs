#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// IP头长度
#define IP_HDRLEN 20
// ICMP头长度
#define ICMP_HDRLEN 8
// 数据包总长度
#define PACKET_LEN (IP_HDRLEN + ICMP_HDRLEN + 64)

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

int main() {
    int sockfd;
    char buffer[PACKET_LEN];
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    struct sockaddr_in dest_addr;

    // Step 1: 创建原始套接字（IPPROTO_RAW表示我们自己构造IP头）
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() 失败");
        return 1;
    }

    // 清空缓冲区
    memset(buffer, 0, PACKET_LEN);

    // Step 2: 构造IP头
    ip_hdr = (struct ip *)buffer;
    ip_hdr->ip_v = 4;                     // IPv4
    ip_hdr->ip_hl = 5;                    // IP头长度（5*4=20字节）
    ip_hdr->ip_tos = 0;                   // 服务类型
    ip_hdr->ip_len = htons(PACKET_LEN);   // 总长度
    ip_hdr->ip_id = htons(12345);         // 标识
    ip_hdr->ip_off = 0;                   // 片偏移
    ip_hdr->ip_ttl = 64;                  // TTL
    ip_hdr->ip_p = IPPROTO_ICMP;          // 协议：ICMP
    // TODO: 伪造源IP
    inet_pton(AF_INET, "10.9.0.9", &(ip_hdr->ip_src));
    // TODO: 目的IP（可以是8.8.8.8或hostA 10.9.0.5）
    inet_pton(AF_INET, "8.8.8.8", &(ip_hdr->ip_dst));
    // IP校验和（内核会自动计算，这里可以不填）
    ip_hdr->ip_sum = 0;

    // Step 3: 构造ICMP头
    icmp_hdr = (struct icmphdr *)(buffer + IP_HDRLEN);
    icmp_hdr->type = ICMP_ECHO;           // ICMP类型：echo请求
    icmp_hdr->code = 0;                   // 代码
    icmp_hdr->un.echo.id = htons(1000);   // 标识符
    icmp_hdr->un.echo.sequence = htons(1);// 序列号
    // 添加自定义数据
    char *data = buffer + IP_HDRLEN + ICMP_HDRLEN;
    strcpy(data, "Spoofed ICMP packet from C program!");
    // 计算ICMP校验和
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, ICMP_HDRLEN + strlen(data));

    // Step 4: 设置目的地址
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_hdr->ip_dst;

    // Step 5: 发送数据包
    if (sendto(sockfd, buffer, PACKET_LEN, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto() 失败");
        close(sockfd);
        return 1;
    }
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("已发送伪造ICMP请求：%s -> %s\n", src_ip, dst_ip);
    printf("请查看是否有对应应答包\n");

    close(sockfd);
    return 0;
}