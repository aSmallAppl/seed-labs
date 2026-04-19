#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

#define INTERFACE_NAME "br-d96734b3a6af" // 修改为你的网卡名
#define IP_HDRLEN 20
#define ICMP_HDRLEN 8
#define ICMP_DATA "SEED Lab ICMP Spoofing Test"
#define ICMP_DATA_LEN strlen(ICMP_DATA)
#define RECV_BUF_SIZE 1024

// 校验和计算（通用）
unsigned short checksum(unsigned short *buf, int len) {
    unsigned int sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/**
 * @brief 对标Scapy sr1()的ICMP发送接收函数
 * @param spoof_src_ip 伪造的源IP地址字符串
 * @param dst_ip 目标IP地址字符串
 * @param icmp_id ICMP标识符（用于匹配回包）
 * @param icmp_seq ICMP序列号（用于匹配回包）
 * @param timeout_sec 超时时间（秒）
 * @param recv_buf 输出参数：存储接收到的完整IP+ICMP数据包
 * @param recv_buf_len 输入：接收缓冲区大小；输出：实际接收的字节数
 * @return 成功返回0，超时返回-1，错误返回-2
 */
int icmp_sr1(const char *spoof_src_ip, const char *dst_ip,
             uint16_t icmp_id, uint16_t icmp_seq,
             int timeout_sec,
             u_char *recv_buf, int *recv_buf_len) {
    int send_sock = -1, recv_sock = -1;
    int ret = -2; // 默认错误
    struct ifreq ifr_bind;
    struct timeval timeout;
    char send_buf[IP_HDRLEN + ICMP_HDRLEN + ICMP_DATA_LEN];
    struct ip *ip_hdr = (struct ip *)send_buf;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(send_buf + IP_HDRLEN);
    struct sockaddr_in dest_addr;

    // --- 1. 创建socket ---
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (send_sock < 0 || recv_sock < 0) {
        perror("创建socket失败");
        goto cleanup;
    }

    // --- 2. 绑定到指定网卡（关键：解决多网卡环境收不到包的问题）---
    memset(&ifr_bind, 0, sizeof(ifr_bind));
    strncpy(ifr_bind.ifr_name, INTERFACE_NAME, IFNAMSIZ-1);
    if (setsockopt(send_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr_bind, sizeof(ifr_bind)) < 0 ||
        setsockopt(recv_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr_bind, sizeof(ifr_bind)) < 0) {
        perror("绑定网卡失败");
        goto cleanup;
    }

    // --- 3. 设置接收超时 ---
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // --- 4. 构造伪造的ICMP请求包 ---
    memset(send_buf, 0, sizeof(send_buf));
    
    // IP头
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(send_buf));
    ip_hdr->ip_id = htons(rand() % 65535); // 随机ID
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_ICMP;
    inet_pton(AF_INET, spoof_src_ip, &(ip_hdr->ip_src));
    inet_pton(AF_INET, dst_ip, &(ip_hdr->ip_dst));
    ip_hdr->ip_sum = checksum((unsigned short *)ip_hdr, IP_HDRLEN); // 计算IP校验和

    // ICMP头
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(icmp_id);
    icmp_hdr->un.echo.sequence = htons(icmp_seq);
    char *data = send_buf + IP_HDRLEN + ICMP_HDRLEN;
    strcpy(data, ICMP_DATA);
    icmp_hdr->checksum = checksum((unsigned short *)icmp_hdr, ICMP_HDRLEN + ICMP_DATA_LEN);

    // 目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip, &(dest_addr.sin_addr));

    // --- 5. 发送数据包 ---
    if (sendto(send_sock, send_buf, sizeof(send_buf), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("发送数据包失败");
        goto cleanup;
    }

    // --- 6. 等待并匹配回包（核心逻辑）---
    printf("已发送伪造包 %s -> %s (ID: %d, Seq: %d)，等待回包...\n",
           spoof_src_ip, dst_ip, icmp_id, icmp_seq);

    while (1) {
        int n = recvfrom(recv_sock, recv_buf, *recv_buf_len, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ret = -1; // 超时
                break;
            }
            perror("接收数据包失败");
            break;
        }

        // 解析IP头
        struct ip *recv_ip = (struct ip *)recv_buf;
        int ip_len = recv_ip->ip_hl * 4;
        if (ip_len + ICMP_HDRLEN > n) continue; // 包不完整

        // 解析ICMP头
        struct icmphdr *recv_icmp = (struct icmphdr *)(recv_buf + ip_len);
        
        // 精确匹配：Echo Reply + 相同ID + 相同Seq
        if (recv_icmp->type == ICMP_ECHOREPLY &&
            ntohs(recv_icmp->un.echo.id) == icmp_id &&
            ntohs(recv_icmp->un.echo.sequence) == icmp_seq) {
            *recv_buf_len = n;
            ret = 0; // 成功匹配
            break;
        }
    }

cleanup:
    if (send_sock >= 0) close(send_sock);
    if (recv_sock >= 0) close(recv_sock);
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s <伪造源IP> <目标IP>\n", argv[0]);
        return 1;
    }

    // 实验前必须执行：关闭反向路径过滤
    system("sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null");
    system("sysctl -w net.ipv4.conf." INTERFACE_NAME ".rp_filter=0 > /dev/null");

    u_char recv_buf[RECV_BUF_SIZE];
    int recv_len = sizeof(recv_buf);
    
    // 对标Scapy: reply = sr1(IP(src=argv[1], dst=argv[2])/ICMP(id=1234, seq=1), timeout=5)
    int result = icmp_sr1(argv[1], argv[2], 1234, 1, 5, recv_buf, &recv_len);

    if (result == 0) {
        printf("\n✅ 成功收到匹配的回包！\n");
        
        // 解析并打印回包信息
        struct ip *ip = (struct ip *)recv_buf;
        struct icmphdr *icmp = (struct icmphdr *)(recv_buf + ip->ip_hl * 4);
        
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->ip_dst, dst, INET_ADDRSTRLEN);
        
        printf("[IP] %s -> %s (TTL: %d)\n", src, dst, ip->ip_ttl);
        printf("[ICMP] Echo Reply (ID: %d, Seq: %d)\n",
               ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
    } else if (result == -1) {
        printf("\n❌ 超时，未收到回包\n");
    } else {
        printf("\n❌ 发生错误\n");
    }

    return 0;
}