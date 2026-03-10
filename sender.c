#include "sender.h"
#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h> // 提供 udphdr 结构体

// TCP 伪首部，仅在这个文件内部使用
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void send_syn_packet(int sock, const char* ip, int port) {
    char datagram[4096];
    memset(datagram, 0, 4096);
    struct tcphdr *tcph = (struct tcphdr *)datagram;
    struct pseudo_header psh;
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip, &dest.sin_addr);

    tcph->source = htons(54321); 
    tcph->dest = htons(port);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(5840);
    tcph->check = 0;

    inet_pton(AF_INET, config.local_ip, &psh.source_address);
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    sendto(sock, datagram, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest));
}

void send_udp_packet(int sock, const char* ip, int port) {
    char datagram[4096];
    memset(datagram, 0, 4096);
    
    // 我们只需要构造 UDP 头部，IP 头部由原始套接字自动处理 (IPPROTO_UDP 特性)
    struct udphdr *udph = (struct udphdr *)datagram;
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip, &dest.sin_addr);

    // 填充 UDP 头部 (仅 8 个字节)
    udph->source = htons(54321);              // 随机源端口
    udph->dest = htons(port);                 // 目标端口
    udph->len = htons(sizeof(struct udphdr)); // 长度: 头部(8字节) + 数据(0字节)
    udph->check = 0;                          // 校验和置 0，让内核或网卡代劳

    // 将这个空载的 UDP 报文发射出去
    sendto(sock, datagram, sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest));
}
