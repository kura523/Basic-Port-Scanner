#include "network.h"
#include <stdio.h>      // 提供 fprintf, stderr
#include <stdlib.h>     // 提供 NULL, atoi, exit
#include <string.h>     // 提供 strncpy, strcpy, strchr
#include <arpa/inet.h>  // 提供 inet_pton, inet_ntop, htonl, ntohl
#include <sys/socket.h> // 提供 AF_INET 宏
#include <netinet/in.h> // 提供 struct in_addr 结构体
#include <unistd.h> // 提供 close() 函数

// 真正实例化全局配置变量的地方
ScanConfig config;
volatile uint8_t **port_status = NULL;

// 经典的校验和算法实现
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    while(nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if(nbytes == 1) sum += *(unsigned char*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (short)~sum;
}

// 【核心算法】：解析 CIDR 或单 IP
void parse_cidr(const char *target) {
    strncpy(config.original_target, target, 63);
    char ip_part[32] = {0};
    int prefix = 32; // 默认是单 IP (/32)
    
    char *slash = strchr(target, '/');
    if (slash) {
        strncpy(ip_part, target, slash - target);
        prefix = atoi(slash + 1);
    } else {
        strcpy(ip_part, target);
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) <= 0) {
        fprintf(stderr, "[!] 无效的 IP 地址格式: %s\n", ip_part);
        exit(1);
    }

    // 将网络字节序转为主机字节序，方便进行加减法运算
    uint32_t ip_host = ntohl(addr.s_addr);

    // 计算子网掩码 (处理前缀为 0 的边界情况)
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    
    config.start_ip = ip_host & mask;
    config.end_ip = config.start_ip | ~mask;
    config.num_ips = config.end_ip - config.start_ip + 1;
}

// 辅助函数：将主机字节序的 IP 转回字符串
void ip_to_string(uint32_t ip, char *buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buffer, 16);
}

void get_local_ip(const char *target, char *local_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53); // 随便指定一个端口，比如 DNS 端口
    inet_pton(AF_INET, target, &serv.sin_addr);

    // 对于 UDP，connect 不会发包，只会查询内核路由表并绑定本地接口
    connect(sock, (struct sockaddr*)&serv, sizeof(serv));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);
    inet_ntop(AF_INET, &name.sin_addr, local_ip, 16);
    close(sock);
}
