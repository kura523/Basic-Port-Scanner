#include "sniffer.h"
#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h> // 提供 icmphdr 结构体
#include <netinet/udp.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 【第一层剥洋葱】：链路层安全检查
    if (args == NULL) return;
    int link_header_length = *(int *)args;

    // 确保包的长度至少包含链路层和一个基础的 IP 头部
    if (header->caplen < link_header_length + sizeof(struct iphdr)) return;
    
    // 【第二层剥洋葱】：提取 IP 头部
    struct iphdr *iph = (struct iphdr *)(packet + link_header_length);
    if (iph->version != 4) return; // 确保是 IPv4
    
    int ip_header_len = iph->ihl * 4;

    // ==========================================
    // 【核心修正位置】：现在 iph 已经安全了，可以读取 IP 并计算索引了！
    // 提取发送方的 IP 地址 (网络转主机字节序)
    uint32_t src_ip = ntohl(iph->saddr);
    
    // 计算这个 IP 在我们二维状态数组中的行索引
    int ip_index = src_ip - config.start_ip;
    
    // 安全防御：如果收到的包不在我们的扫描 IP 范围内，直接丢弃
    if (ip_index < 0 || ip_index >= config.num_ips) return;
    // ==========================================

    // 【第三层剥洋葱】：根据协议解析端口状态
    if (config.scan_type == SCAN_TYPE_SYN) {
        if (header->caplen < link_header_length + ip_header_len + sizeof(struct tcphdr)) return;
        struct tcphdr *tcph = (struct tcphdr *)(packet + link_header_length + ip_header_len);
        
        int port = ntohs(tcph->source);
        port_status[ip_index][port] = PORT_OPEN; // 使用二维索引记录状态
    } 
    else if (config.scan_type == SCAN_TYPE_UDP) {
        // 确保这是一个 ICMP 报文
        if (iph->protocol != IPPROTO_ICMP) return;

        // 定位到 ICMP 头部 (跳过当前的 IP 头)
        struct icmphdr *icmph = (struct icmphdr *)((unsigned char *)iph + ip_header_len);
        
        // 再次确认是端口不可达报错 (Type 3, Code 3)
        if (icmph->type == 3 && icmph->code == 3) {
            
            // 跳过 8 字节的 ICMP 首部，找到我们当初发过去的原始 IP 头部
            struct iphdr *orig_iph = (struct iphdr *)((unsigned char *)icmph + 8);
            
            // 安全边界检查：确保原始 IP 头部完整
            int orig_ip_header_len = orig_iph->ihl * 4;
            if (orig_ip_header_len < 20) return; 

            // 跳过原始 IP 头部，找到我们当初发过去的原始 UDP 头部
            struct udphdr *orig_udph = (struct udphdr *)((unsigned char *)orig_iph + orig_ip_header_len);

            // 提取目标端口并记录为关闭状态
            int port = ntohs(orig_udph->dest);
            port_status[ip_index][port] = PORT_CLOSED; // 使用二维索引记录状态
        }
    }
}

void *sniffer_thread(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[256] = {0};

    // 动态生成 BPF 规则 (利用 libpcap 原生支持 src net <CIDR> 的特性)
    if (config.scan_type == SCAN_TYPE_SYN) {
        snprintf(filter_exp, sizeof(filter_exp), 
                 "src net %s and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", 
                 config.original_target);
    } 
    else if (config.scan_type == SCAN_TYPE_UDP) {
        snprintf(filter_exp, sizeof(filter_exp), 
                 "src net %s and icmp and icmp[icmptype] == icmp-unreach and icmp[icmpcode] == 3", 
                 config.original_target);
    }

    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) exit(1);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) exit(1);
    if (pcap_setfilter(handle, &fp) == -1) exit(1);

    int dlt = pcap_datalink(handle);
    static int link_offset = 14; 
    if (dlt == DLT_NULL) link_offset = 4;
    else if (dlt == DLT_EN10MB) link_offset = 14;
    else if (dlt == 113) link_offset = 16;

    pcap_loop(handle, 0, packet_handler, (u_char *)&link_offset);
    pcap_close(handle);
    return NULL;
}
