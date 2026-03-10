#include "network.h"
#include "sender.h"
#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

void print_usage(const char *prog_name) {
    printf("用法: %s -i <目标IP或CIDR> -p <端口范围> -s <S|U> -o <输出文件.json>\n", prog_name);
}

// 核心函数：根据二维状态数组生成 JSON 报告
void generate_json_report() {
    FILE *fp = fopen(config.output_file, "w");
    if (!fp) {
        perror("[!] 无法创建 JSON 输出文件");
        return;
    }

    fprintf(fp, "{\n  \"scan_type\": \"%s\",\n  \"results\": [\n", 
            config.scan_type == SCAN_TYPE_SYN ? "TCP_SYN" : "UDP");

    int first_ip = 1; // 控制 JSON 数组元素的逗号分隔
    
    // 【修正点 1】：外层循环正确遍历所有的 IP 索引 (ip_idx)
    for (int ip_idx = 0; ip_idx < config.num_ips; ip_idx++) {
        int has_open_ports = 0;

        // 先检查这个 IP 有没有开放的端口，如果有，我们才生成它的 JSON 块
        for (int p = config.start_port; p <= config.end_port; p++) {
            if (config.scan_type == SCAN_TYPE_SYN && port_status[ip_idx][p] == PORT_OPEN) has_open_ports = 1;
            if (config.scan_type == SCAN_TYPE_UDP && port_status[ip_idx][p] == PORT_SCANNED) has_open_ports = 1;
        }

        if (has_open_ports) {
            if (!first_ip) fprintf(fp, ",\n");
            first_ip = 0;

            char ip_str[16];
            ip_to_string(config.start_ip + ip_idx, ip_str);
            fprintf(fp, "    {\n      \"ip\": \"%s\",\n      \"open_ports\": [", ip_str);

            int first_port = 1; // 控制端口数组元素的逗号分隔
            
            // 【修正点 2】：内层循环正确遍历所有的端口 (p)
            for (int p = config.start_port; p <= config.end_port; p++) {
                int is_open = 0;
                if (config.scan_type == SCAN_TYPE_SYN && port_status[ip_idx][p] == PORT_OPEN) is_open = 1;
                if (config.scan_type == SCAN_TYPE_UDP && port_status[ip_idx][p] == PORT_SCANNED) is_open = 1;

                if (is_open) {
                    if (!first_port) fprintf(fp, ", ");
                    fprintf(fp, "%d", p);
                    first_port = 0;
                }
            }
            fprintf(fp, "]\n    }");
        }
    }

    fprintf(fp, "\n  ]\n}\n");
    fclose(fp);
    printf("[+] 扫描完成！全网段结构化报告已保存至: %s\n", config.output_file);
}

int main(int argc, char *argv[]) {
    // 【修正点 3】：使用 parse_cidr 替代废弃的 target_ip 赋值
    parse_cidr("127.0.0.1"); 
    config.start_port = 1;
    config.end_port = 1000;
    config.scan_type = SCAN_TYPE_SYN;
    strncpy(config.output_file, "result.json", 255); 

    int opt;
    char port_str[64];
    
    // 解析命令行参数
    while ((opt = getopt(argc, argv, "i:p:s:o:h")) != -1) {
        switch (opt) {
            case 'i': parse_cidr(optarg); break;
            case 'o': strncpy(config.output_file, optarg, 255); break;
            case 'p':
                strncpy(port_str, optarg, 63);
                char *dash = strchr(port_str, '-');
                if (dash) {
                    *dash = '\0';
                    config.start_port = atoi(port_str);
                    config.end_port = atoi(dash + 1);
                } else {
                    config.start_port = config.end_port = atoi(port_str);
                }
                break;
            case 's':
                if (optarg[0] == 'S') config.scan_type = SCAN_TYPE_SYN;
                else if (optarg[0] == 'U') config.scan_type = SCAN_TYPE_UDP;
                else exit(1);
                break;
            case 'h': default: print_usage(argv[0]); exit(1);
        }
    }


// 【新增】：根据目标 IP，探测我们正确的出网 IP
    char first_ip_str[16];
    ip_to_string(config.start_ip, first_ip_str);
    get_local_ip(first_ip_str, config.local_ip);
    
    printf("[*] 启动扫描引擎 | 目标网段: %s (共 %d 个 IP) | 端口: %d-%d\n", 
           config.original_target, config.num_ips, config.start_port, config.end_port);
    printf("[*] 自动探测本机出网 IP (用于构造合法校验和): %s\n", config.local_ip);
    
    // 动态分配二维状态数组
    port_status = malloc(config.num_ips * sizeof(uint8_t *));
    for (int i = 0; i < config.num_ips; i++) {
        port_status[i] = calloc(65536, sizeof(uint8_t)); 
    }

    pthread_t sniffer;
    pthread_create(&sniffer, NULL, sniffer_thread, NULL);
    usleep(500000); 

    int sock = socket(AF_INET, SOCK_RAW, config.scan_type == SCAN_TYPE_UDP ? IPPROTO_UDP : IPPROTO_TCP);
    
    printf("[*] 正在对全网段进行无状态扫描...\n");

    for (int port = config.start_port; port <= config.end_port; port++) {
        for (int ip_idx = 0; ip_idx < config.num_ips; ip_idx++) {
            
            char ip_str[16];
            ip_to_string(config.start_ip + ip_idx, ip_str);

            port_status[ip_idx][port] = PORT_SCANNED; 

            if (config.scan_type == SCAN_TYPE_SYN) {
                send_syn_packet(sock, ip_str, port);
            } else if (config.scan_type == SCAN_TYPE_UDP) {
                send_udp_packet(sock, ip_str, port);
            }
            
            usleep(50); 
        }
    }

    printf("[*] 报文发送完毕，等待网络响应 (3秒)...\n");
    sleep(3); 
    
    generate_json_report();

    // 释放内存
    for (int i = 0; i < config.num_ips; i++) free((void*)port_status[i]);
    free((void*)port_status);

    return 0;
}
