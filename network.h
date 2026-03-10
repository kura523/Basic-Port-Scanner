#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/types.h>

// --- 新增：端口状态定义 ---
#define PORT_UNSCANNED 0
#define PORT_SCANNED   1  // 已发送包，等待回应 (对于 UDP 意味着默认 Open|Filtered)
#define PORT_CLOSED    2  // 收到 RST 或 ICMP 报错，明确关闭
#define PORT_OPEN      3  // 收到 SYN-ACK，明确开放

// 扫描类型枚举
typedef enum {
    SCAN_TYPE_SYN,
    SCAN_TYPE_FIN,
    SCAN_TYPE_UDP
} ScanType;

// 全局配置结构体
typedef struct {
    char original_target[64]; // 保存用户输入的原始字符串 (如 "192.168.1.0/24")
    uint32_t start_ip;        // 起始 IP (主机字节序)
    uint32_t end_ip;          // 结束 IP (主机字节序)
    int num_ips;              // 需要扫描的 IP 总数
    
    int start_port;
    int end_port;
    ScanType scan_type;
    char output_file[256]; // 新增：输出文件路径
    char local_ip[16];
} ScanConfig;

// 使用 extern 声明全局变量，确保所有引入此头文件的 .c 文件都能访问同一个 config
extern ScanConfig config;
// 【核心升级】：二维状态追踪数组的指针 (行是 IP，列是端口)
extern volatile uint8_t **port_status; 

// 工具函数声明
unsigned short csum(unsigned short *ptr, int nbytes);
void parse_cidr(const char *target);
void ip_to_string(uint32_t ip, char *buffer);
void get_local_ip(const char *target, char *local_ip);

#endif
