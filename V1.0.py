#单线程 TCP Connect 扫描
import socket

def scan_port(ip, port):
    """
    尝试连接目标 IP 的指定端口
    """
    # 1. 创建一个 Socket 对象
    # AF_INET 表示使用 IPv4 地址，SOCK_STREAM 表示使用 TCP 协议
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 2. 设置超时时间（极其重要！）
    # 如果不设置，默认会等待很长时间（可能几分钟），导致扫描极慢
    s.settimeout(1.0) 
    
    try:
        # 3. 尝试建立连接
        # connect_ex() 比 connect() 更好用，因为它成功返回 0，失败返回错误码，而不是直接抛出异常
        result = s.connect_ex((ip, port))
        
        if result == 0:
            print(f"[+] 端口 {port} 状态: 开放 (Open)")
        else:
            # 实际上这里包含了 Closed 和 Filtered 两种状态，但在最基础的 Connect 扫描中很难精确区分
            print(f"[-] 端口 {port} 状态: 关闭/被过滤 (Closed/Filtered)")
            
    except Exception as e:
        print(f"[!] 扫描端口 {port} 时发生错误: {e}")
        
    finally:
        # 4. 无论如何，最后一定要关闭 Socket 释放系统资源
        s.close()

if __name__ == '__main__':
    # 设定测试目标，127.0.0.1 是你的本机地址，最安全
    target_ip = "127.0.0.1" 
    
    # 挑选几个常见的端口进行测试 (FTP, SSH, HTTP, HTTPS, MySQL)
    ports_to_test = [21, 22, 80, 443, 3306, 8000]
    print(f"开始扫描目标: {target_ip}")
    print("-" * 30)
    
    for port in ports_to_test:
        scan_port(target_ip, port)
        
    print("-" * 30)
    print("扫描完成！")