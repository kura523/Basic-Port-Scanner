#加入 命令行参数解析 (CLI) 和 服务指纹识别 (Banner Grabbing)
import socket
import concurrent.futures
import argparse
from datetime import datetime

def grab_banner(s):
    """
    尝试从已连接的 Socket 中读取服务发送的 Banner 信息
    """
    try:
        # 尝试接收最多 1024 字节的数据
        # 很多服务在建立连接后不会立刻发送数据（比如 HTTP），这里可能会超时
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except Exception:
        return ""

def scan_port(ip, port):
    """
    扫描核心逻辑，并在端口开放时尝试抓取 Banner
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5) 
    
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            # 端口开放，尝试抓取 Banner
            # 因为 recv 会阻塞等待数据，我们需要稍微延长一点超时时间
            s.settimeout(1.0) 
            banner = grab_banner(s)
            return port, True, banner
        else:
            return port, False, ""
    except Exception:
        return port, False, ""
    finally:
        s.close()

def main():
    # 1. 设置命令行参数解析
    parser = argparse.ArgumentParser(description="Python 多线程端口扫描器 v2.5")
    parser.add_argument("-i", "--ip", required=True, help="目标 IP 地址 (例如: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="1-1024", help="扫描端口范围 (例如: 1-1000 或者 80,443,8000)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="最大并发线程数 (默认: 100)")
    
    args = parser.parse_args()
    target_ip = args.ip
    
    # 2. 解析端口输入逻辑
    ports_to_test = []
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
        ports_to_test = list(range(start_port, end_port + 1))
    elif "," in args.ports:
        ports_to_test = [int(p) for p in args.ports.split(",")]
    else:
        ports_to_test = [int(args.ports)]

    print(f"[*] 启动扫描任务...")
    print(f"[*] 目标: {target_ip}")
    print(f"[*] 端口数量: {len(ports_to_test)}")
    print(f"[*] 并发线程: {args.threads}")
    print("-" * 50)
    
    start_time = datetime.now()
    open_ports_info = []

    # 3. 启动线程池
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports_to_test}
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                # 格式化输出，如果抓到了 banner 就显示出来
                banner_info = f" [Banner: {banner}]" if banner else ""
                print(f"[+] 发现开放端口: {port:<5} {banner_info}")
                open_ports_info.append(port)

    end_time = datetime.now()
    print("-" * 50)
    print(f"扫描完成！共发现 {len(open_ports_info)} 个开放端口。")
    print(f"总耗时: {end_time - start_time}")

if __name__ == '__main__':
    main()