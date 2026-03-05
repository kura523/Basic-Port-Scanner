#多线程高并发扫描器
import socket
import concurrent.futures
from datetime import datetime

def scan_port(ip, port):
    """
    扫描核心逻辑：尝试连接，返回端口号和状态
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5) # 进一步缩短超时时间到 0.5 秒，提升整体并发速度
    
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            return port, True  # 开放
        else:
            return port, False # 关闭/过滤
    except Exception:
        return port, False
    finally:
        s.close()

if __name__ == '__main__':
    target_ip = "127.0.0.1"
    # 扩大扫描范围：扫描从 1 到 1024 的所有知名端口，加上我们测试的 8000 端口
    ports_to_test = list(range(1, 1025)) + [8000] 
    
    print(f"[*] 开始扫描目标: {target_ip}")
    start_time = datetime.now()
    
    open_ports = [] # 用于收集开放的端口
    
    # 使用 ThreadPoolExecutor 创建一个线程池
    # max_workers 定义了同时运行的最大线程数。100 是一个不错的起点。
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # executor.map 会自动将 ports_to_test 列表里的端口号，分配给线程池中的线程去执行 scan_port
        # 注意：使用 map 时，由于我们需要传两个参数 (ip, port)，这里用了一个列表推导式或 lambda 的变体。
        # 更简洁的写法是固定 IP 参数：
        
        # 提交所有任务到线程池，并获取 future 对象列表
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports_to_test}
        
        # as_completed 会在某个线程完成任务时立刻返回结果
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                print(f"[+] 发现开放端口: {port}")
                open_ports.append(port)

    end_time = datetime.now()
    print("-" * 30)
    print(f"扫描完成！共发现 {len(open_ports)} 个开放端口。")
    print(f"开放端口列表: {sorted(open_ports)}")
    print(f"总耗时: {end_time - start_time}")