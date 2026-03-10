import os
import json
import subprocess
import time

def pre_warm_arp(target_cidr):
    """
    战术动作 1：使用 nmap 进行极速 Ping 扫描，预热局域网 ARP 缓存表
    这完美解决了 C 引擎发包过快导致的 ARP 风暴漏报问题。
    """
    print(f"[*] 正在对网段 {target_cidr} 进行存活主机发现与 ARP 预热...")
    # -sn: 只 Ping 不扫端口; -T4: 提高速度
    subprocess.run(["nmap", "-sn", "-T4", target_cidr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] ARP 缓存预热完毕！")

def run_c_scanner(target_cidr, port_range, output_file="report.json"):
    """
    战术动作 2：调用我们亲手写的 C 语言 Raw Socket 引擎进行无状态极速扫描
    """
    print(f"[*] 启动 C 语言极速扫描引擎，对 {port_range} 端口执行 SYN 探测...")
    
    cmd = [
        "sudo", "./scan", 
        "-i", target_cidr, 
        "-p", port_range, 
        "-s", "S", 
        "-o", output_file
    ]
    
    # 阻塞执行我们的 C 程序
    result = subprocess.run(cmd)
    
    if result.returncode == 0 and os.path.exists(output_file):
        print(f"[+] 底层引擎扫描完毕，战报已生成: {output_file}")
        return True
    else:
        print("[-] C 引擎执行失败或未生成报告。")
        return False

def analyze_and_exploit(json_file):
    """
    战术动作 3：解析 JSON 战报，并智能调度漏洞检测模块
    """
    print("\n" + "="*50)
    print("[*] 启动自动化漏洞分析与调度模块...")
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] 报告解析失败: {e}")
        return

    print(f"[*] 扫描类型: {data.get('scan_type')}")
    results = data.get('results', [])
    
    if not results:
        print("[-] 未发现任何开放端口的目标。")
        return

    for host in results:
        ip = host['ip']
        open_ports = host['open_ports']
        
        print(f"\n[+] 锁定高价值目标: {ip}")
        
        # 【核心联动逻辑】：根据不同的开放端口，触发不同的后续攻击/检测脚本
        for port in open_ports:
            print(f"    -> 发现开放端口: {port}")
            
            if port == 22:
                print("       [分析调度] 识别到 SSH 服务，启动弱口令爆破模块 (Hydra / Paramiko)...")
                # 你的后续动作： os.system(f"python3 ssh_brute.py {ip}")
                
            elif port == 53:
                print("       [分析调度] 识别到 DNS 服务，启动区域传输漏洞(Zone Transfer)检测...")
                
            elif port in [80, 8000, 8080]:
                print(f"       [分析调度] 识别到 Web 服务 ({port})，启动目录扫描与指纹识别...")
                
            elif port == 445:
                print("       [分析调度] 识别到 SMB 服务，启动永恒之蓝 (MS17-010) 漏洞探测...")

    print("="*50)

if __name__ == "__main__":
    TARGET = "192.168.30.0/24"
    PORTS = "1-1000"
    REPORT_FILE = "report.json"
    
    print("[*] 自动化渗透测试流水线启动！")
    
    # 1. 预热
    pre_warm_arp(TARGET)
    
    # 2. 发射
    if run_c_scanner(TARGET, PORTS, REPORT_FILE):
        # 3. 分析
        analyze_and_exploit(REPORT_FILE)
        
    print("[*] 任务全部完成。")
