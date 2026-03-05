# 添加GUI
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import concurrent.futures
from datetime import datetime

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python 端口扫描器 v3.0")
        self.root.geometry("600x450")
        
        # 控制扫描状态的标志位
        self.is_scanning = False 

        self.setup_ui()

    def setup_ui(self):
        # --- 顶部输入区 ---
        input_frame = tk.Frame(self.root, pady=10)
        input_frame.pack(fill=tk.X, padx=20)

        tk.Label(input_frame, text="目标 IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = tk.Entry(input_frame, width=20)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5)

        tk.Label(input_frame, text="端口范围:").grid(row=0, column=2, sticky=tk.W)
        self.port_entry = tk.Entry(input_frame, width=15)
        self.port_entry.insert(0, "1-1024")
        self.port_entry.grid(row=0, column=3, padx=5)

        self.scan_btn = tk.Button(input_frame, text="开始扫描", command=self.start_scan_thread, bg="lightblue")
        self.scan_btn.grid(row=0, column=4, padx=10)

        # --- 中间日志输出区 ---
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        # 使用 ScrolledText 实现滚动日志窗口
        self.log_area = scrolledtext.ScrolledText(log_frame, state='disabled', bg="black", fg="green", font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # --- 底部状态栏 ---
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log_message(self, msg):
        """线程安全的日志更新方法"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END) # 自动滚动到最底部
        self.log_area.config(state='disabled')

    def scan_port(self, ip, port):
        """底层的扫描原子操作"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            if s.connect_ex((ip, port)) == 0:
                self.log_message(f"[+] 发现开放端口: {port}")
        except:
            pass
        finally:
            s.close()

    def start_scan_thread(self):
        """按钮点击事件：启动独立的扫描线程，防止界面卡死"""
        if self.is_scanning:
            messagebox.showwarning("警告", "扫描正在进行中！")
            return

        target_ip = self.ip_entry.get().strip()
        ports_str = self.port_entry.get().strip()

        # 简单的端口解析
        try:
            if "-" in ports_str:
                start, end = map(int, ports_str.split("-"))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p) for p in ports_str.split(",")]
        except ValueError:
            messagebox.showerror("错误", "端口格式不正确！请使用类似 1-1000 或 80,443 的格式。")
            return

        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED, text="扫描中...")
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END) # 清空历史日志
        self.log_area.config(state='disabled')
        
        self.log_message(f"[*] 开始扫描目标: {target_ip}")
        self.status_var.set("正在扫描...")

        # 核心：将耗时的网络扫描放入独立的 Thread 中运行
        threading.Thread(target=self.run_scan, args=(target_ip, ports), daemon=True).start()

    def run_scan(self, target_ip, ports):
        """在后台线程中运行的扫描调度逻辑"""
        start_time = datetime.now()
        
        # 依然使用线程池来保证并发速度
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            # 提交任务
            futures = [executor.submit(self.scan_port, target_ip, port) for port in ports]
            # 等待所有任务完成
            concurrent.futures.wait(futures)

        end_time = datetime.now()
        self.log_message("-" * 40)
        self.log_message(f"扫描完成！耗时: {end_time - start_time}")
        
        # 恢复 UI 状态
        self.is_scanning = False
        self.scan_btn.config(state=tk.NORMAL, text="开始扫描")
        self.status_var.set("就绪")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop() # 启动 GUI 主事件循环