# Basic Port Scanner
my first attempt
本项目是一个基于 C 语言底层网络栈（Raw Sockets + libpcap）开发的高并发、无状态端口扫描与资产探测探针。结合 Python Flask 构建的 Web 调度前端，实现了从底层高速发包到上层自动化漏洞分析的完整闭环。
本项目在架构上借鉴了 Nmap 和 Masscan 的核心思想，彻底抛弃了传统的、受限于操作系统文件描述符（FD）上限的 connect() 模型，实现了内核级的极速探测。

核心技术亮点：
1.异步无状态架构 (Asynchronous Stateless)： 发包与收包逻辑完全解耦。主线程利用 Raw Sockets 极速构建并注入伪造报文，独立嗅探线程利用 libpcap 静默监听响应。
2.内核级 BPF 过滤： 动态生成 BPF (Berkeley Packet Filter) 规则，将不相干的网络流量直接在 Linux 内核态丢弃，极大降低应用层 CPU 消耗。
3.多协议支持：TCP SYN 隐蔽扫描 (-sS)： 手工构造 TCP 伪首部与校验和，仅完成半连接握手，不在目标应用层留下任何日志。UDP 逆向推导扫描 (-sU)： 通过捕获 ICMP Port Unreachable (Type 3, Code 3) 报错报文，利用“剥洋葱”技术解析原始 IP/UDP 首部，反向推导 UDP 端口状态。
4.O(1)极速状态追踪： 摒弃低效的链表或树结构，采用动态分配的二维状态数组（Bitmap 思想），在极高并发下实现内存零碰撞的无锁状态更新。
5.CIDR 与全网段降维打击： 内置底层 IP 解析与掩码运算，支持类似 192.168.1.0/24 的大规模子网扫描。
6.智能路由与防 ARP 风暴： 自动探测本机出网 IP 以伪造合法校验和，并联动 Nmap 进行 ARP 预热，解决局域网极限发包导致的内核邻居表溢出漏报问题。

项目架构：
Scan/
├── C Engine (底层发包与嗅探)
│   ├── main.c       # 主控引擎与参数解析 (getopt)
│   ├── network.c    # 校验和算法、CIDR 解析、自动出网 IP 探测
│   ├── sender.c     # Raw Sockets 报文手工组装 (TCP/UDP)
│   ├── sniffer.c    # libpcap 抓包、BPF 注入、链路层偏移动态计算
│   └── Makefile     # 自动化编译配置
├── Python Backend (分析与调度中心)
│   ├── pipeline.py  # 自动化渗透测试流水线调度脚本
│   └── app.py       # Flask Web SaaS 服务化后端
└── Web Frontend (交互视图)
    └── templates/
        └── index.html # Web 控制面板

环境依赖与编译安装：
本项目深入 Linux 内核网络栈，请在 Ubuntu/Debian 等 Linux 环境下编译运行。、
1. 安装底层依赖：
2. sudo apt update
sudo apt install gcc make libpcap-dev nmap python3-flask
2. 编译 C 语言核心引擎：
make clean
make


本项目提供两种使用模式：命令行模式与 Web 平台模式。

模式一：CLI 命令行执行 (集成度高，适合脚本调用)
注意： 使用 Raw Sockets 需要 Root 权限。
扫描单个 IP 的 TCP 端口：sudo ./scan -i 192.168.1.100 -p 1-1000 -s S -o report.json
全网段 UDP 扫描：sudo ./scan -i 192.168.1.0/24 -p 1-1000 -s U -o report.json
生成的标准 report.json 格式如下：
{
  "scan_type": "TCP_SYN",
  "results": [
    {
      "ip": "192.168.1.100",
      "open_ports": [22, 80, 443]
    }
  ]
}

模式二：Web 平台模式
启动 Flask 后端：sudo python3 app.py
终端显示 Running on http://0.0.0.0:5000 后，在浏览器中访问该地址。
在 Web 面板中输入目标 CIDR 和端口，即可体验自动化探测与数据可视化渲染。

免责声明 (Disclaimer)
1.本工具的核心引擎发包速度极快且极具隐蔽性，仅限用于合法授权的渗透测试、安全审计与学术研究用途。
2.未经授权，严禁对任何公网或非所有权目标使用本工具进行扫描探测。
3.若将 Web 服务暴露于公网，请务必自行添加严格的身份认证（如 Token/OAuth）机制，以防服务器被恶意利用成为 DDoS 反射源。
4.使用本工具产生的一切法律后果由使用者自行承担，开发者不承担任何直接或间接的责任。
