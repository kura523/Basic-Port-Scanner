from flask import Flask, request, jsonify, render_template
import subprocess
import json
import os
import uuid
import time

app = Flask(__name__)

# 路由 1：用户访问首页时，返回网页界面
@app.route('/')
def index():
    return render_template('index.html')

# 路由 2：前端点击“扫描”按钮后，调用的 API 接口
@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json
    target = data.get('target', '127.0.0.1')
    ports = data.get('ports', '1-1000')
    scan_type = data.get('scan_type', 'S')

    # 【核心】：为了防止多个用户同时扫描导致结果文件冲突，我们用 UUID 生成随机文件名
    output_file = f"report_{uuid.uuid4().hex}.json"
    
    # 构造执行命令 (因为运行 app.py 时会加 sudo，所以这里不需要写 sudo)
    cmd = ["./scan", "-i", target, "-p", ports, "-s", scan_type, "-o", output_file]

    try:
        # 可选：执行 ARP 预热 (针对局域网段)
        if "/" in target:
            subprocess.run(["nmap", "-sn", "-T4", target], stdout=subprocess.DEVNULL)

        # 启动底层 C 引擎，等待其执行完毕
        print(f"[*] Web 触发扫描任务: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

        # 读取 C 引擎生成的 JSON 文件
        with open(output_file, 'r') as f:
            result_data = json.load(f)

        # 打扫战场：删除临时结果文件
        os.remove(output_file)

        return jsonify({"status": "success", "data": result_data})

    except Exception as e:
        # 如果出错，也要记得清理残留文件
        if os.path.exists(output_file):
            os.remove(output_file)
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    # 启动 Web 服务器，监听所有网卡 (0.0.0.0) 的 5000 端口
    print("[*] Web 扫描平台已启动，请在浏览器访问 http://本机IP:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
