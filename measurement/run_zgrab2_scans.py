import os
import subprocess

TARGETS_DIR = "/home/wzq/project/autov/data/zgrab2_targets"
RESULTS_DIR = "/home/wzq/project/autov/data/zgrab2_results"
ZGRAB2_PATH = "zgrab2"  # conda 环境中已配置好，可直接调用

# 创建存放扫描结果的目录
os.makedirs(RESULTS_DIR, exist_ok=True)

def get_zgrab2_command(proto, port, input_csv, output_jsonl):
    """根据协议和端口，动态拼装 zgrab2 命令"""
    module = "pop3" if proto == "pop" else proto
    
    # 1. 全局参数 (必须严格放在模块名之前)
    cmd = [
        ZGRAB2_PATH, 
        "--senders=100", 
        "-f", input_csv, 
        "-o", output_jsonl
    ]
    
    # 2. 指定模块名 (smtp, imap, pop3)
    cmd.append(module)
    
    # 3. 模块专属参数 (必须严格放在模块名之后)
    cmd.extend([
        f"--port={port}",
        "--target-timeout=10s",
        "--connect-timeout=10s"
    ])
    
    # 4. 加密探测机制差异化处理
    if port in ["465"] and module == "smtp":
        cmd.append("--smtps")
    elif port in ["993"] and module == "imap":
        cmd.append("--imaps")
    elif port in ["995"] and module == "pop3":
        cmd.append("--pop3s")
    else:
        # 对 25, 587, 143, 110 及所有非标准端口，尝试 STARTTLS 升级探测
        # 注意：SMTP 模块会自动处理 STARTTLS，不能加此参数；仅向 imap 和 pop3 显式下发
        if module in ["imap", "pop3"]:
            cmd.append("--starttls")
        
    return cmd

def main():
    print("🚀 开始执行 zgrab2 并发扫描任务...\n")
    
    for file in os.listdir(TARGETS_DIR):
        if not file.endswith(".csv") or "undefined" in file:
            continue
            
        base_name = file.replace(".csv", "")
        parts = base_name.split("_")
        if len(parts) != 2:
            continue
            
        proto, port = parts[0], parts[1]
        input_csv = os.path.join(TARGETS_DIR, file)
        output_jsonl = os.path.join(RESULTS_DIR, f"result_{base_name}.jsonl")
        
        # 获取针对性的扫描命令
        cmd = get_zgrab2_command(proto, port, input_csv, output_jsonl)
        
        print(f"执行探测: {' '.join(cmd)}")
        try:
            # 阻塞调用，跑完一个 CSV 再跑下一个
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠️ 扫描 {base_name} 时发生错误: {e}")
            
    print("\n✅ 所有网络探测任务执行完毕！结果已落盘至 zgrab2_results 目录。")

if __name__ == "__main__":
    main()