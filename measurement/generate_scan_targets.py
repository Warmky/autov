# 实际连接02 既提取配置文件中声明的加密方式，又根据端口直接尝试最高级别的加密方式，可以在扫描结束后进行对比
import json
import os
from collections import defaultdict

'''
数据解耦与扫描调度脚本
1. 提取去重后的 Host 交给 zgrab2 扫描真实的网络能力 (Ground Truth)。
2. 将配置文件声明的加密类型封存，用于后续的安全漏洞碰撞 (降级、接管、伪造)。
'''

# 数据路径配置
INPUT_FILE = "/home/wzq/project/autov/data/check_dif_results.jsonl"
TARGETS_DIR = "/home/wzq/project/autov/data/zgrab2_targets"
EXPECTATIONS_FILE = "/home/wzq/project/autov/data/config_expectations.json"

# 用于 zgrab2 扫描的全局去重集合: scan_targets[协议][端口] = set(主机名)
scan_targets = defaultdict(lambda: defaultdict(set))

# 用于交叉比对的预期配置字典: expectations[主机名][端口][协议][域名] = set(预期的加密类型)
# 采用 set 是因为同一个域名可能在 Autoconfig 和 SRV 中给出了不同甚至冲突的加密建议
expectations = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(set))))

def normalize_crypto(ssl_raw):
    """归一化不同来源的加密类型表达"""
    if ssl_raw is None:
        return "PLAIN"
    ssl_str = str(ssl_raw).strip().upper()
    
    if ssl_str in ["ON", "SSL", "TLS", "TRUE", "YES"]:
        return "TLS"
    elif ssl_str == "STARTTLS":
        return "STARTTLS"
    elif ssl_str in ["", "OFF", "NONE", "FALSE", "NO", "PLAIN"]:
        return "PLAIN"
    return ssl_str

def process_ports_usage(result_list, domain):
    if not result_list:
        return
    if isinstance(result_list, dict):
        result_list = [result_list]

    for result in result_list:
        # 增加容错：确保 result 本身是一个字典
        if not isinstance(result, dict):
            continue
            
        ports_usage = result.get("ports_usage")
        
        # 核心修复：如果 ports_usage 是 None 或 空列表 []，直接跳过
        if not ports_usage:
            continue
            
        for proto_detail in ports_usage:
            # 增加容错：确保 proto_detail 是字典
            if not isinstance(proto_detail, dict):
                continue
                
            proto_type = proto_detail.get("protocol", "").lower()
            server = proto_detail.get("host", "").rstrip(".")
            port = str(proto_detail.get("port") or "").strip()
            ssl_raw = proto_detail.get("ssl", "")
            
            if not (proto_type and server and port):
                continue
                
            crypto = normalize_crypto(ssl_raw)
            
            # 1. 加入扫描目标池
            scan_targets[proto_type][port].add(server)
            
            # 2. 记录预期配置
            expectations[server][port][proto_type][domain].add(crypto)

def main():
    os.makedirs(TARGETS_DIR, exist_ok=True)
    
    print("🔍 正在解析底层数据并分离扫描层与验证层...")
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                domain = data.get("domain")
                if not domain:
                    continue

                process_ports_usage(data.get("autodiscover_check_result"), domain)
                process_ports_usage(data.get("autoconfig_check_result"), domain)
                process_ports_usage(data.get("srv_check_result"), domain)
            except json.JSONDecodeError:
                continue

    # 1. 导出 zgrab2 扫描目标 CSV
    print(f"\n📁 生成 zgrab2 无差别扫描目标至 {TARGETS_DIR}/ :")
    total_scan_tasks = 0
    for proto, ports in scan_targets.items():
        for port, hosts in ports.items():
            csv_path = os.path.join(TARGETS_DIR, f"{proto}_{port}.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                for host in hosts:
                    f.write(f"{host}\n")
            print(f"  - 生成 {proto}_{port}.csv (共 {len(hosts)} 个唯一主机)")
            total_scan_tasks += len(hosts)

    # 2. 导出预期配置 JSON (将 set 转换为 list 以支持 JSON 序列化)
    print(f"\n📁 生成交叉验证基线文件至 {EXPECTATIONS_FILE} ...")
    serializable_exp = {}
    for host, ports in expectations.items():
        serializable_exp[host] = {}
        for port, protos in ports.items():
            serializable_exp[host][port] = {}
            for proto, domains in protos.items():
                serializable_exp[host][port][proto] = {
                    dom: list(cryptos) for dom, cryptos in domains.items()
                }
                
    with open(EXPECTATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(serializable_exp, f, indent=4)
        
    print(f"✅ 解耦完成！总计下发 {total_scan_tasks} 个网络探测任务。")

if __name__ == "__main__":
    main()