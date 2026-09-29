import os
import json
import glob
import csv
from collections import defaultdict

# 路径配置
EXPECTATIONS_FILE = "/home/wzq/project/autov/data/config_expectations.json"
RESULTS_DIR = "/home/wzq/project/autov/data/zgrab2_results"
OUTPUT_DIR = "/home/wzq/project/autov/data/vulnerabilities"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_realities():
    """解析所有 zgrab2 扫描结果，构建真实网络状态字典"""
    # realities[host][port][proto] = {"status": "NXDOMAIN" / "DEAD" / "SUCCESS", "crypto": "TLS" / "PLAIN"}
    realities = defaultdict(lambda: defaultdict(dict))
    
    print("🔍 正在解析 zgrab2 实际扫描结果...")
    for filepath in glob.glob(os.path.join(RESULTS_DIR, "*.jsonl")):
        filename = os.path.basename(filepath)
        parts = filename.replace("result_", "").replace(".jsonl", "").split("_")
        if len(parts) != 2:
            continue
            
        proto_raw, port = parts[0], parts[1]
        # 归一化协议名，确保与 expectations 匹配
        proto = "pop3" if proto_raw == "pop" else proto_raw
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    host = record.get("domain") # zgrab2 的 domain 字段实际上是我们扫的 host
                    if not host:
                        continue
                        
                    error_msg = record.get("error", "")
                    
                    # 1. 检测 NXDOMAIN
                    if "no such host" in error_msg:
                        realities[host][port][proto] = {"status": "NXDOMAIN", "crypto": None}
                        continue
                        
                    # 2. 深入 data 块分析连接状态
                    if "data" in record and proto in record["data"]:
                        module_data = record["data"][proto]
                        status = module_data.get("status")
                        
                        if status == "success":
                            result = module_data.get("result", {})
                            # 只要 result 里有 tls 字段，就说明加密协商成功
                            has_tls = "tls" in result
                            crypto_status = "TLS" if has_tls else "PLAIN"
                            realities[host][port][proto] = {"status": "SUCCESS", "crypto": crypto_status}
                        else:
                            # 超时、拒绝连接等
                            realities[host][port][proto] = {"status": "DEAD", "crypto": None}
                except Exception as e:
                    continue
                    
    return realities

def cross_verify(expectations, realities):
    """交叉比对，发现安全漏洞"""
    print("⚔️ 正在与 config_expectations.json 进行漏洞碰撞...")
    
    vuln_takeover = []      # 接管漏洞: NXDOMAIN
    vuln_downgrade = []     # 降级漏洞: 预期 PLAIN，实际支持 TLS
    vuln_false_promise = [] # 虚假承诺: 预期 TLS，实际只能 PLAIN 或连不上
    
    for host, ports in expectations.items():
        for port, protos in ports.items():
            for proto, domains in protos.items():
                
                # 获取该 host:port:proto 的真实网络情况
                reality = realities.get(host, {}).get(port, {}).get(proto, {"status": "UNKNOWN", "crypto": None})
                
                for domain, expected_cryptos in domains.items():
                    # 漏洞 1：接管漏洞 (配置文件指向了已被释放的主机)
                    if reality["status"] == "NXDOMAIN":
                        vuln_takeover.append({
                            "Domain": domain, "Configured_Host": host, 
                            "Protocol": proto, "Port": port
                        })
                        continue # 已经是 NXDOMAIN，不再比对加密
                        
                    for expected_crypto in expected_cryptos:
                        actual_crypto = reality["crypto"]
                        
                        # 如果实际连通了，比对加密策略
                        if reality["status"] == "SUCCESS":
                            # 漏洞 2：配置降级
                            if expected_crypto == "PLAIN" and actual_crypto == "TLS":
                                vuln_downgrade.append({
                                    "Domain": domain, "Host": host, "Port": port, "Protocol": proto,
                                    "Expected": expected_crypto, "Actual": actual_crypto
                                })
                            
                            # 漏洞 3：虚假安全承诺 (配置要 TLS，但服务器只支持明文)
                            elif expected_crypto in ["TLS", "STARTTLS"] and actual_crypto == "PLAIN":
                                vuln_false_promise.append({
                                    "Domain": domain, "Host": host, "Port": port, "Protocol": proto,
                                    "Expected": expected_crypto, "Actual": actual_crypto
                                })
                                
                        # 如果服务器已死 (Timeout/Connection Refused)，但配置要求 TLS
                        elif reality["status"] == "DEAD" and expected_crypto in ["TLS", "STARTTLS"]: # in PLAIN ? 而且超时也不一定就是服务器真的不可用，可能与节点有关 9.29
                                vuln_false_promise.append({
                                    "Domain": domain, "Host": host, "Port": port, "Protocol": proto,
                                    "Expected": expected_crypto, "Actual": "DEAD_SERVICE"
                                })

    return vuln_takeover, vuln_downgrade, vuln_false_promise

def save_to_csv(filename, headers, data):
    """将结果保存为 CSV 文件"""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)
    print(f"📄 已生成报告: {filepath} (共 {len(data)} 条)")

def main():
    # 1. 加载预期配置
    with open(EXPECTATIONS_FILE, 'r', encoding='utf-8') as f:
        expectations = json.load(f)
        
    # 2. 解析实际结果
    realities = parse_realities()
    
    # 3. 交叉碰撞
    vuln_takeover, vuln_downgrade, vuln_false_promise = cross_verify(expectations, realities)
    
    # 4. 导出报告
    print("\n📊 漏洞碰撞统计结果：")
    print(f"  - 基础设施接管漏洞 (NXDOMAIN): {len(vuln_takeover)} 个")
    print(f"  - 安全配置降级漏洞 (Downgrade): {len(vuln_downgrade)} 个")
    print(f"  - 虚假安全承诺缺陷 (False Promise): {len(vuln_false_promise)} 个\n")
    
    save_to_csv("vuln_takeover.csv", ["Domain", "Configured_Host", "Protocol", "Port"], vuln_takeover)
    save_to_csv("vuln_downgrade.csv", ["Domain", "Host", "Port", "Protocol", "Expected", "Actual"], vuln_downgrade)
    save_to_csv("vuln_false_promise.csv", ["Domain", "Host", "Port", "Protocol", "Expected", "Actual"], vuln_false_promise)

if __name__ == "__main__":
    main()