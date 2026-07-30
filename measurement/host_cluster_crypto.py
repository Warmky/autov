import json
from collections import defaultdict

'''
配置信息提取与全局去重增强版 (包含加密类型)  实际连接01
从 check_dif_results.jsonl 中提取 Host、port、protocol 以及 ssl(加密类型) 
聚类为 clusters_crypto.json，确保相同元组只进行一次实际连接测试。
'''

# 定义聚类结果: clusters[协议-端口-加密方式][主机名] = {域名集合}
clusters = defaultdict(lambda: defaultdict(set))

def normalize_crypto(ssl_raw):
    """
    归一化不同来源的 ssl 字段表达方式。
    将各种各样的表达统一映射为: TLS, STARTTLS, 或 PLAIN
    """
    if ssl_raw is None:
        return "PLAIN"
        
    ssl_str = str(ssl_raw).strip().upper()
    
    # 隐式加密 (通常用于 465, 993, 995 端口)
    if ssl_str in ["ON", "SSL", "TLS", "TRUE", "YES"]:
        return "TLS"
    # 显式加密 (通常用于 587, 143, 110 端口)
    elif ssl_str == "STARTTLS":
        return "STARTTLS"
    # 明文或未指定
    elif ssl_str in ["", "OFF", "NONE", "FALSE", "NO", "PLAIN"]:
        return "PLAIN"
    else:
        # 保留未知的边缘情况，便于排查异常配置
        return ssl_str

def process_ports_usage(result_list, domain):
    """处理包含 ports_usage 的列表"""
    if not result_list:
        return
    
    # 兼容 SRV 的单对象情况（将其转为列表统一处理）
    if isinstance(result_list, dict):
        result_list = [result_list]

    for result in result_list:
        ports_usage = result.get("ports_usage", [])
        if not ports_usage:
            continue
            
        for proto_detail in ports_usage:
            proto_type = proto_detail.get("protocol", "").lower()
            server = proto_detail.get("host", "").rstrip(".")
            port = str(proto_detail.get("port") or "").strip()
            ssl_raw = proto_detail.get("ssl", "")
            
            # 如果缺了核心网络标识，跳过
            if not (proto_type and server and port):
                continue
                
            # 归一化加密类型
            crypto = normalize_crypto(ssl_raw)
                
            # 构建新的三维 Key: 协议-端口-加密方式
            cluster_key = f"{proto_type}-{port}-{crypto}"
            
            # 存入字典，利用 set 对 domain 自动去重
            clusters[cluster_key][server].add(domain)

# 输入输出路径
input_file = "/home/wzq/project/autov/data/check_dif_results.jsonl"
output_file = "/home/wzq/project/autov/data/clusters_crypto.json"

print("🔍 正在解析并去重配置数据...")

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            domain = data.get("domain")

            if not domain:
                continue

            # 提取三种机制下的端口使用情况
            process_ports_usage(data.get("autodiscover_check_result"), domain)
            process_ports_usage(data.get("autoconfig_check_result"), domain)
            process_ports_usage(data.get("srv_check_result"), domain)
        except json.JSONDecodeError:
            continue

# 转换 set 为 list，方便 JSON 序列化输出
output = {}
total_tuples = 0

for cluster_key, hosts in clusters.items():
    output[cluster_key] = {}
    for host, domains in hosts.items():
        output[cluster_key][host] = list(domains)
        total_tuples += 1

# 保存聚类结果
with open(output_file, "w", encoding="utf-8") as out_f:
    json.dump(output, out_f, indent=4)

print(f"✅ 全局去重与聚类完成！结果已保存至: {output_file}")
print(f"📊 共生成了 {len(output)} 个通信策略组 (协议-端口-加密)。")
print(f"🎯 提取了 {total_tuples} 个唯一的实际连接目标 (Target Tuples)。")