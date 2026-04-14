import json
from collections import defaultdict

'''
配置信息02
从 check_dif_results.jsonl 中提取 Host(及供给的那些域名)、port、protocol 到 clusters.json 中，
为后续的大规模实际连接测试 (TLS/TCP) 做准备
'''

# 定义聚类结果: clusters[协议-端口][主机名] = {域名集合}
clusters = defaultdict(lambda: defaultdict(set))

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
            
            # 如果缺了任何一个核心连接要素，就跳过
            if not (proto_type and server and port):
                continue
                
            cluster_key = f"{proto_type}-{port}"
            clusters[cluster_key][server].add(domain)

# 读取最新生成的 V3 结果文件
input_file = "/home/wzq/project/autov/data/check_dif_results.jsonl"
output_file = "/home/wzq/project/autov/data/clusters.json"

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        data = json.loads(line)
        domain = data.get("domain")

        # 提取各个机制下的端口使用情况
        process_ports_usage(data.get("autodiscover_check_result"), domain)
        process_ports_usage(data.get("autoconfig_check_result"), domain)
        process_ports_usage(data.get("srv_check_result"), domain)

# 转换 set 为 list，方便 JSON 序列化输出
output = {
    cluster: {host: list(domains) for host, domains in hosts.items()}
    for cluster, hosts in clusters.items()
}

# 保存聚类结果
with open(output_file, "w", encoding="utf-8") as out_f:
    json.dump(output, out_f, indent=4)

print(f"✅ 主机名聚类完成！结果已保存至: {output_file}")
print(f"📊 共生成了 {len(output)} 个 协议-端口 测试组。")