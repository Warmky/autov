import json
import tldextract
import pandas as pd
import os
import ipaddress
from collections import defaultdict

'''
配置信息03
从clusters.json生成ecosystem_details.csv和host_tier_mapping.json，分析主机名的生态垄断度并进行分层打标（Giant vs Long-tail vs Self-Hosted）
'''

# =====================================================================
# 复用防弹实体解析器 (新增 IP 地址精准识别)
# =====================================================================
class EntityResolver:
    def __init__(self, entities_json_path):
        self.entity_map = {}
        self.load_entities(entities_json_path)

    def _get_reg_domain(self, url):
        if not url: return ""
        if not url.startswith('http'):
            url = 'http://' + url
        ext = tldextract.extract(url)
        if hasattr(ext, 'top_domain_under_public_suffix'):
            return ext.top_domain_under_public_suffix
        return ext.registered_domain

    def load_entities(self, path):
        if not os.path.exists(path): return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for entity_name, details in data.items():
            for domain in details.get("properties", []):
                reg_domain = self._get_reg_domain(domain)
                if reg_domain:
                    self.entity_map[reg_domain] = entity_name

    def get_entity(self, url):
        if not url: return ""
        
        # 🌟 新增：判断是否为纯 IP 地址 (支持 IPv4 和 IPv6)
        # 去掉可能存在的端口号和 IPv6 的方括号
        clean_host = url.split(':')[0].strip("[]")
        try:
            ipaddress.ip_address(clean_host)
            return f"[IP: {clean_host}]"  # 纯 IP 地址独立成派！
        except ValueError:
            pass # 不是 IP，继续走域名解析逻辑

        reg_domain = self._get_reg_domain(url)
        if reg_domain in self.entity_map:
            return self.entity_map[reg_domain]
        if reg_domain:
            return f"[Brand: {reg_domain}]"
        
        return "[Unknown]"

# =====================================================================
# 核心：以主机为中心的生态分析与【分层打标】逻辑
# =====================================================================
def analyze_host_centralization(cluster_file, entities_path, output_csv, output_json):
    print("🌍 开始基于配置文件的主机名进行生态垄断度分析与分层打标...")
    resolver = EntityResolver(entities_path)
    
    with open(cluster_file, "r", encoding="utf-8") as f:
        clusters = json.load(f)

    # 1. 收集每个 Hostname 服务的所有 Domains
    host_served_domains = defaultdict(set)
    for proto_port, hosts in clusters.items():
        for host, domains in hosts.items():
            host_served_domains[host].update(domains)

    # 2. 对每个 Hostname 进行定性评估
    host_evaluations = {}
    provider_domain_count = defaultdict(set) # 用于计算每个 Provider 的真实市场份额

    for host, domains in host_served_domains.items():
        base_provider = resolver.get_entity(host)
        host_reg_domain = resolver._get_reg_domain(host)
        
        # 判断：这个主机是否服务了“外人”？
        # (加入了 host == d 的兜底判断，防止纯 IP 等情况匹配失败)
        serves_others = False
        for d in domains:
            d_reg_domain = resolver._get_reg_domain(d)
            if not ((host_reg_domain and host_reg_domain == d_reg_domain) or host == d):
                serves_others = True
                break

        # 如果既给自己用又给别人用，整体算作该 Provider 的份额
        if not serves_others:
            macro_provider = "Self-Hosted (纯自建)"
            tier = "Self-Hosted"
        else:
            macro_provider = base_provider
            tier = "Pending" 

        host_evaluations[host] = {
            "Provider": macro_provider,
            "Tier": tier
        }
        
        # 将这些域名归入宏观提供商名下用于算份额
        provider_domain_count[macro_provider].update(domains)

    # 3. 计算市场份额与确立 Giants (巨头)
    total_unique_domains = len(set(d for domains in host_served_domains.values() for d in domains))
    
    market_shares = {}
    for provider, domains in provider_domain_count.items():
        market_shares[provider] = (len(domains) / total_unique_domains) * 100

    # 按份额排序
    sorted_providers = sorted(market_shares.items(), key=lambda item: item[1], reverse=True)
    
    # 提取 Top 10 作为 Giants (排除 Self-Hosted 和 Unknown)
    giants = []
    for provider, share in sorted_providers:
        if provider not in ["Self-Hosted (纯自建)", "[Unknown]"] and not str(provider).startswith("[IP:"):
            giants.append(provider)
        if len(giants) >= 10:
            break

    # 4. 更新 Tier (巨头 vs 长尾)
    for host, eval_data in host_evaluations.items():
        if eval_data["Tier"] == "Pending":
            if eval_data["Provider"] in giants:
                eval_data["Tier"] = "Giant"
            else:
                eval_data["Tier"] = "Long-tail"

    # ==========================================
    # 5. 导出数据：构建明细 CSV 与 映射 JSON
    # ==========================================
    detailed_records = []
    for proto_port, hosts in clusters.items():
        for host, domains in hosts.items():
            eval_data = host_evaluations[host]
            for d in domains:
                detailed_records.append({
                    "Protocol_Port": proto_port,
                    "Hostname": host,
                    "Domain": d,
                    "Provider": eval_data["Provider"],
                    "Tier": eval_data["Tier"]
                })

    # 导出明细 CSV
    df = pd.DataFrame(detailed_records)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    
    # 导出 Hostname -> Tier 的黄金映射字典
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(host_evaluations, f, indent=4)

    # 6. 打印简报
    hhi = sum(share**2 for share in market_shares.values())
    
    print("\n" + "="*50)
    print(f"📊 [配置文件 Server 主机名中心化报告 (V3 IP分离版)]")
    print(f"总计评估的去重有效域名数: {total_unique_domains}")
    print(f"全球邮件配置主机 HHI 指数: {hhi:.2f} (注: >2500 为高度垄断)")
    print("\n🏆 Top 15 宏观份额 (包含 IP 分离与整体计算):")
    for rank, (provider, share) in enumerate(sorted_providers[:15], 1):
        print(f"{rank:2d}. {provider:<35} {share:>6.2f}%")
        
    print("\n" + "="*50)
    print(f"📁 分层打标完成！")
    print(f"✅ 全文明细 CSV 已导出至: {output_csv}")
    print(f"✅ 黄金字典 JSON 已导出至: {output_json}")

if __name__ == "__main__":
    CLUSTER_FILE = "/home/wzq/project/autov/data/clusters.json" 
    ENTITIES_FILE = "/home/wzq/project/autov/data/entity_map.json" 
    
    OUTPUT_CSV = "/home/wzq/project/autov/data/ecosystem_details.csv"
    OUTPUT_JSON = "/home/wzq/project/autov/data/host_tier_mapping.json"
    
    analyze_host_centralization(CLUSTER_FILE, ENTITIES_FILE, OUTPUT_CSV, OUTPUT_JSON)