import json
import tldextract
import pandas as pd
from urllib.parse import urlparse
#专注统计重定向链链数，但是统计了所有（无论是否可以获得配置信息？）
def extract_registered_domain(url):
    """从 URL 中提取主域名（如 mail.example.com.cn -> example.com.cn）"""
    if not url:
        return ""
    ext = tldextract.extract(url)
    return ext.registered_domain

def analyze_redirect_chains(input_file, output_csv):
    print("🚀 正在专注提取重定向链条特征...")
    
    chain_records = []
    
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            domain = obj.get("domain")
            
            # 同时遍历 Autodiscover 和 Autoconfig
            all_entries = obj.get("autodiscover", []) + obj.get("autoconfig", [])
            
            for entry in all_entries:
                redirects = entry.get("redirects", [])
                
                # 如果完全没有重定向，记为 0 跳
                if not redirects:
                    continue
                    
                service_type = "Autodiscover" if "autodiscover" in entry.get("uri", "").lower() else "Autoconfig"
                status = entry.get("status_tag", "UNKNOWN")
                
                # 1. 重建完整 URL 链条 (起点 + 所有的重定向跳转)
                full_chain_urls = [entry.get("uri", "")] + [r.get("URL", "") for r in redirects]
                
                # 2. 提取链条上的主域名
                # 例如: [example.com, mail.example.com, autodiscover.vendor.com, outlook.com]
                # 转换后: [example.com, example.com, vendor.com, microsoft.com]
                reg_domains = [extract_registered_domain(u) for u in full_chain_urls if u]
                
                # 3. 计算跨组织跳数 (Cross-Org Hops)
                # 利用列表去重，相邻且相同的域名只算作一个组织
                # 比如 example.com -> example.com -> vendor.com，这里其实只有 1 次跨组织跳跃
                unique_orgs = []
                for d in reg_domains:
                    if not unique_orgs or unique_orgs[-1] != d:
                        unique_orgs.append(d)
                
                cross_org_hops = len(unique_orgs) - 1 if unique_orgs else 0
                
                # 是否存在隐藏委托 (超过 1 次跨组织跳转)
                is_hidden_delegation = (cross_org_hops >= 2)
                
                # 记录这根链条的数据
                chain_records.append({
                    "domain": domain,
                    "service_type": service_type,
                    "status_tag": status,
                    "total_redirects": len(redirects),      # HTTP 层面总重定向次数
                    "cross_org_hops": cross_org_hops,       # 跨越了多少个不同的利益实体
                    "is_hidden_delegation": is_hidden_delegation,
                    "chain_path": " -> ".join(unique_orgs)  # 组织维度的流转路径
                })

    # 将数据转换为 Pandas DataFrame，方便后续打印和统计
    df = pd.DataFrame(chain_records)
    
    if df.empty:
        print("❌ 未找到包含重定向的记录。")
        return

    # ==========================================
    # 打印一些有直接学术价值的统计信息
    # ==========================================
    print("\n" + "="*50)
    print("📊 论文指标 1: 重定向链的基础分布 (Complexity)")
    print(f"提取出包含重定向的链条总数: {len(df)}")
    print(df['total_redirects'].describe()[['mean', '50%', 'max']].to_string())
    
    print("\n" + "="*50)
    print("📊 论文指标 2: 信任边界扩张程度 (Cross-Org Hops)")
    print("跨组织跳转次数分布 (次数 : 链条数量):")
    print(df['cross_org_hops'].value_counts().sort_index().to_string())
    
    print("\n" + "="*50)
    print("📊 论文指标 3: 隐蔽的第三方委托 (Hidden Delegation)")
    hidden_df = df[df['is_hidden_delegation'] == True]
    print(f"发现经历了 2 个或以上不同第三方的链条数量: {len(hidden_df)}")
    if not hidden_df.empty:
        print("\n典型的隐藏委托路径 Top 3 (谁在做中间商?):")
        print(hidden_df['chain_path'].value_counts().head(3).to_string())
    
    # 导出为 CSV 供画图使用
    df.to_csv(output_csv, index=False)
    print(f"\n📁 详细链条特征已导出至: {output_csv}")

if __name__ == "__main__":
    # 使用你之前跑出来的 5000 个测试样本文件
    INPUT_FILE = "/home/wzq/project/autov/data/results_test.jsonl" #最原始的init.jsonl
    OUTPUT_FILE = "/home/wzq/project/autov/data/chain_analysis_results.csv"
    analyze_redirect_chains(INPUT_FILE, OUTPUT_FILE)