import pandas as pd
import json
import tldextract
from collections import Counter

# 1. 预定义一些已知的大型服务商指纹（可根据你的发现不断扩充）
PROVIDER_MAP = {
    "outlook.com": "Microsoft Exchange/O365",
    "office365.com": "Microsoft Exchange/O365",
    "microsoft.com": "Microsoft Exchange/O365",
    "google.com": "Google Workspace",
    "gmail.com": "Google Workspace",
    "secureserver.net": "GoDaddy",
    "godaddy.com": "GoDaddy",
    "hostgator.com": "HostGator",
    "bluehost.com": "Bluehost",
    "1and1.com": "1&1 IONOS",
    "ionos.com": "1&1 IONOS",
    "strato.de": "Strato (DE)",
    "mail.ru": "Mail.ru (RU)",
    "yandex.ru": "Yandex (RU)",
    "aliyun.com": "Alibaba Cloud (CN)",
    "netease.com": "NetEase (CN)",
    "tencent.com": "Tencent (CN)"
}

def get_provider_name(domain):
    """根据注册域名映射到具体的服务商名称"""
    if not domain:
        return "Unknown/Failed"
    return PROVIDER_MAP.get(domain, domain) # 如果不在字典里，直接返回原域名

def analyze_ecosystem():
    print("🌍 正在进行宏观邮件生态垄断度与数据主权分析...")
    
    data = []
    with open("/home/wzq/project/autov/data/security_redirect_analysis.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            data.append(json.loads(line))

    if not data:
        print("无数据，请检查输入文件。")
        return

    df = pd.json_normalize(data)
    
    # 我们只关心成功获取配置的样本，因为只有这些是真正生效的邮件托管关系
    df_success = df[df['status_tag'] == 'SUCCESS'].copy()
    
    # 提取源域名的 TLD (用于区分 gTLD 和 ccTLD)
    df_success['origin_tld'] = df_success['domain'].apply(lambda x: tldextract.extract(x).suffix)
    
    # 提取最终的服务商域名 (重定向链的最后一跳)
    def extract_final_provider(reg_domains, origin_domain):
        if not reg_domains:
            return "Self-Hosted" # 没有重定向，说明是自建邮局
        
        final_domain = reg_domains[-1]
        origin_reg = tldextract.extract(origin_domain).registered_domain
        
        if final_domain == origin_reg:
            return "Self-Hosted"
        return get_provider_name(final_domain)

    df_success['provider'] = df_success.apply(
        lambda row: extract_final_provider(row['trace.registered_domains'], row['domain']), axis=1
    )

    # ==========================================
    # 1. 市场份额与 HHI 垄断指数计算
    # ==========================================
    total_valid = len(df_success)
    provider_counts = df_success['provider'].value_counts()
    
    # 计算 HHI (Herfindahl-Hirschman Index)
    # HHI < 1500 (竞争激烈), 1500-2500 (中度集中), > 2500 (高度垄断)
    market_shares = (provider_counts / total_valid) * 100
    hhi = sum(share**2 for share in market_shares)
    
    print(f"\n📊 [宏观市场集中度]")
    print(f"总计成功配置的域名数: {total_valid}")
    print(f"识别到的独立服务商数量: {len(provider_counts)}")
    print(f"邮件托管市场 HHI 垄断指数: {hhi:.2f} (注: >2500 为高度垄断)")
    print("\n🏆 Top 10 邮件服务提供商:")
    print(market_shares.head(10).round(2).astype(str) + "%")

    # ==========================================
    # 2. 为 Sankey 图准备数据 (TLD -> Provider)
    # ==========================================
    # 为了图表美观，我们将非 Top 15 的 TLD 归为 "Other TLDs"
    top_tlds = df_success['origin_tld'].value_counts().nlargest(15).index.tolist()
    df_success['sankey_tld'] = df_success['origin_tld'].apply(lambda x: x if x in top_tlds else "Other TLDs")
    
    # 将非 Top 10 的 Provider 归为 "Other Providers"
    top_providers = provider_counts.nlargest(10).index.tolist()
    df_success['sankey_provider'] = df_success['provider'].apply(lambda x: x if x in top_providers else "Other Providers")

    # 按服务发现机制分类 (Autodiscover vs Autoconfig)
    sankey_data = df_success.groupby(['service_type', 'sankey_tld', 'sankey_provider']).size().reset_index(name='weight')
    
    # 导出为 CSV，你可以直接扔进 RawGraphs (rawgraphs.io) 或用 Plotly 画出极其专业的桑基图
    sankey_csv_path = "/home/wzq/project/autov/data/sankey_tld_to_provider.csv"
    sankey_data.to_csv(sankey_csv_path, index=False)
    
    # ==========================================
    # 3. 数据主权揭秘 (ccTLD 本地化分析)
    # ==========================================
    print("\n🌍 [数据主权与跨国托管现象]")
    # 举例：看看德国 (.de) 的域名是不是更喜欢本土服务商
    if 'de' in df_success['origin_tld'].values:
        de_domains = df_success[df_success['origin_tld'] == 'de']
        print(f"🇩🇪 .de 域名的邮件服务商偏好:")
        print(de_domains['provider'].value_counts().head(3))

    if 'cn' in df_success['origin_tld'].values:
        cn_domains = df_success[df_success['origin_tld'] == 'cn']
        print(f"🇨🇳 .cn 域名的邮件服务商偏好:")
        print(cn_domains['provider'].value_counts().head(3))

    print(f"\n📁 桑基图绘图数据已导出至: {sankey_csv_path}")

if __name__ == "__main__":
    analyze_ecosystem()