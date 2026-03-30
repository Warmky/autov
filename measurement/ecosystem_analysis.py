import json
import tldextract
import pandas as pd
import os
#探究自动化配置生态情况的，包括是否被大型服务商垄断、长尾服务商、国家为单位数据主权流向 redirect2_1，下接measurement/draw_hero_sanky.py
# =====================================================================
# 复用我们的防弹实体解析器 (保持不变)
# =====================================================================
class EntityResolver:
    def __init__(self, entities_json_path):
        self.entity_map = {}
        self.load_entities(entities_json_path)

    def _get_reg_domain(self, url):
        if not url: return ""
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
        ext = tldextract.extract(url)
        reg_domain = self._get_reg_domain(url)
        if reg_domain in self.entity_map:
            return self.entity_map[reg_domain]
        if ext.domain:
            return f"[Brand: {ext.domain}]"
        return reg_domain

# =====================================================================
# 核心宏观生态分析逻辑 
# =====================================================================
def analyze_ecosystem(input_file, output_sankey_csv, entities_path):
    print("🌍 开始进行宏观邮件生态垄断度与数据主权分析...")
    resolver = EntityResolver(entities_path)
    records = []

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain = obj.get("domain")
            ext = tldextract.extract(domain)
            origin_tld = ext.suffix 
            origin_entity = resolver.get_entity(domain)
            
            # 1. 严谨的协议类型打标 (在循环外进行，干干净净)
            autodiscover_entries = obj.get("autodiscover", [])
            for e in autodiscover_entries: 
                e['_service_type'] = "Autodiscover"
                
            autoconfig_entries = obj.get("autoconfig", [])
            for e in autoconfig_entries: 
                e['_service_type'] = "Autoconfig"
            
            all_entries = autodiscover_entries + autoconfig_entries
            
            # 2. 唯一的遍历循环 (以域名为单位的“短路探测”)
            for entry in all_entries:
                # 必须且只能看 SUCCESS 的数据
                if entry.get("status_tag") != "SUCCESS":
                    continue
                    
                service_type = entry.get('_service_type', "Unknown")
                redirects = entry.get("redirects") or []
                
                # 提取配置的最终归宿
                if redirects:
                    final_url = redirects[-1].get("URL", "")
                    final_entity = resolver.get_entity(final_url)
                else:
                    final_entity = origin_entity
                
                hosting_provider = "Self-Hosted" if final_entity == origin_entity else final_entity
                
                records.append({
                    "domain": domain,
                    "tld": origin_tld,
                    "service_type": service_type,
                    "provider": hosting_provider
                })
                
                # 【神级修复】：真实客户端一旦拿到配置就会停止探测。
                # 加上 break，确保 1个域名 绝对只投 1票！彻底挤干水分！
                break

    df = pd.DataFrame(records)
    if df.empty:
        print("❌ 未找到任何 SUCCESS 的记录。")
        return

    # 1. 基础设施垄断度计算 (HHI)
    total_valid = len(df)
    provider_counts = df['provider'].value_counts()
    market_shares = (provider_counts / total_valid) * 100
    hhi = sum(share**2 for share in market_shares)

    print("\n" + "="*50)
    print("📊 [RQ1: 基础设施中心化与垄断度]")
    print(f"总计成功配置的有效链条数: {total_valid}")
    print(f"全球邮件托管市场 HHI 指数: {hhi:.2f} (注: >2500 为高度垄断)")
    print("\n🏆 Top 10 终态数据托管巨头 (包含自建):")
    print(market_shares.head(10).round(2).astype(str) + "%")

    # 2. 长尾生存现状分析
    cumulative_shares = market_shares.cumsum()
    # 修复：寻找累积份额【还没到90%】的数量，再加上刚好跨过90%的那 1 家
    top_90_percent_cutoff = len(cumulative_shares[cumulative_shares < 90]) + 1
    long_tail_count = len(market_shares) - top_90_percent_cutoff
    print(f"\n💡 长尾现状: 前 {top_90_percent_cutoff} 家巨头瓜分了 90% 的市场，剩下的 {long_tail_count} 家长尾服务商在底层的 10% 中艰难求生。")

    # 3. 数据主权与合规分析
    print("\n" + "="*50)
    print("🌍 [RQ3: 数据主权与跨国托管]")
    target_cctlds = ['de', 'cn', 'uk', 'fr', 'ru', 'jp']
    for cctld in target_cctlds:
        cctld_df = df[df['tld'] == cctld]
        if not cctld_df.empty:
            print(f"\n国家顶级域 .{cctld} (样本数: {len(cctld_df)}):")
            top_3 = cctld_df['provider'].value_counts(normalize=True).head(3) * 100
            print(top_3.round(2).astype(str) + "%")

    # 4. 导出桑基图数据
    top_tlds = df['tld'].value_counts().nlargest(10).index.tolist()
    df['sankey_tld'] = df['tld'].apply(lambda x: x if x in top_tlds else "Other TLDs")
    
    top_providers = provider_counts.nlargest(8).index.tolist()
    df['sankey_provider'] = df['provider'].apply(lambda x: x if x in top_providers else "Other Providers")

    sankey_data = df.groupby(['service_type', 'sankey_tld', 'sankey_provider']).size().reset_index(name='weight')
    sankey_data.to_csv(output_sankey_csv, index=False)
    print("\n" + "="*50)
    print(f"📁 桑基图绘图数据已导出至: {output_sankey_csv}")

if __name__ == "__main__":
    INPUT_FILE = "/home/wzq/project/autov/data/results_test.jsonl"
    OUTPUT_SANKEY = "/home/wzq/project/autov/data/sankey_tld_to_provider.csv"
    ENTITIES_FILE = "/home/wzq/project/autov/data/entity_map.json" 
    
    analyze_ecosystem(INPUT_FILE, OUTPUT_SANKEY, ENTITIES_FILE)