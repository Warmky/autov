import json
import tldextract
import pandas as pd
import os

# 先从最原始的扫描结果文件init.jsonl中得到重定向链有待统计的几个指标，放到一个.csv文件里，后接plot_cdf.py绘制图表
# =====================================================================
# 模块一：权威实体解析引擎 (Entity Resolution Engine)
# 作用：将杂乱的域名统一映射为背后的实际商业实体（如 sharepoint.com -> Microsoft）
# =====================================================================
class EntityResolver:
    def __init__(self, entities_json_path):
        self.entity_map = {}
        self.load_entities(entities_json_path)

    def _get_reg_domain(self, url):
        """兼容最新版 tldextract，消除 DeprecationWarning 警告"""
        if not url: return ""
        ext = tldextract.extract(url)
        # 如果是新版本，使用推荐的新属性；否则兼容老版本
        if hasattr(ext, 'top_domain_under_public_suffix'):
            return ext.top_domain_under_public_suffix
        return ext.registered_domain

    def load_entities(self, path):
        print(f"🌍 正在加载权威实体映射库: {path} ...")
        if not os.path.exists(path):
            print("⚠️ 警告：未找到 entity_map.json！请先确保下载了该文件。")
            return
            
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # DuckDuckGo 数据格式解析
        for entity_name, details in data.items():
            for domain in details.get("properties", []):
                reg_domain = self._get_reg_domain(domain)
                if reg_domain:
                    self.entity_map[reg_domain] = entity_name
                    
        print(f"✅ 成功加载了 {len(self.entity_map)} 条域名到企业实体的映射规则！")

    def get_entity(self, url):
        """输入 URL，返回最终商业实体。若查不到，则退化为返回基础注册域名。"""
        if not url: return ""
        reg_domain = self._get_reg_domain(url)
        return self.entity_map.get(reg_domain, reg_domain)

# =====================================================================
# 模块二：重定向链特征提取逻辑
# 作用：遍历请求，计算 HTTP 跳数、跨实体跳数，并精准识别隐藏委托
# =====================================================================
def process_redirect_chains(input_file, output_csv, entities_path):
    print("🚀 开始进行学术级重定向链特征提取...")
    
    resolver = EntityResolver(entities_path)
    records = []
    
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            domain = obj.get("domain")
            origin_entity = resolver.get_entity(domain)
            
            all_entries = obj.get("autodiscover", []) + obj.get("autoconfig", [])
            
            for entry in all_entries:
                # 修复: 解决 JSON 中 redirects 为 null 的问题
                redirects = entry.get("redirects") or []
                status = entry.get("status_tag", "UNKNOWN")
                
                # 1. 重建完整 URL 链条 (起点 + 所有的重定向跳转)
                chain_urls = [entry.get("uri", "")] + [r.get("URL", "") for r in redirects]
                
                # 2. 映射为商业实体序列
                chain_entities = [resolver.get_entity(u) for u in chain_urls if u]
                
                # 3. 路径压缩 (相邻且相同的实体去重)
                path_entities = []
                for e in chain_entities:
                    if not path_entities or path_entities[-1] != e:
                        path_entities.append(e)
                
                # ==================== 指标计算核心 ====================
                
                # 指标 A: HTTP 总跳数 (衡量网络层的折腾程度)
                # 修复：因为 redirects 数组包含了初始请求本身，所以真正的跳转次数是 长度 - 1。
                # 使用 max(0, ...) 是为了防止 redirects 为空（如 TCP 失败）时变成 -1
                total_http_redirects = max(0, len(redirects) - 1)
                
                # 指标 B: 跨实体跳数 (衡量数据流转边界的跨越次数)
                cross_org_hops = len(path_entities) - 1 if path_entities else 0
                
                # 指标 C: 独立第三方数量 (衡量隐私暴露面)
                # 使用 set 集合剔除起点实体，剩下的就是纯粹的“外人”
                unique_third_parties = set(path_entities) - {origin_entity}
                external_entity_count = len(unique_third_parties)
                
                # 指标 D: 隐藏委托判定 (暗箱操作)
                # 极其严格的标准：必须涉及 2 家或以上【不同】的第三方公司
                is_hidden_delegation = (external_entity_count >= 2)
                
                records.append({
                    "domain": domain,
                    "status_tag": status,
                    "total_redirects": total_http_redirects,
                    "cross_org_hops": cross_org_hops,
                    "external_entity_count": external_entity_count,
                    "is_hidden_delegation": is_hidden_delegation,
                    "chain_path": " -> ".join(path_entities)
                })

    df = pd.DataFrame(records)
    
    if df.empty:
        print("❌ 未提取到任何数据，请检查输入文件。")
        return

    print("\n📊 数据提取概况：")
    print(f"共提取请求链条: {len(df)} 条")
    print(f"成功获取配置的链条: {len(df[df['status_tag'] == 'SUCCESS'])} 条")
    print(f"失败的请求链条: {len(df[df['status_tag'] != 'SUCCESS'])} 条")
    
    # ==================== 隐蔽委托案例深度输出 ====================
    hidden_df = df[df['is_hidden_delegation']]
    print(f"\n🎯 精准识别出的隐蔽第三方委托总计: {len(hidden_df)} 例")
    
    if not hidden_df.empty:
        # 分离成功与失败的隐蔽委托
        success_hidden = hidden_df[hidden_df['status_tag'] == 'SUCCESS']
        failed_hidden = hidden_df[hidden_df['status_tag'] != 'SUCCESS']
        
        print("\n" + "="*60)
        print(f"🚨 类别 1: 【成功获取配置】的隐蔽委托 (极其危险，共 {len(success_hidden)} 例)")
        print("说明：这些域名的邮件服务正常工作，但账号密码流经了多家不受控的第三方！")
        print("-" * 60)
        if not success_hidden.empty:
            # 统计出现次数最多的 Top 10 危险路径
            top_succ_paths = success_hidden['chain_path'].value_counts().head(10)
            for path, count in top_succ_paths.items():
                # 随机抽取一个具有代表性的受害域名
                sample_domain = success_hidden[success_hidden['chain_path'] == path]['domain'].iloc[0]
                print(f"🔹 出现次数: {count} 次 | 典型受害域名: {sample_domain}")
                print(f"   流转路径: {path}\n")
        else:
            print("   暂无成功获取配置的隐蔽委托案例。\n")

        print("="*60)
        print(f"⚠️ 类别 2: 【获取失败】的隐蔽委托 (浪费资源/陷入迷宫，共 {len(failed_hidden)} 例)")
        print("说明：这些请求不仅流经了多家第三方，且最终一无所获。")
        print("-" * 60)
        if not failed_hidden.empty:
            top_fail_paths = failed_hidden['chain_path'].value_counts().head(10)
            for path, count in top_fail_paths.items():
                sample_domain = failed_hidden[failed_hidden['chain_path'] == path]['domain'].iloc[0]
                print(f"🔸 出现次数: {count} 次 | 典型域名: {sample_domain}")
                print(f"   流转路径: {path}\n")
        else:
            print("   暂无失败的隐蔽委托案例。\n")
        print("="*60 + "\n")
        
    df.to_csv(output_csv, index=False)
    print(f"📁 学术级完整数据已保存至: {output_csv}")

if __name__ == "__main__":
    INPUT_FILE = "/home/wzq/project/autov/data/results_test.jsonl"  #最初的扫描的init.jsonl
    OUTPUT_FILE = "/home/wzq/project/autov/data/chain_analysis_results.csv"
    ENTITIES_FILE = "/home/wzq/project/autov/data/entity_map.json"  #DuckDuckgo中的域名-实体映射文件
    
    process_redirect_chains(INPUT_FILE, OUTPUT_FILE, ENTITIES_FILE)


# =====================================================================NOTE TODO
#因为发现存在这种情况，有些小域名没办法通过已知数据库得到是否同一实体，于是通过比较.之前的部分
#🚨 类别 1: 【成功获取配置】的隐蔽委托 (极其危险，共 2 例)
# 说明：这些域名的邮件服务正常工作，但账号密码流经了多家不受控的第三方！
# ------------------------------------------------------------
# 🔹 出现次数: 2 次 | 典型受害域名: moviezwap.casa
#    流转路径: moviezwap.casa -> moviezwap.sarl -> moviezwap.surf -> moviezwap.toys
# 模块一：权威实体解析引擎 (Entity Resolution Engine) 强化版
# 作用：权威库 + 启发式 SLD 聚类
# =====================================================================
class EntityResolver:
    def __init__(self, entities_json_path):
        self.entity_map = {}
        self.load_entities(entities_json_path)

    def _get_reg_domain(self, url):
        """兼容最新版 tldextract"""
        if not url: return ""
        ext = tldextract.extract(url)
        if hasattr(ext, 'top_domain_under_public_suffix'):
            return ext.top_domain_under_public_suffix
        return ext.registered_domain

    def load_entities(self, path):
        print(f"🌍 正在加载权威实体映射库: {path} ...")
        if not os.path.exists(path):
            print("⚠️ 警告：未找到 entity_map.json！")
            return
            
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        for entity_name, details in data.items():
            for domain in details.get("properties", []):
                reg_domain = self._get_reg_domain(domain)
                if reg_domain:
                    self.entity_map[reg_domain] = entity_name
                    
        print(f"✅ 成功加载了 {len(self.entity_map)} 条域名到企业实体的映射规则！")

    def get_entity(self, url):
        """
        核心智能判定逻辑：
        1. 先查 DuckDuckGo 权威库 (解决 sharepoint == microsoft)
        2. 若查不到，提取 SLD 核心词汇作为实体名 (解决 moviezwap.casa == moviezwap.surf)
        3. 兜底返回完整注册域名
        """
        if not url: return ""
        ext = tldextract.extract(url)
        reg_domain = self._get_reg_domain(url)
        
        # 策略 1: 权威库匹配
        if reg_domain in self.entity_map:
            return self.entity_map[reg_domain]
            
        # 策略 2: 启发式品牌聚类 (SLD Clustering)
        # ext.domain 会提取出 "moviezwap.casa" 中的 "moviezwap"
        if ext.domain:
            # 加上 "[Brand: ]" 前缀，方便我们在结果中一眼看出这是算法推断出来的实体
            return f"[Brand: {ext.domain}]"
            
        # 策略 3: 兜底
        return reg_domain