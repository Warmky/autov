import json
import tldextract
import os
from collections import defaultdict
#measurement/ecosystem_analysis.py之前会重复计算同一机制不同路径的服务商情况，现在在这里单独把这方面拎出来分析结果，改为只分析优先级最高的路径。
# =====================================================================
# 复用极简版实体解析
# =====================================================================
def get_reg_domain(url):
    if not url: return ""
    ext = tldextract.extract(url)
    if hasattr(ext, 'top_domain_under_public_suffix'):
        return ext.top_domain_under_public_suffix
    return ext.registered_domain

# =====================================================================
# 核心猎杀与溯源逻辑
# =====================================================================
def hunt_intra_protocol_conflicts(input_file, output_report_file):
    print("🕵️ 开始猎杀 '协议内脑裂' 并追踪探测路径...")
    
    conflict_count = 0
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_report_file), exist_ok=True)
    
    with open(input_file, "r", encoding="utf-8") as f_in, \
         open(output_report_file, "w", encoding="utf-8") as f_out:
        
        # 写入报告头部
        f_out.write("=" * 70 + "\n")
        f_out.write("🚨 协议内配置冲突 (Intra-protocol Split-Brain) 深度溯源报告 🚨\n")
        f_out.write("=" * 70 + "\n\n")

        for line in f_in:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain = obj.get("domain")
            origin_reg = get_reg_domain(domain)
            
            # 使用 defaultdict 记录映射：Provider -> [探测路径列表]
            ad_providers = defaultdict(list)
            ac_providers = defaultdict(list)
            
            # 1. 检查 Autodiscover
            for entry in obj.get("autodiscover", []):
                if entry.get("status_tag") == "SUCCESS":
                    method = entry.get("method", "UNKNOWN_METHOD")
                    index = entry.get("index", "?")
                    
                    redirects = entry.get("redirects") or []
                    final_url = redirects[-1].get("URL", "") if redirects else entry.get("uri", "")
                    final_entity = get_reg_domain(final_url)
                    provider = "Self-Hosted" if final_entity == origin_reg else final_entity
                    
                    # 记录：这个提供商是通过什么 method 和 index 拿到的
                    path_info = f"Method: {method} (Index: {index})"
                    ad_providers[provider].append(path_info)
            
            # 2. 检查 Autoconfig
            for entry in obj.get("autoconfig", []):
                if entry.get("status_tag") == "SUCCESS":
                    method = entry.get("method", "UNKNOWN_METHOD")
                    index = entry.get("index", "?")
                    
                    redirects = entry.get("redirects") or []
                    final_url = redirects[-1].get("URL", "") if redirects else entry.get("uri", "")
                    final_entity = get_reg_domain(final_url)
                    provider = "Self-Hosted" if final_entity == origin_reg else final_entity
                    
                    path_info = f"Method: {method} (Index: {index})"
                    ac_providers[provider].append(path_info)
            
            # 3. 核心判定：同一协议下是否出现了不同的服务商？
            has_ad_conflict = len(ad_providers) > 1
            has_ac_conflict = len(ac_providers) > 1
            
            if has_ad_conflict or has_ac_conflict:
                conflict_count += 1
                
                # 构建写入文件的详细报告
                report_block = f"[{conflict_count}] 危险域名: {domain}\n"
                
                if has_ad_conflict:
                    report_block += "  [Autodiscover 机制脑裂]\n"
                    for prov, paths in ad_providers.items():
                        report_block += f"    ┣━ 归宿: {prov}\n"
                        for p in paths:
                            report_block += f"    ┃    ┗━ 探测依据: {p}\n"
                            
                if has_ac_conflict:
                    report_block += "  [Autoconfig 机制脑裂]\n"
                    for prov, paths in ac_providers.items():
                        report_block += f"    ┣━ 归宿: {prov}\n"
                        for p in paths:
                            report_block += f"    ┃    ┗━ 探测依据: {p}\n"
                            
                report_block += "-" * 70 + "\n"
                
                # 写入文件并同步打印极其简短的提示到终端
                f_out.write(report_block)
                print(f"⚠️ 发现冲突域名: {domain} (已记录至报告)")

    # 打印最终总结
    print("\n" + "=" * 50)
    if conflict_count == 0:
        print("✅ 扫描完成：未发现协议内冲突。")
    else:
        print(f"🔥 扫描完成：共捕获 {conflict_count} 个协议内脑裂域名！")
        print(f"📁 详细溯源报告已保存至: {output_report_file}")
        print("💡 请打开该文件，去验证你的 ISPDB 假设吧！")

if __name__ == "__main__":
    INPUT_FILE = "/home/wzq/project/autov/data/results_test.jsonl"
    OUTPUT_REPORT = "/home/wzq/project/autov/data/intra_protocol_conflicts_report.txt"
    
    hunt_intra_protocol_conflicts(INPUT_FILE, OUTPUT_REPORT)