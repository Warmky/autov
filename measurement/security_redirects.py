import json
import tldextract
from urllib.parse import urlparse
#重定向安全分析脚本01
def analyze_redirect_security(input_file, output_file):
    print(f"🔍 正在深度解析重定向安全漏洞: {input_file} ...")
    
    total_chains = 0
    downgrade_count = 0
    loop_count = 0
    cross_domain_count = 0

    with open(input_file, "r", encoding="utf-8") as f, open(output_file, "w", encoding="utf-8") as out_f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            domain = obj.get("domain")
            
            # 同时提取 Autodiscover 和 Autoconfig 的记录
            # 因为两种机制都可能存在重定向劫持风险
            all_entries = obj.get("autodiscover", []) + obj.get("autoconfig", [])
            
            for entry in all_entries:
                redirects = entry.get("redirects", [])
                
                # 如果没有重定向，跳过
                if not redirects:
                    continue
                    
                total_chains += 1
                status_tag = entry.get("status_tag", "UNKNOWN")
                
                # ==========================================
                # 1. 还原完整的 URL 访问链
                # ==========================================
                # 链条起点是我们构造的初始 URI
                start_url = entry.get("uri", "")
                chain_urls = [start_url]
                chain_statuses = []
                
                for r in redirects:
                    chain_urls.append(r.get("URL", ""))
                    chain_statuses.append(r.get("Status", 0))
                    
                # ==========================================
                # 2. 提取不同层级的特征 (用于深度分析)
                # ==========================================
                schemes = [urlparse(u).scheme for u in chain_urls if u]
                fqdns = [urlparse(u).hostname for u in chain_urls if u]
                reg_domains = [tldextract.extract(u).registered_domain for u in chain_urls if u]
                
                # ==========================================
                # 3. 漏洞一：HTTPS 降级检测 (Downgrade Risk)
                # ==========================================
                has_downgrade = False
                for i in range(len(schemes) - 1):
                    if schemes[i] == "https" and schemes[i+1] == "http":
                        has_downgrade = True
                        downgrade_count += 1
                        break # 发现一次降级即可标记
                        
                # ==========================================
                # 4. 漏洞二：跨域委托检测 (Third-Party Delegation)
                # ==========================================
                is_cross_domain = False
                if len(reg_domains) > 1:
                    # 如果重定向的终点和起点的主域名不同，说明控制权交给了第三方
                    if reg_domains[-1] != reg_domains[0] and reg_domains[-1] != "":
                        is_cross_domain = True
                        cross_domain_count += 1

                # ==========================================
                # 5. 漏洞三：配置死循环/重定向风暴
                # ==========================================
                is_loop = False
                if status_tag in ["HTTP_REDIRECT_LIMIT", "REDIRECT_URL_FAILED", "REDIRECT_ADDR_FAILED"]:
                    is_loop = True
                    loop_count += 1

                # 组装安全分析记录并写入文件
                analysis_record = {
                    "domain": domain,
                    "service_type": "Autodiscover" if "autodiscover" in entry.get("uri", "").lower() else "Autoconfig",
                    "method": entry.get("method", "unknown"),
                    "status_tag": status_tag,
                    "chain_length": len(redirects),
                    "vulnerabilities": {
                        "has_downgrade": has_downgrade,
                        "is_cross_domain": is_cross_domain,
                        "is_loop": is_loop,
                    },
                    "trace": {
                        "full_urls": chain_urls,
                        "fqdns": fqdns,             # 保留子域名，以后可用于“悬空子域名(Dangling Subdomain)”接管分析
                        "registered_domains": reg_domains,
                        "statuses": chain_statuses
                    }
                }
                
                out_f.write(json.dumps(analysis_record) + "\n")

    print("\n✅ 安全视角的重定向链提取完成！")
    print("-" * 40)
    print(f"📊 共提取出含重定向的链条: {total_chains} 条")
    print(f"⚠️ 发现 HTTP 降级风险: {downgrade_count} 条")
    print(f"🌐 发生跨域第三方委托: {cross_domain_count} 条")
    print(f"🌀 发生死循环/次数超限: {loop_count} 条")
    print(f"📁 结果已保存至: {output_file}")


if __name__ == "__main__":
    # 使用你之前测试生成的 init.jsonl
    INPUT_JSONL = "/home/wzq/project/autov/data/results_test.jsonl"  # 请根据你的实际路径调整
    OUTPUT_JSONL = "/home/wzq/project/autov/data/security_redirect_analysis.jsonl"
    
    analyze_redirect_security(INPUT_JSONL, OUTPUT_JSONL)