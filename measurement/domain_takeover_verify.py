import tldextract
import dns.resolver
import whois
import concurrent.futures
import time

INPUT_FILE = "/home/wzq/project/autov/data/potential_takeover_targets.txt"
OUTPUT_FILE = "/home/wzq/project/autov/data/confirmed_takeovers.txt"
#重定向安全分析脚本03 具体调用接口查看哪些域名可被抢注
# 常见的 Whois 未注册特征字符串，用于精准判定
UNREGISTERED_STRINGS = [
    "no match", "not found", "no data found", "domain not found", 
    "available for registration", "is free", "no entries found",
    "the queried object does not exist", "status: free"
]

def check_domain_availability(base_domain):
    """
    核心检测逻辑：先查 DNS，如果 NXDOMAIN，再查 Whois 确认可注册
    """
    result = {
        "domain": base_domain,
        "dns_dead": False,
        "whois_available": False,
        "status": "SAFE",
        "reason": ""
    }
    
    # 1. DNS NS 记录检查 (过滤掉存活的域名)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        # 查询 NS 记录
        resolver.resolve(base_domain, 'NS')
        result["reason"] = "DNS NS records exist (Domain is alive)"
        return result
    except dns.resolver.NXDOMAIN:
        result["dns_dead"] = True
        result["reason"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["dns_dead"] = True
        result["reason"] = "NoAnswer (Suspicious)"
    except Exception as e:
        result["dns_dead"] = True
        result["reason"] = f"DNS Error: {type(e).__name__}"

    # 2. 如果 DNS 判定为死亡/可疑，深入进行 Whois 查询
    if result["dns_dead"]:
        try:
            # whois.whois 会向相应的注册局发起请求
            w = whois.whois(base_domain)
            
            # python-whois 在域名不存在时，通常返回 None、空字典，或者特定的 status
            if not w or not w.domain_name or w.status is None:
                result["whois_available"] = True
            elif isinstance(w.text, str):
                # 检查返回的原始文本是否包含未注册关键字
                lower_text = w.text.lower()
                if any(keyword in lower_text for keyword in UNREGISTERED_STRINGS):
                    result["whois_available"] = True
        except whois.parser.PywhoisError as e:
            # 抛出 PywhoisError 通常意味着 "No match for domain"
            lower_err = str(e).lower()
            if any(keyword in lower_err for keyword in UNREGISTERED_STRINGS):
                result["whois_available"] = True
        except Exception as e:
            result["reason"] += f" | Whois Error: {type(e).__name__}"

    # 3. 最终定性
    if result["whois_available"]:
        result["status"] = "CRITICAL: AVAILABLE FOR REGISTRATION!"
    elif result["dns_dead"]:
        result["status"] = "WARNING: DNS Dead but Whois not strictly free (Pending Delete/Hold)"

    return result

def verify_takeovers():
    print("🔍 正在加载潜在的接管目标 FQDN...")
    
    with open(INPUT_FILE, "r") as f:
        fqdns = [line.strip() for line in f if line.strip()]
        
    if not fqdns:
        print("未找到输入文件或文件为空。")
        return

    # 核心：提取 FQDN 的主域名，并利用 Set 去重
    base_domains = set()
    for fqdn in fqdns:
        extracted = tldextract.extract(fqdn)
        if extracted.registered_domain:
            base_domains.add(extracted.registered_domain)
            
    print(f"📊 从 {len(fqdns)} 个 FQDN 中，去重提取出 {len(base_domains)} 个独立主域名。")
    print("🚀 开始向全球 DNS 服务器及 Whois 注册局发起并发查询 (这可能需要几分钟)...\n")
    
    critical_domains = []
    warning_domains = []
    
    # 采用少量并发，防止被 Whois 服务器封禁 IP (建议 5-10 线程)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_domain_availability, domain): domain for domain in base_domains}
        
        for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
            domain = futures[future]
            try:
                res = future.result()
                if "CRITICAL" in res["status"]:
                    print(f"[🚨 高危可抢注] {domain}")
                    critical_domains.append(domain)
                elif "WARNING" in res["status"]:
                    print(f"[⚠️ 悬空但不可注] {domain} ({res['reason']})")
                    warning_domains.append(domain)
                
                # 简单进度反馈
                if idx % 10 == 0:
                    print(f"   ... 已处理 {idx}/{len(base_domains)} 个主域名 ...")
            except Exception as e:
                print(f"[❌ 执行错误] {domain}: {e}")
                
            time.sleep(0.5) # 友好的查询延迟，保护你的服务器 IP 不被 Whois 屏蔽

    # 写入最终的爆炸性结果
    with open(OUTPUT_FILE, "w") as f:
        f.write("=== CRITICAL: 确认可抢注的域名 (真实接管漏洞) ===\n")
        for d in critical_domains:
            f.write(d + "\n")
            
        f.write("\n=== WARNING: DNS 悬空但当前处于保留/赎回期 (未来可接管) ===\n")
        for d in warning_domains:
            f.write(d + "\n")

    print("\n" + "="*50)
    print("✅ 验证大扫除完成！")
    print(f"🎯 确认可立刻花钱抢注的高危主域名: {len(critical_domains)} 个")
    print(f"⏸️ 处于赎回期或解析瘫痪的悬空域名: {len(warning_domains)} 个")
    print(f"📁 确凿证据已存档至: {OUTPUT_FILE}")
    print("="*50)

if __name__ == "__main__":
    verify_takeovers()