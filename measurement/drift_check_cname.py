import dns.resolver
#  配置漂移02 尝试通过域名的子域名CNAME判断是否真正漂移，现在只是对单一域名
def check_subdomains(domain):
    prefixes = ["mail", "imap", "smtp", "pop", "webmail", "autodiscover"]
    
    print(f"🔍 开始探测 {domain} 的邮件子域名...\n" + "="*40)
    
    # 设置常用的公共 DNS，防止本地 DNS 缓存污染
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    
    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"
        print(f"\n▶ 正在查询: {subdomain}")
        
        # 1. 查询 CNAME 记录
        has_cname = False
        try:
            cname_answers = resolver.resolve(subdomain, 'CNAME', lifetime=5)
            for rdata in cname_answers:
                print(f"  [CNAME] -> {rdata.target.to_text()}")
                has_cname = True
        except dns.resolver.NoAnswer:
            print("  [CNAME] -> (无记录)")
        except dns.resolver.NXDOMAIN:
            print("  [状态]  -> NXDOMAIN (该子域名不存在)")
            continue # 如果域名都不存在，就不需要查 A 记录了
        except Exception as e:
            print(f"  [CNAME] -> 查询出错: {type(e).__name__}")

        # 2. 查询 A 记录 (IP地址)
        try:
            a_answers = resolver.resolve(subdomain, 'A', lifetime=5)
            for rdata in a_answers:
                print(f"  [A]     -> {rdata.address}")
                # 如果有 CNAME，通常 A 记录解析出来的就是 CNAME 目标的 IP
        except Exception:
            if not has_cname:
                print("  [A]     -> (无记录)")

if __name__ == "__main__":
    target = "erome.com"
    check_subdomains(target)