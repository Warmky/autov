import pandas as pd
import json
#重定向安全分析脚本02
def run_security_analysis(input_file):
    print("🚀 开始进行深度安全威胁分析...")
    data = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            data.append(json.loads(line))

    if not data:
        print("没有提取到重定向数据，请检查上一步的输出。")
        return

    df = pd.json_normalize(data)

    # ==========================================
    # 故事线一：直接致命的威胁 (成功的重定向)
    # ==========================================
    df_success = df[df['status_tag'] == 'SUCCESS']
    print(f"\n✅ [基线] 包含重定向且最终成功获取配置的链条数量: {len(df_success)}")

    # 1. 降级攻击
    downgrade_success = df_success[df_success['vulnerabilities.has_downgrade'] == True]
    print(f"🚨 [直接威胁] 成功获取配置，但中途发生 HTTP 降级的数量: {len(downgrade_success)}")
    if len(downgrade_success) > 0:
        print("   -> 危险样本举例: ", downgrade_success['domain'].head(3).tolist())

    # 2. 跨域委托
    cross_domain_success = df_success[df_success['vulnerabilities.is_cross_domain'] == True]
    print(f"🌐 [隐私/信任转移] 成功获取配置，且跨域委托给第三方的数量: {len(cross_domain_success)}")

    # ==========================================
    # 故事线二：悬空重定向与域名接管潜力 (失败的重定向)
    # ==========================================
    df_failed = df[df['status_tag'] != 'SUCCESS']
    print(f"\n❌ [基线] 包含重定向但最终获取失败的链条数量: {len(df_failed)}")

    dangling_candidates = df_failed[df_failed['vulnerabilities.is_cross_domain'] == True]
    print(f"💀 [潜在接管威胁] 重定向到第三方但最终失败的链条数量 (子域名接管候选者): {len(dangling_candidates)}")

    takeover_targets = set()
    for fqdns in dangling_candidates['trace.fqdns']:
        if len(fqdns) > 1:
            takeover_targets.add(fqdns[-1])

    print(f"🎯 提取出 {len(takeover_targets)} 个潜在可被抢注的第三方目标 FQDN 域名。")
    
    # 将这些可能有接管风险的域名存下来，以后可以写个脚本批量查它们是不是真的未注册
    with open("/home/wzq/project/autov/data/potential_takeover_targets.txt", "w") as f:
        for target in takeover_targets:
            f.write(target + "\n")
    print("📁 潜在接管目标已保存至 /home/wzq/project/autov/data/potential_takeover_targets.txt")

if __name__ == "__main__":
    run_security_analysis("/home/wzq/project/autov/data/security_redirect_analysis.jsonl")