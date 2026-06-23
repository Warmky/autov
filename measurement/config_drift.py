import json
import xml.etree.ElementTree as ET
import dns.resolver
import re
import pandas as pd
import os

# 复用你已有的实体映射器，还只有Autoconfig
try:
    from analyze_host import EntityResolver
except ImportError:
    print("⚠️ 导入失败：请确保此脚本与 analyze_host.py 在同一目录下（例如 measurement/ 目录）。")
    exit(1)

def clean_xml(xml_str):
    """清洗 XML 命名空间，复用之前的逻辑"""
    xml_str = re.sub(r'\sxmlns(:\w+)?="[^"]*"', '', xml_str)
    xml_str = re.sub(r'</?\w+:', lambda m: '<' if m.group(0).startswith('</') else '<', xml_str)
    return xml_str

def get_dns_providers(domain, resolver):
    """动态查询域名的 MX 和 SPF 记录，并映射为服务商实体"""
    mx_providers = set()
    spf_providers = set()
    
    # 1. 查询 MX 记录
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        for rdata in answers:
            # 提取 MX 主机名并去掉末尾的 '.'
            mx_host = rdata.exchange.to_text().rstrip('.')
            mx_providers.add(resolver.get_entity(mx_host))
    except Exception:
        pass # 忽略超时或无记录的异常
        
    # 2. 查询 SPF 记录 (TXT)
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for rdata in answers:
            # TXT 记录可能被分段，拼合后解码
            txt_record = b"".join(rdata.strings).decode('utf-8').strip('"')
            if txt_record.startswith("v=spf1"):
                # 提取 include: 后面的域名
                includes = re.findall(r'include:([^\s]+)', txt_record)
                for inc in includes:
                    spf_providers.add(resolver.get_entity(inc))
    except Exception:
        pass
        
    return list(mx_providers), list(spf_providers)

def detect_drift(raw_jsonl_file, entities_path, output_csv):
    print("🚀 开始执行配置漂移分析...")
    resolver = EntityResolver(entities_path)
    drift_results = []
    
    processed_count = 0
    with open(raw_jsonl_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except:
                continue
                
            domain = obj.get("domain") or obj.get("Domain")
            if not domain: continue

            # --- 1. 提取配置中的邮件服务器 (Expected) ---
            config_hosts = set()
            
            # 提取 Autoconfig 主机名
            for entry in obj.get("autoconfig", []) + obj.get("Autoconfig", []):
                raw_xml = entry.get("config") or entry.get("Config") or ""
                if not raw_xml or "Bad" in raw_xml or "Error" in raw_xml: continue
                try:
                    root = ET.fromstring(clean_xml(raw_xml))
                    for host_node in root.findall(".//hostname"):
                        if host_node.text: config_hosts.add(host_node.text.strip().lower())
                except: pass
                
            # 提取 Autodiscover 主机名
            for entry in obj.get("autodiscover", []) + obj.get("Autodiscover", []):
                raw_xml = entry.get("config") or entry.get("Config") or ""
                if not raw_xml or "Bad" in raw_xml or "Error" in raw_xml: continue
                try:
                    root = ET.fromstring(clean_xml(raw_xml))
                    for server_node in root.findall(".//Server"):
                        if server_node.text: config_hosts.add(server_node.text.strip().lower())
                except: pass
                
            # 如果该域名没扫出任何有效配置，跳过对比
            if not config_hosts:
                continue 
                
            # 将配置的主机名映射为 Provider
            config_providers = {resolver.get_entity(host) for host in config_hosts}
            
            # --- 2. 动态获取实际的 DNS 信息 (Actual) ---
            print(f"[*] 正在探测域名 DNS: {domain}")
            mx_providers, spf_providers = get_dns_providers(domain, resolver)
            
            # --- 3. 漂移判定逻辑 ---
            # 过滤掉 Unknown 和自建IP情况，进行严谨比对
            valid_config_provs = {p for p in config_providers if not p.startswith("[")}
            valid_mx_provs = {p for p in mx_providers if not p.startswith("[")}
            valid_spf_provs = {p for p in spf_providers if not p.startswith("[")}
            
            is_drift = False
            drift_type = "Consistent"
            
            if valid_config_provs and (valid_mx_provs or valid_spf_provs):
                # 如果 MX 且/或 SPF 都有明确的大厂标签，但都不在配置文件标明的提供商里
                mx_drift = bool(valid_mx_provs and not (valid_config_provs & valid_mx_provs))
                spf_drift = bool(valid_spf_provs and not (valid_config_provs & valid_spf_provs))
                
                if mx_drift and spf_drift:
                    is_drift = True
                    drift_type = "🚨 Complete Drift (MX & SPF Mismatch)"
                elif mx_drift:
                    is_drift = True
                    drift_type = "⚠️ MX Drift (Gateway or Partial Migration)"
                elif spf_drift:
                    is_drift = True
                    drift_type = "⚠️ SPF Drift (Sender Migration)"
            
            drift_results.append({
                "Domain": domain,
                "Config_Hosts_Found": " | ".join(config_hosts),
                "Config_Provider": " | ".join(config_providers),
                "Actual_MX_Provider": " | ".join(mx_providers) if mx_providers else "No MX / Unknown",
                "Actual_SPF_Provider": " | ".join(spf_providers) if spf_providers else "No SPF / Unknown",
                "Is_Drifted": is_drift,
                "Drift_Severity": drift_type
            })
            
            processed_count += 1

    # ==========================================
    # 4. 导出数据分析结果
    # ==========================================
    df = pd.DataFrame(drift_results)
    df.to_csv(output_csv, index=False, encoding="utf-8-sig")
    
    drifted_count = len(df[df['Is_Drifted'] == True])
    print("\n" + "="*50)
    print(f"📊 [配置漂移检测报告]")
    print(f"总计评估包含有效配置的域名: {processed_count}")
    print(f"检测到潜在配置漂移的域名: {drifted_count} (占比: {drifted_count/processed_count*100:.2f}%)")
    print(f"✅ 漂移明细 CSV 已导出至: {output_csv}")
    print("="*50)

if __name__ == "__main__":
    # 配置你的文件路径
    RAW_JSONL_FILE = "/home/wzq/project/autov/data/results_test.jsonl" 
    ENTITIES_FILE = "/home/wzq/project/autov/data/entity_map.json" 
    
    # 输出结果文件
    OUTPUT_CSV = "/home/wzq/project/autov/data/config_drift_report.csv"
    
    detect_drift(RAW_JSONL_FILE, ENTITIES_FILE, OUTPUT_CSV)