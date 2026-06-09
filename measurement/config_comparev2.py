import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import re

'''
配置信息05 - 协议解耦版 (Protocol-Decoupled Version)
从ecosystem_details.csv和host_tier_mapping.json，回到一开始的配置信息jsonl，
针对 TCP-based 和 URL-based 协议进行分流统计，生成 schema_discovery_report_v2.json
'''

def discover_schema_differences(raw_jsonl_file, mapping_file, output_report_json):
    print("🧬 开始进行 XML 基因图谱分析 (TCP/URL 协议解耦版)...")
    
    # 1. 加载主机的阶层字典
    with open(mapping_file, "r", encoding="utf-8") as f:
        tier_mapping = json.load(f)

    # 存储结构：额外增加 auth_by_class 用于宏观统计
    stats = defaultdict(lambda: defaultdict(lambda: {
        "tags": Counter(),
        "values": defaultdict(Counter),
        "auth_by_class": {
            "TCP-based": Counter(),
            "URL-based": Counter(),
            "Other": Counter()
        },
        "total_configs": 0
    }))

    # 定义协议阵营 (基于 RFC 草案)
    TCP_PROTOCOLS = {"imap", "pop3", "pop", "smtp", "exchange"} # Exchange 属于传统的 TCP 端口复用包装
    URL_PROTOCOLS = {"ews", "owa", "graph", "jmap", "caldav", "carddav", "webdav"}

    def clean_xml(xml_str):
        xml_str = re.sub(r'\sxmlns(:\w+)?="[^"]*"', '', xml_str)
        xml_str = re.sub(r'</?\w+:', lambda m: '<' if m.group(0).startswith('</') else '<', xml_str)
        return xml_str

    # 递归遍历 XML 树
    def traverse_tree(node, current_path, tier_data, parent_type=None):
        # 1. 记录本节点的属性
        for attr_name, attr_val in node.attrib.items():
            attr_path = f"{current_path}[@{attr_name}]" if current_path else f"[@{attr_name}]"
            tier_data["tags"][attr_path] += 1
            if attr_val:
                tier_data["values"][attr_path][attr_val.lower()] += 1
        
        # 2. 记录本节点的值
        text_val = node.text.strip() if node.text else ""
        if text_val and len(node) == 0:
            tier_data["values"][current_path][text_val.lower()] += 1
            
            # 🌟 核心升级 1：自动将认证方式按协议阵营 (TCP/URL) 进行分流汇总
            if node.tag == "authentication":
                auth_val = text_val.lower()
                if parent_type in TCP_PROTOCOLS:
                    tier_data["auth_by_class"]["TCP-based"][auth_val] += 1
                elif parent_type in URL_PROTOCOLS:
                    tier_data["auth_by_class"]["URL-based"][auth_val] += 1
                else:
                    tier_data["auth_by_class"]["Other"][auth_val] += 1
                
        # 3. 处理子节点
        child_tag_counts = Counter()
        
        for child in node:
            child_base_tag = child.tag
            child_type = child.attrib.get("type", "").lower()
            
            # 🌟 核心升级 2：将 type 属性直接注入路径！
            # 例如将 incomingServer 转换为 incomingServer[@type=imap]
            if child_type:
                child_tag = f"{child_base_tag}[@type={child_type}]"
            else:
                child_tag = child_base_tag
                
            child_tag_counts[child_tag] += 1
            index = child_tag_counts[child_tag] 
            
            child_path = f"{current_path}/{child_tag}[{index}]" if current_path else f"{child_tag}[{index}]"
            
            tier_data["tags"][child_path] += 1
            
            # 将当前的协议 type 传递给下一层（作为 parent_type）
            next_parent_type = child_type if child_type else parent_type
            traverse_tree(child, child_path, tier_data, next_parent_type)

    # 2. 扫描数据
    processed_count = 0
    with open(raw_jsonl_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except:
                continue
                
            auto_disc_list = obj.get("autodiscover") or obj.get("Autodiscover") or []
            auto_conf_list = obj.get("autoconfig") or obj.get("Autoconfig") or []
            
            # --- 处理 Autodiscover ---
            for entry in auto_disc_list:
                raw_xml = entry.get("Config") or entry.get("config") or ""
                if not raw_xml or "Bad" in raw_xml or "Error" in raw_xml:
                    continue
                try:
                    root = ET.fromstring(clean_xml(raw_xml))
                except:
                    continue
                
                host = ""
                for server_node in root.findall(".//Protocol/Server"):
                    if server_node.text:
                        host = server_node.text.lower().strip()
                        break
                
                if host:
                    tier = tier_mapping.get(host, {}).get("Tier", "Long-tail")
                    stats["autodiscover"][tier]["total_configs"] += 1
                    traverse_tree(root, "", stats["autodiscover"][tier])
                    processed_count += 1
                    break 

            # --- 处理 Autoconfig ---
            for entry in auto_conf_list:
                raw_xml = entry.get("Config") or entry.get("config") or ""
                if not raw_xml or "Bad" in raw_xml or "Error" in raw_xml:
                    continue
                try:
                    root = ET.fromstring(clean_xml(raw_xml))
                except:
                    continue
                
                host = ""
                for host_node in root.findall(".//incomingServer/hostname") + root.findall(".//outgoingServer/hostname"):
                    if host_node.text:
                        host = host_node.text.lower().strip()
                        break
                        
                if host:
                    tier = tier_mapping.get(host, {}).get("Tier", "Long-tail")
                    stats["autoconfig"][tier]["total_configs"] += 1
                    traverse_tree(root, "", stats["autoconfig"][tier])
                    processed_count += 1
                    break

    # 3. 整理报告
    print(f"📊 扫描完毕！成功解析了 {processed_count} 个有效 XML 配置。正在生成报告...")
    report = {}
    
    for mech, tier_data in stats.items():
        report[mech] = {}
        for tier, data in tier_data.items():
            total = data["total_configs"]
            if total == 0:
                continue
                
            report[mech][tier] = {
                "Total_Configurations_Parsed": total,
                # 🌟 输出专门针对协议阵营的认证机制横向对比
                "Authentication_By_Protocol_Class": {
                    "TCP-based (IMAP/POP3/SMTP)": dict(data["auth_by_class"]["TCP-based"].most_common()),
                    "URL-based (EWS/OWA/Graph/CalDAV)": dict(data["auth_by_class"]["URL-based"].most_common()),
                    "Other_or_Unknown": dict(data["auth_by_class"]["Other"].most_common())
                },
                "Tag_Frequencies": {},
                "Common_Values": {}
            }
            
            # 排序：优先按路径的逻辑层级展示
            for path, count in data["tags"].most_common():
                coverage = round((count / total) * 100, 2)
                report[mech][tier]["Tag_Frequencies"][path] = f"{count} occurrences ({coverage}%)"
                
            for path, val_counter in data["values"].items():
                if len(val_counter) > 50:
                    report[mech][tier]["Common_Values"][path] = "[Too many unique values, dynamic data]"
                else:
                    report[mech][tier]["Common_Values"][path] = {val: count for val, count in val_counter.most_common(5)}

    with open(output_report_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
        
    print(f"✅ 协议解耦分析成功！报告已导出至: {output_report_json}")

if __name__ == "__main__":
    RAW_JSONL_FILE = "/home/wzq/project/autov/data/results_test.jsonl" 
    MAPPING_FILE = "/home/wzq/project/autov/data/host_tier_mapping.json"
    OUTPUT_REPORT = "/home/wzq/project/autov/data/schema_discovery_report_v3.json"   #6.8
    
    discover_schema_differences(RAW_JSONL_FILE, MAPPING_FILE, OUTPUT_REPORT)