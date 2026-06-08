import json
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import re

'''
配置信息04
从ecosystem_details.csv和host_tier_mapping.json，回到一开始的配置信息jsonl，分析不同层级（Giant vs Long-tail）的配置结构差异，生成 schema_discovery_report.json
'''

def discover_schema_differences(raw_jsonl_file, mapping_file, output_report_json):
    print("🧬 开始进行 XML 基因图谱分析 (兼容 Go 语言结构版)...")
    
    # 1. 加载主机的阶层字典
    with open(mapping_file, "r", encoding="utf-8") as f:
        tier_mapping = json.load(f)

    # 存储结构：stats[Mechanism][Tier] = {"tags": Counter(), "values": {path: Counter()}}
    stats = defaultdict(lambda: defaultdict(lambda: {
        "tags": Counter(),
        "values": defaultdict(Counter),
        "total_configs": 0
    }))

    # 🛠️ 终极清洗：干掉所有命名空间和特殊前缀，让 Python 的解析像 Go 的 etree 一样宽容
    def clean_xml(xml_str):
        # 去掉 xmlns="..."
        xml_str = re.sub(r'\sxmlns(:\w+)?="[^"]*"', '', xml_str)
        # 去掉标签上的前缀，比如 <ns1:Server> 变成 <Server>
        xml_str = re.sub(r'</?\w+:', lambda m: '<' if m.group(0).startswith('</') else '<', xml_str)
        return xml_str

    # 递归遍历 XML 树 (带顺位与优先级追踪版)
    def traverse_tree(node, current_path, tags_counter, values_counter):
        # 记录本节点的属性
        for attr_name, attr_val in node.attrib.items():
            attr_path = f"{current_path}[@{attr_name}]" if current_path else f"[@{attr_name}]"
            tags_counter[attr_path] += 1
            if attr_val:
                values_counter[attr_path][attr_val.lower()] += 1
        
        # 记录本节点的值
        text_val = node.text.strip() if node.text else ""
        if text_val and len(node) == 0:
            values_counter[current_path][text_val.lower()] += 1
            
        # 🌟 核心升级：追踪子节点的出现顺序 (用于分析优先级/降级机制)
        child_tag_counts = Counter()
        
        for child in node:
            child_tag = child.tag
            child_tag_counts[child_tag] += 1
            index = child_tag_counts[child_tag] # 它是第几个出现的同名兄弟？
            
            # 构建带顺位的路径，比如: incomingServer/authentication[1]
            # 为了让只有1个的标签不显得太丑，我们可以：如果同名标签只有1个就不加，但因为是流式遍历无法预知总数，
            # 所以统一加上 [1], [2]... 这种标准的 XPath 格式，反而更严谨！
            child_path = f"{current_path}/{child_tag}[{index}]" if current_path else f"{child_tag}[{index}]"
            
            # 记录标签出现
            tags_counter[child_path] += 1
            
            # 递归
            traverse_tree(child, child_path, tags_counter, values_counter)

    # 2. 扫描数据
    processed_count = 0
    with open(raw_jsonl_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except:
                continue
                
            # 兼容各种大小写的 JSON 键名
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
                    traverse_tree(root, "", stats["autodiscover"][tier]["tags"], stats["autodiscover"][tier]["values"])
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
                    traverse_tree(root, "", stats["autoconfig"][tier]["tags"], stats["autoconfig"][tier]["values"])
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
                "Tag_Frequencies": {},
                "Common_Values": {}
            }
            
            for path, count in data["tags"].most_common():
                coverage = round((count / total) * 100, 2)
                report[mech][tier]["Tag_Frequencies"][path] = f"{count} occurrences ({coverage}%)"
                
            for path, val_counter in data["values"].items():
                # 如果这个字段的唯一值超过 50 个，大概率是用户名/域名等变量，过滤掉
                if len(val_counter) > 50:
                    report[mech][tier]["Common_Values"][path] = "[Too many unique values, dynamic data]"
                else:
                    report[mech][tier]["Common_Values"][path] = {val: count for val, count in val_counter.most_common(5)}

    with open(output_report_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
        
    print(f"✅ 深度嗅探成功！发现报告已导出至: {output_report_json}")

if __name__ == "__main__":
    # ⚠️ 极其重要：确保这里输入的是包含原始 "Config" 字段的 jsonl 文件
    # 例如你在 Go 代码中提到的 init.jsonl，或者 results_test.jsonl
    RAW_JSONL_FILE = "/home/wzq/project/autov/data/results_test.jsonl" 
    
    MAPPING_FILE = "/home/wzq/project/autov/data/host_tier_mapping.json"
    OUTPUT_REPORT = "/home/wzq/project/autov/data/schema_discovery_report_2.json"
    
    discover_schema_differences(RAW_JSONL_FILE, MAPPING_FILE, OUTPUT_REPORT)