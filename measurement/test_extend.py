import subprocess
import json
# 实际连接，仅测试extend逻辑是否正确
def test_extend_logic():
    # 1. 模拟最基础的命令列表
    cmd = ["zgrab2", "smtp", "--port=587"]
    
    # 2. 使用 extend 平铺追加 override 参数
    cmd.extend(["--send-ehlo-override", "--send-starttls-override"])
    
    print(f"🚀 拼装后的完整命令列表: {cmd}")
    print(f"💻 实际执行的 Shell 形态: {' '.join(cmd)}\n")
    
    try:
        # 3. 使用 subprocess 执行，并把 smtp.zoho.com 通过标准输入喂给它
        result = subprocess.run(
            cmd,
            input="smtp.zoho.com\n",  # 模拟 echo "smtp.zoho.com" |
            text=True,
            capture_output=True,
            check=True
        )
        
        print("✅ 执行成功！提取 JSON 结果中的 tls 字段判定：")
        
        # 简单解析一下输出，证明拿到了 TLS 数据
        for line in result.stdout.strip().split('\n'):
            if not line.startswith('{'): 
                continue
            data = json.loads(line)
            result_data = data.get("data", {}).get("smtp", {}).get("result", {})
            
            if "tls" in result_data:
                print("🎉 完美！成功触发了 STARTTLS 握手，拿到了 TLS 数据块！")
            else:
                print("⚠️ 糟糕，没有拿到 TLS 数据。")
                
            # 打印完整的 JSON 让你确认
            print(f"\n完整输出: {line}")
            
    except subprocess.CalledProcessError as e:
        print(f"❌ 运行失败，退出码: {e.returncode}")
        print(f"错误输出: {e.stderr}")

if __name__ == "__main__":
    test_extend_logic()