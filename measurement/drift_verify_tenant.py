# import imaplib
# import socket

# def check_tenant_status(server, target_domain, real_domain):
#     port = 993
#     print(f"\n🚀 开始对 {server} 进行僵尸租户探测...")
#     print("-" * 50)
    
#     # 构造三个测试账号：
#     dummy_domain = "this-is-a-fake-domain-for-research-999.com"
    
#     accounts_to_test = [
#         ("【1】阴性基线测试 (绝对不存在的租户)", f"admin@{dummy_domain}"),
#         ("【2】阳性对照测试 (确定真实的ZOHO租户)", f"admin@{real_domain}"),
#         ("【3】目标漏洞探测 (我们怀疑存活的僵尸租户)", f"admin@{target_domain}")
#     ]
    
#     for desc, email in accounts_to_test:
#         print(f"\n▶ 阶段: {desc}")
#         print(f"  [>] 尝试使用账号: {email}")
        
#         try:
#             # 连接到 IMAP 服务器
#             mail = imaplib.IMAP4_SSL(server, port, timeout=10)
            
#             # 使用一个绝对错误的密码进行尝试
#             fake_password = "WrongPassword_SecurityResearch_123!"
#             mail.login(email, fake_password)
            
#             print("  [!] 警告: 居然登录成功了! (这说明对方没有设密码或存在弱口令)")
#             mail.logout()
            
#         except imaplib.IMAP4.error as e:
#             # 捕获并打印服务器返回的原始错误信息
#             error_msg = str(e)
#             print(f"  [<] 服务器拒绝登录。原始响应:\n      \033[91m{error_msg}\033[0m")
            
#         except socket.timeout:
#             print("  [!] 连接超时。")
#         except Exception as e:
#             print(f"  [!] 其他错误: {e}")

# if __name__ == "__main__":
#     # 我们从配置中发现的旧服务器
#     target_server = "imap.zoho.eu"
    
#     # 我们要验证的漂移目标
#     target_domain = "erome.com"
    
#     # 我们确定的真实在用 ZOHO 的域名 (阳性对照)
#     real_zoho_domain = "doi.org"
    
#     check_tenant_status(target_server, target_domain, real_zoho_domain)

import smtplib

def check_tenant_via_smtp(target_domain):
    # ZOHO 欧洲区的收信服务器 (MX)
    # 我们可以直接连它的 25 端口或 587 端口
    smtp_server = "mx.zoho.eu"
    
    # 伪造的发件人
    fake_sender = "researcher@test-security-lab.com"
    target_email = f"admin@{target_domain}"
    
    print(f"\n🚀 开始通过 SMTP 路由测试探测: {target_domain}")
    print(f"连接服务器: {smtp_server}:25 ...")
    
    try:
        # 连接 SMTP 服务器
        server = smtplib.SMTP(smtp_server, 25, timeout=10)
        server.set_debuglevel(0) # 如果想看详细交互，可以改为 1
        
        # 1. 握手
        server.helo("test-security-lab.com")
        
        # 2. 告诉服务器我是谁 (MAIL FROM)
        server.mail(fake_sender)
        
        # 3. 关键一步：告诉服务器我想发给谁 (RCPT TO)
        # 这里会暴露服务器到底认不认识这个域名
        code, message = server.rcpt(target_email)
        msg_str = message.decode('utf-8')
        
        print(f"  [<] 服务器响应码: {code}")
        print(f"  [<] 服务器响应信息: {msg_str}")
        
        if code == 250:
            print("  [🚨 严重警告] 服务器返回 250 OK。它接收了这封信！")
            print("  [!] 说明 ZOHO 内部数据库依然认为这个域名是它的合法租户 (僵尸租户存活)！")
        elif code in [550, 553, 554]:
            if "Relay access denied" in msg_str or "Relaying disallowed" in msg_str:
                print("  [✅ 安全] 服务器拒绝代发 (Relay Denied)。")
                print("  [!] 说明 ZOHO 已经不认识这个域名了，租户已注销。")
            else:
                print("  [?] 被拒绝，但原因不是 Relay Denied。需人工判断。")
        else:
            print("  [?] 收到其他状态码。")
            
        server.quit()
        
    except Exception as e:
        print(f"  [!] SMTP 交互出错: {e}")

if __name__ == "__main__":
    domains_to_test = [
        ("this-is-a-fake-domain-999.com", "阴性对照(不存在)"),
        ("doi.org", "阳性对照(真实ZOHO租户)"),
        ("erome.com", "目标测试(疑似僵尸租户)")
    ]
    
    for domain, desc in domains_to_test:
        print("-" * 50)
        print(f"▶ 测试阶段: {desc}")
        check_tenant_via_smtp(domain)