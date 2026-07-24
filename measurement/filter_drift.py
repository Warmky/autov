import pandas as pd
# 配置漂移筛选
# 输入和输出文件路径，筛选可能存在配置漂移的域名
input_file = "/home/wzq/project/autov/data/config_drift_report.csv"
output_file = "/home/wzq/project/autov/data/drifted_only_report.csv"

# 读取完整结果
df = pd.read_csv(input_file)

# 筛选 Is_Drifted 为 True（或者是字符串 "True"）的行
drifted_df = df[df['Is_Drifted'] == True]

# 如果读取出来的是字符串，可以用这行代替上面那行：
# drifted_df = df[df['Is_Drifted'].astype(str).str.lower() == 'true']

# 将筛选后的结果保存到新文件
drifted_df.to_csv(output_file, index=False, encoding="utf-8-sig")

print(f"✅ 筛选完成！在 {len(df)} 条记录中，共找到 {len(drifted_df)} 条漂移记录。")
print(f"📁 漂移明细已保存至: {output_file}")