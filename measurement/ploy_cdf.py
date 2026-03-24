import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# =====================================================================
# 学术绘图风格设置 (达到 IEEE/ACM 顶会出版标准)
# =====================================================================
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    'font.size': 14,
    'axes.labelsize': 16,
    'axes.titlesize': 18,
    'xtick.labelsize': 14,
    'ytick.labelsize': 14,
    'legend.fontsize': 14,
    'lines.linewidth': 2.5,
    'figure.dpi': 300 # 高分辨率输出
})

def get_cdf_data(data):
    """计算用于画 CDF 图的 X 和 Y 坐标"""
    sorted_data = np.sort(data)
    # 计算累积概率 (CDF)
    yvals = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
    return sorted_data, yvals

def draw_cdf(df, metric_column, title, xlabel, output_path, x_max=None):
    plt.figure(figsize=(8, 6))
    
    # 核心逻辑：拆分成功与失败的数据集
    success_data = df[df['status_tag'] == 'SUCCESS'][metric_column]
    failed_data = df[df['status_tag'] != 'SUCCESS'][metric_column]
    
    # 获取 CDF 坐标
    x_succ, y_succ = get_cdf_data(success_data)
    x_fail, y_fail = get_cdf_data(failed_data)
    
    # 绘制两条对比曲线
    # 成功的画绿色实线，代表“健康生态”
    plt.plot(x_succ, y_succ, label=f'Effective Configs (n={len(success_data)})', 
             color='#2ca02c', linestyle='-')
    # 失败的画红色虚线，代表“病态/迷宫生态”
    plt.plot(x_fail, y_fail, label=f'Failed Attempts (n={len(failed_data)})', 
             color='#d62728', linestyle='--')
    
    # 图表细节修饰
    plt.title(title, pad=15)
    plt.xlabel(xlabel)
    plt.ylabel('CDF (Fraction of Requests)')
    
    # Y轴固定在 0 到 1.05，X轴稍微向左偏移一点以看清 0 跳的点
    plt.ylim(0, 1.05)
    if x_max:
        plt.xlim(-0.2, x_max)
        
    plt.legend(loc='lower right', frameon=True, shadow=True)
    plt.tight_layout()
    
    plt.savefig(output_path)
    print(f"📊 图表已生成: {output_path}")
    plt.close()

def main():
    print("📈 开始生成学术级 CDF 对比图...")
    input_csv = "/home/wzq/project/autov/data/chain_analysis_results.csv"
    
    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"❌ 找不到 {input_csv}，请先确认上一步数据已生成。")
        return

    # 图 1：总 HTTP 跳转次数 (网络层折腾程度)
    # 因为有长尾效应，X轴截断在 10 左右即可看清全貌
    draw_cdf(
        df, 
        metric_column='total_redirects', 
        title='CDF of Total HTTP Redirects', 
        xlabel='Number of HTTP Redirects', 
        output_path='/home/wzq/project/autov/data/cdf_total_redirects.png',
        x_max=10
    )

    # 图 2：跨实体组织跳数 (信任边界转移程度)
    draw_cdf(
        df, 
        metric_column='cross_org_hops', 
        title='CDF of Cross-Org Hops (Trust Boundaries)', 
        xlabel='Number of Cross-Org Hops', 
        output_path='/home/wzq/project/autov/data/cdf_cross_org_hops.png',
        x_max=5
    )
    
    # 图 3：独立外部商业实体数量 (隐私泄露广度)
    draw_cdf(
        df, 
        metric_column='external_entity_count', 
        title='CDF of Unique Third-Party Entities', 
        xlabel='Number of External Third-Parties', 
        output_path='/home/wzq/project/autov/data/cdf_external_entities.png',
        x_max=5
    )
    
    print("\n🎉 所有 CDF 图表生成完毕！请将 /data 目录下的三张 png 图片下载到本地查看。")

if __name__ == "__main__":
    main()