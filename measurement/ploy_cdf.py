import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as plt_sns

# 设置学术绘图风格
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    'font.size': 14,
    'axes.labelsize': 16,
    'axes.titlesize': 18,
    'xtick.labelsize': 14,
    'ytick.labelsize': 14,
    'legend.fontsize': 14,
    'lines.linewidth': 2.5
})

def plot_cdf(df, column, title, xlabel, output_filename, x_max=None):
    plt.figure(figsize=(8, 6))
    
    # 区分 Success 和 Failed
    success_data = df[df['status_tag'] == 'SUCCESS'][column]
    failed_data = df[df['status_tag'] != 'SUCCESS'][column]
    
    # 计算 CDF 的辅助函数
    def get_cdf_data(data):
        sorted_data = np.sort(data)
        yvals = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
        return sorted_data, yvals

    # 获取数据
    x_success, y_success = get_cdf_data(success_data)
    x_failed, y_failed = get_cdf_data(failed_data)
    
    # 绘制 CDF 曲线
    plt.plot(x_success, y_success, marker='o', markersize=4, linestyle='-', color='#2ca02c', label=f'Effective Chains (n={len(success_data)})')
    plt.plot(x_failed, y_failed, marker='x', markersize=4, linestyle='--', color='#d62728', label=f'Attempted/Failed Chains (n={len(failed_data)})')
    
    # 细节修饰
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel('CDF (Fraction of Domains)')
    plt.ylim(0, 1.05)
    
    if x_max:
        plt.xlim(-0.2, x_max)
        
    plt.legend(loc='lower right')
    plt.tight_layout()
    
    # 保存高分辨率图片供论文使用
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"✅ 图表已保存: {output_filename}")
    plt.close()

def main():
    print("📈 正在生成学术级 CDF 对比图...")
    
    # 加载上一步提取的链条数据
    # 请确保路径与你生成的 csv 一致
    input_file = "/home/wzq/project/autov/data/chain_analysis_results.csv" 
    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"❌ 找不到文件 {input_file}，请先运行上一步的提取脚本。")
        return

    # 画图 1：HTTP 总跳转次数对比 (HTTP-level Redirects)
    plot_cdf(
        df=df,
        column='total_redirects',
        title='CDF of Total HTTP Redirects',
        xlabel='Number of HTTP Redirects',
        output_filename='/home/wzq/project/autov/data/cdf_total_redirects.png',
        x_max=12 # 截断 X 轴，展示到最多 12 次跳转
    )
    
    # 画图 2：跨组织边界跳转次数对比 (Cross-Org Hops)
    plot_cdf(
        df=df,
        column='cross_org_hops',
        title='CDF of Cross-Org Hops (Trust Boundaries)',
        xlabel='Number of Cross-Org Hops',
        output_filename='/home/wzq/project/autov/data/cdf_cross_org_hops.png',
        x_max=5 # 跨组织跳数通常较少，X轴展示到 5 即可
    )
    
    print("🎉 所有 CDF 图表生成完毕！可以下载到本地查看。")

if __name__ == "__main__":
    main()