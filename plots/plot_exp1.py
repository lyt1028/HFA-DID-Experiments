import os
import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.font_manager import FontProperties

# 字体文件路径（如有不同可用 fc-list 查找）
FONT_PATH = '/usr/share/fonts/truetype/wqy/wqy-microhei.ttc'
font_zh = FontProperties(fname=FONT_PATH)
def set_chinese_font():
    import matplotlib
    # 优先尝试常见中文字体
    font_candidates = ['WenQuanYi Micro Hei']
    for font in font_candidates:
        try:
            matplotlib.rcParams['font.sans-serif'] = [font]
            plt.figure()
            plt.title('中文测试')
            plt.close()
            print(f'已设置中文字体: {font}')
            break
        except Exception:
            continue
    matplotlib.rcParams['axes.unicode_minus'] = False
set_chinese_font()

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
PLOTS_DIR = os.path.dirname(__file__)

# 自动查找最新的 EXP1a 和 EXP1b 结果文件
def find_latest_result(prefix):
    files = [f for f in os.listdir(RESULTS_DIR) if f.startswith(prefix) and f.endswith('.json')]
    if not files:
        return None
    files.sort(reverse=True)
    return os.path.join(RESULTS_DIR, files[0])

# 绘制 EXP1a 域内验证延迟

def plot_exp1a():
    path = find_latest_result('EXP1a')
    if not path:
        print('未找到 EXP1a 结果文件')
        return
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)['results']
    x = [d['requests'] for d in data]
    y = [d['avg_total_ms'] for d in data]
    tps = [d['tps'] for d in data]
    plt.figure(figsize=(6,4))
    plt.plot(x, y, marker='o', label='平均延迟 (ms)', color='C0')
    plt.plot(x, tps, marker='s', label='TPS', color='C1')
    plt.xlabel('验证请求数', fontproperties=font_zh)
    plt.ylabel('延迟 / TPS', fontproperties=font_zh)
    plt.title('EXP1a 域内验证延迟与TPS', fontproperties=font_zh)
    plt.legend(prop=font_zh)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'exp1a_latency_tps.png'))
    plt.close()

# 绘制 EXP1b 三方案对比

def plot_exp1b():
    path = find_latest_result('EXP1b')
    if not path:
        print('未找到 EXP1b 结果文件')
        return
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)['results']
    x = [d['load'] for d in data]
    hfa = [d['hfa_avg_ms'] for d in data]
    wei = [d['wei_avg_ms'] for d in data]
    can = [d['can_avg_ms'] for d in data]
    plt.figure(figsize=(6,4))
    plt.plot(x, hfa, marker='o', label='HFA-DID', color='C0')
    plt.plot(x, wei, marker='x', label='WeIdentity', color='C1')
    plt.plot(x, can, marker='s', label='CanDID', color='C2')
    plt.xlabel('负载因子', fontproperties=font_zh)
    plt.ylabel('平均验证延迟 (ms)', fontproperties=font_zh)
    plt.title('EXP1b 三方案域内验证对比', fontproperties=font_zh)
    plt.legend(prop=font_zh)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'exp1b_scheme_comparison.png'))
    plt.close()

if __name__ == '__main__':
    plot_exp1a()
    plot_exp1b()
    print('EXP1 图表已生成，见 plots/ 目录。')
