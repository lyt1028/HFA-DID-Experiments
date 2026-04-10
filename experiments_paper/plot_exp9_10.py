#!/usr/bin/env python3
"""
绘图: 实验6 v2 (自适应门限 - 真实BLS测量)
图8(a): 不同门限值下各阶段签名延迟 (堆叠柱状图)
图8(b): 多epoch场景下三种策略的签发延迟与通信开销
"""

import json
import os
import glob
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.ticker import MaxNLocator

# ============================================================
# 字体与样式 (与 plot_all.py 一致)
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'plots')
os.makedirs(OUTPUT_DIR, exist_ok=True)

PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
FONT_PATH = os.path.join(PROJECT_DIR, 'fonts', 'wqy-microhei.ttc')
if not os.path.exists(FONT_PATH):
    FONT_PATH = '/usr/share/fonts/truetype/wqy/wqy-microhei.ttc'

CN_FONT = FontProperties(fname=FONT_PATH, size=11)
CN_FONT_SMALL = FontProperties(fname=FONT_PATH, size=9)
CN_FONT_LABEL = FontProperties(fname=FONT_PATH, size=10)
CN_FONT_TITLE = FontProperties(fname=FONT_PATH, size=12)

plt.rcParams.update({
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'axes.unicode_minus': False,
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'axes.edgecolor': '#333333',
    'axes.linewidth': 0.8,
    'axes.grid': True,
    'grid.linestyle': '--',
    'grid.alpha': 0.5,
    'grid.linewidth': 0.6,
    'lines.linewidth': 1.8,
    'lines.markersize': 6,
    'xtick.direction': 'in',
    'ytick.direction': 'in',
    'xtick.major.size': 4,
    'ytick.major.size': 4,
    'legend.framealpha': 0.9,
    'legend.edgecolor': '#cccccc',
    'legend.fontsize': 9,
})

C_BLUE   = '#1f77b4'
C_ORANGE = '#ff7f0e'
C_GREEN  = '#2ca02c'
C_RED    = '#d62728'
C_PURPLE = '#9467bd'
C_GRAY   = '#7f7f7f'


def load_latest(prefix):
    files = sorted(glob.glob(os.path.join(RESULTS_DIR, f'{prefix}*.json')))
    if not files:
        raise FileNotFoundError(f'No results for {prefix}')
    with open(files[-1], 'r', encoding='utf-8') as f:
        return json.load(f)


def save_fig(fig, name):
    for ext in ['pdf', 'png']:
        path = os.path.join(OUTPUT_DIR, f'{name}.{ext}')
        fig.savefig(path, format=ext, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print(f'  -> {name}.pdf / {name}.png')


def plot_exp9_v2():
    data = load_latest('EXP9v2_adaptive_threshold')
    part_a = data['part_a']
    part_b = data['part_b']

    fig, axes = plt.subplots(1, 3, figsize=(14, 4.2))

    # =========================================
    # (a) 不同门限值下的签名延迟分解 (堆叠柱状图)
    # =========================================
    ax = axes[0]
    t_values = [r['t'] for r in part_a]
    partial = [r['avg_partial_sign_ms'] for r in part_a]
    aggregate = [r['avg_aggregate_ms'] for r in part_a]
    verify = [r['avg_verify_ms'] for r in part_a]

    x = np.arange(len(t_values))
    width = 0.6

    bars1 = ax.bar(x, partial, width, color=C_BLUE, label='\u90e8\u5206\u7b7e\u540d')
    bars2 = ax.bar(x, aggregate, width, bottom=partial, color=C_ORANGE,
                   label='\u4efd\u989d\u805a\u5408')
    bottom2 = [p + a for p, a in zip(partial, aggregate)]
    bars3 = ax.bar(x, verify, width, bottom=bottom2, color=C_GREEN,
                   label='\u7b7e\u540d\u9a8c\u8bc1')

    ax.set_xticks(x)
    ax.set_xticklabels([str(t) for t in t_values])
    ax.set_xlabel('\u95e8\u9650\u503c $t$', fontproperties=CN_FONT_LABEL)
    ax.set_ylabel('\u7b7e\u53d1\u5ef6\u8fdf (ms)', fontproperties=CN_FONT_LABEL)
    ax.set_title('(a) \u4e0d\u540c\u95e8\u9650\u4e0b\u7684\u7b7e\u540d\u5ef6\u8fdf\u5206\u89e3',
                 fontproperties=CN_FONT_TITLE)
    ax.legend(prop=CN_FONT_SMALL, loc='upper left')

    # 在柱顶标注总延迟
    for i, (p, a, v) in enumerate(zip(partial, aggregate, verify)):
        total = p + a + v
        ax.text(i, total + 20, f'{total:.0f}',
                ha='center', va='bottom', fontsize=8)

    # =========================================
    # (b) 多epoch签发延迟对比 + 通信开销
    # =========================================
    ax = axes[1]
    strategies = ['fixed_high', 'fixed_low', 'adaptive']
    labels = {
        'fixed_high': '\u56fa\u5b9a\u9ad8\u95e8\u9650 ($t=11$)',
        'fixed_low':  '\u56fa\u5b9a\u4f4e\u95e8\u9650 ($t=7$)',
        'adaptive':   '\u81ea\u9002\u5e94\u95e8\u9650 $t(e)$',
    }
    colors = {'fixed_high': C_BLUE, 'fixed_low': C_ORANGE, 'adaptive': C_GREEN}
    markers = {'fixed_high': 's', 'fixed_low': '^', 'adaptive': 'o'}

    for s in strategies:
        epochs_data = part_b[s]
        ep_ok, lat_ok, ep_fail = [], [], []
        for e in epochs_data:
            if e['avg_sign_latency_ms'] > 0:
                ep_ok.append(e['epoch'])
                lat_ok.append(e['avg_sign_latency_ms'])
            else:
                ep_fail.append(e['epoch'])
        ax.plot(ep_ok, lat_ok, marker=markers[s], color=colors[s],
                label=labels[s], linewidth=1.8, markersize=5)
        if ep_fail:
            ax.scatter(ep_fail, [1500]*len(ep_fail), marker='x',
                       color=colors[s], s=80, linewidths=2, zorder=5)

    # 威胁背景
    threat = [e['threat_level'] for e in part_b['adaptive']]
    ep = [e['epoch'] for e in part_b['adaptive']]
    ax2 = ax.twinx()
    ax2.fill_between(ep, [t * 100 for t in threat],
                     alpha=0.12, color=C_RED, step='mid')
    ax2.set_ylabel('\u5a01\u80c1\u7b49\u7ea7 (%)',
                   fontproperties=CN_FONT_SMALL, color=C_RED)
    ax2.set_ylim(0, 60)
    ax2.tick_params(axis='y', labelcolor=C_RED, labelsize=8)

    ax.set_xlabel('\u8f6e\u6b21 (epoch)', fontproperties=CN_FONT_LABEL)
    ax.set_ylabel('\u7b7e\u53d1\u5ef6\u8fdf (ms)', fontproperties=CN_FONT_LABEL)
    ax.set_title('(b) \u52a8\u6001\u573a\u666f\u4e0b\u7684\u7b7e\u53d1\u5ef6\u8fdf',
                 fontproperties=CN_FONT_TITLE)
    ax.legend(prop=CN_FONT_SMALL, loc='upper left')
    ax.set_xticks(range(1, 16, 2))

    # =========================================
    # (c) 安全裕度对比
    # =========================================
    ax = axes[2]
    for s in strategies:
        epochs_data = part_b[s]
        ep = [e['epoch'] for e in epochs_data]
        margins = [e['safety_margin'] for e in epochs_data]
        ax.plot(ep, margins, marker=markers[s], color=colors[s],
                label=labels[s], linewidth=1.8, markersize=5)

    ax.axhline(y=0, color=C_RED, linestyle='--', linewidth=1.2, alpha=0.7)
    ax.text(14.5, 0.5, '\u4e0d\u5b89\u5168', color=C_RED,
            fontproperties=CN_FONT_SMALL)

    ax.set_xlabel('\u8f6e\u6b21 (epoch)', fontproperties=CN_FONT_LABEL)
    ax.set_ylabel('\u5b89\u5168\u88d5\u5ea6 ($t(e) - f_{active}$)',
                  fontproperties=CN_FONT_LABEL)
    ax.set_title('(c) \u5b89\u5168\u88d5\u5ea6',
                 fontproperties=CN_FONT_TITLE)
    ax.legend(prop=CN_FONT_SMALL, loc='lower right')
    ax.set_xticks(range(1, 16, 2))

    plt.tight_layout()
    save_fig(fig, 'exp9_adaptive_threshold')


if __name__ == '__main__':
    print('\u7ed8\u5236\u56fe\u8868...')
    plot_exp9_v2()
    print('\u5b8c\u6210.')
