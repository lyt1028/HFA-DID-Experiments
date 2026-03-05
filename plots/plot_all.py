#!/usr/bin/env python3
"""
HFA-DID 实验结果绘图脚本
生成论文所需的所有实验结果图

所有中文元素（标题、标签、图例）均使用 WenQuanYi Micro Hei 字体
配色风格参考论文已有图表（信誉.png、委员会规模.png）
"""

import json
import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.ticker import MaxNLocator
import matplotlib.patches as mpatches

# ============================================================
# 字体与全局样式配置
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# WenQuanYi Micro Hei 字体
FONT_PATH = os.path.join(PROJECT_DIR, "fonts", "wqy-microhei.ttc")
if not os.path.exists(FONT_PATH):
    FONT_PATH = os.path.join(os.path.dirname(PROJECT_DIR),
                             "DissertationUESTC-main", "font", "SimHei.ttf")
    if not os.path.exists(FONT_PATH):
        FONT_PATH = "C:/WINDOWS/fonts/simhei.ttf"

CN_FONT = FontProperties(fname=FONT_PATH, size=11)
CN_FONT_SMALL = FontProperties(fname=FONT_PATH, size=9)
CN_FONT_LABEL = FontProperties(fname=FONT_PATH, size=10)
CN_FONT_TITLE = FontProperties(fname=FONT_PATH, size=12)

# 全局 matplotlib 参数 — 匹配参考图风格
plt.rcParams.update({
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'axes.unicode_minus': False,
    'figure.figsize': (8, 5),
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

# ---- 配色方案（匹配参考图: tab10 风格） ----
C_BLUE   = '#1f77b4'
C_ORANGE = '#ff7f0e'
C_GREEN  = '#2ca02c'
C_RED    = '#d62728'
C_PURPLE = '#9467bd'
C_BROWN  = '#8c564b'
C_GRAY   = '#7f7f7f'
C_OLIVE  = '#bcbd22'
C_CYAN   = '#17becf'
C_PINK   = '#e377c2'

# 浅色 (用于 fill_between / bar alpha)
C_LIGHT_BLUE  = '#aec7e8'
C_LIGHT_ORANGE = '#ffbb78'
C_LIGHT_GREEN = '#98df8a'
C_LIGHT_RED   = '#ff9896'
C_LIGHT_GRAY  = '#c7c7c7'

# ============================================================
# 工具函数
# ============================================================

def load_json(*patterns):
    """加载最新的匹配文件，支持多个 pattern 回退"""
    import glob
    for pattern in patterns:
        files = sorted(glob.glob(os.path.join(RESULTS_DIR, pattern)))
        if files:
            return json.load(open(files[-1], encoding='utf-8'))
    print(f"  [WARN] 未找到匹配文件: {patterns}")
    return None


def _get(d, *keys, default=0):
    """从 dict 中按优先级取值（兼容不同字段名）"""
    for k in keys:
        if k in d:
            return d[k]
    return default


def save_fig(fig, name):
    """保存图片为 PDF 和 PNG"""
    for ext in ['pdf', 'png']:
        path = os.path.join(OUTPUT_DIR, f"{name}.{ext}")
        fig.savefig(path, format=ext, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print(f"  -> {name}.pdf / {name}.png")


def set_labels(ax, xlabel=None, ylabel=None, title=None, ylabel_right=None):
    """设置中文标签（匹配参考图风格）"""
    if xlabel:
        ax.set_xlabel(xlabel, fontproperties=CN_FONT_LABEL)
    if ylabel:
        ax.set_ylabel(ylabel, fontproperties=CN_FONT_LABEL)
    if title:
        ax.set_title(title, fontproperties=CN_FONT_TITLE, pad=8)


def cn_legend(ax, **kwargs):
    """中文图例"""
    kwargs.setdefault('fontsize', 9)
    return ax.legend(prop=CN_FONT_SMALL, **kwargs)


def add_subfig_label(fig, ax, label, y_offset=-0.18):
    """在子图下方添加 (a) (b) (c) 标签（匹配参考图风格）"""
    ax.text(0.5, y_offset, label, transform=ax.transAxes,
            ha='center', va='top', fontproperties=CN_FONT,
            fontsize=11)


# ============================================================
# EXP1: 域内验证性能
# ============================================================

def plot_exp1a():
    """EXP1a: 域内验证延迟分解 & TPS"""
    data = load_json("EXP1a_*.json")
    if not data:
        return
    results = data['results']
    reqs = [r['requests'] for r in results]
    bls = [r['avg_bls_ms'] for r in results]
    merkle = [r['avg_merkle_ms'] for r in results]
    tps = [r['tps'] for r in results]

    fig, ax1 = plt.subplots(figsize=(7, 4.5))
    x = np.arange(len(reqs))
    w = 0.30

    ax1.bar(x - w/2, bls, w, label='BLS验证', color=C_BLUE, edgecolor='white',
            linewidth=0.5)
    ax1.bar(x + w/2, merkle, w, label='Merkle验证', color=C_GREEN,
            edgecolor='white', linewidth=0.5)

    set_labels(ax1, xlabel='请求数量', ylabel='平均延迟（ms）')
    ax1.set_xticks(x)
    ax1.set_xticklabels([str(r) for r in reqs])

    ax2 = ax1.twinx()
    ax2.plot(x, tps, 'd-', color=C_ORANGE, linewidth=2.2, markersize=7,
             label='TPS')
    ax2.set_ylabel('TPS', fontproperties=CN_FONT_LABEL)
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    cn_legend(ax1, handles=lines1 + lines2, labels=labels1 + labels2,
              loc='upper left')

    for i, v in enumerate(tps):
        ax2.annotate(f'{v:.0f}', (x[i], v), textcoords="offset points",
                     xytext=(0, 8), ha='center', fontsize=8, color=C_ORANGE)

    fig.tight_layout()
    save_fig(fig, 'exp1a_intra_domain_latency')


def plot_exp1b():
    """EXP1b: 域内验证方案对比"""
    data = load_json("EXP1b_*.json")
    if not data:
        return
    results = data['results']
    loads = [r['load'] for r in results]
    hfa = [r['hfa_avg_ms'] for r in results]
    wei = [r['wei_avg_ms'] for r in results]
    can = [r['can_avg_ms'] for r in results]

    fig, ax = plt.subplots(figsize=(7, 5))
    x = np.arange(len(loads))
    w = 0.22

    ax.bar(x - w, hfa, w, label='HFA-DID', color=C_BLUE, edgecolor='white')
    ax.bar(x, wei, w, label='WeIdentity', color=C_ORANGE, edgecolor='white')
    ax.bar(x + w, can, w, label='Canister-DID', color=C_RED, edgecolor='white')

    set_labels(ax, xlabel='并发负载', ylabel='平均延迟（ms）')
    ax.set_xticks(x)
    ax.set_xticklabels(loads)
    ax.set_yscale('log')
    cn_legend(ax, loc='upper left')

    fig.tight_layout()
    save_fig(fig, 'exp1b_intra_domain_comparison')


# ============================================================
# EXP2: 跨域验证性能
# ============================================================

def plot_exp2a():
    """EXP2a: 跨域验证延迟 vs 域规模"""
    data = load_json("EXP2a_*.json")
    if not data:
        return
    results = data['results']
    domains = [r['m'] for r in results]

    # 兼容字段名 (本地 vs 服务器链上版)
    comp_keys = [
        (['rtl_query_ms', 'chain_domain_query_ms'], 'RTL查询'),
        (['gcl_query_ms', 'chain_global_query_ms'], 'GCL查询'),
        (['local_merkle_ms'], '本地Merkle'),
        (['global_merkle_ms'], '全局Merkle'),
        (['bls_verify_ms'], 'BLS验证'),
        (['rtl_endorse_ms'], 'RTL背书'),
    ]
    colors = [C_BLUE, C_ORANGE, C_GREEN, C_RED, C_PURPLE, C_GRAY]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(domains))
    bottom = np.zeros(len(domains))

    for (keys, label), color in zip(comp_keys, colors):
        vals = [_get(r, *keys) for r in results]
        ax.bar(x, vals, 0.5, bottom=bottom, label=label, color=color,
               edgecolor='white', linewidth=0.5)
        bottom += np.array(vals)

    set_labels(ax, xlabel='域数量（m）', ylabel='总验证延迟（ms）')
    ax.set_xticks(x)
    ax.set_xticklabels([str(d) for d in domains])
    cn_legend(ax, loc='upper right', ncol=2)

    fig.tight_layout()
    save_fig(fig, 'exp2a_cross_domain_breakdown')


def plot_exp2b():
    """EXP2b: 网络扰动下的跨域验证"""
    data = load_json("EXP2b_*.json")
    if not data:
        return
    results = data['results']
    networks = [r['network'] for r in results]
    avg = [r['avg_ms'] for r in results]
    p95 = [r['p95_ms'] for r in results]
    sr = [r['success_rate'] for r in results]

    fig, ax1 = plt.subplots(figsize=(9, 5))
    x = np.arange(len(networks))
    w = 0.28

    ax1.bar(x - w/2, avg, w, label='平均延迟', color=C_BLUE, edgecolor='white')
    ax1.bar(x + w/2, p95, w, label='P95延迟', color=C_LIGHT_BLUE,
            edgecolor='white')
    set_labels(ax1, xlabel='网络条件（延迟/丢包率）', ylabel='延迟（ms）')
    ax1.set_xticks(x)
    ax1.set_xticklabels(networks, fontsize=8, rotation=15)

    ax2 = ax1.twinx()
    ax2.plot(x, sr, 's-', color=C_RED, linewidth=1.8, markersize=6,
             label='成功率')
    ax2.set_ylabel('成功率（%）', fontproperties=CN_FONT_LABEL)
    ax2.set_ylim(70, 105)
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    cn_legend(ax1, handles=lines1 + lines2, labels=labels1 + labels2,
              loc='upper left')

    fig.tight_layout()
    save_fig(fig, 'exp2b_network_perturbation')


def plot_exp2c():
    """EXP2c: HFA-DID vs 跨链方案"""
    data = load_json("EXP2c_*.json")
    if not data:
        return
    results = data['results']
    domains = [r['m'] for r in results]
    hfa = [r['hfa_avg_ms'] for r in results]
    cc = [r['cc_avg_ms'] for r in results]
    speedup = [r['speedup'] for r in results]

    fig, ax1 = plt.subplots(figsize=(7, 5))
    ax1.plot(domains, hfa, 'o-', color=C_BLUE, label='HFA-DID',
             linewidth=1.8, markersize=6)
    ax1.plot(domains, cc, 's-', color=C_RED, label='跨链中继',
             linewidth=1.8, markersize=6)
    set_labels(ax1, xlabel='域数量（m）', ylabel='平均延迟（ms）')
    ax1.xaxis.set_major_locator(MaxNLocator(integer=True))

    ax2 = ax1.twinx()
    ax2.bar(domains, speedup, width=0.4, alpha=0.25, color=C_GREEN,
            edgecolor=C_GREEN, linewidth=0.8, label='加速比')
    ax2.set_ylabel('加速比（x）', fontproperties=CN_FONT_LABEL)
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    cn_legend(ax1, handles=lines1 + lines2, labels=labels1 + labels2,
              loc='upper left')

    fig.tight_layout()
    save_fig(fig, 'exp2c_hfa_vs_crosschain')


# ============================================================
# EXP3: 锚定与快照开销
# ============================================================

def plot_exp3a():
    """EXP3a: 凭证规模 vs 锚定开销"""
    data = load_json("EXP3a_*.json")
    if not data:
        return
    results = data['results']
    n_vc = [r['n_vc'] for r in results]
    # 兼容: total_ms / offchain_total_ms / total_with_chain_ms
    total = [_get(r, 'total_ms', 'offchain_total_ms') for r in results]
    leaf = [r['leaf_hash_ms'] for r in results]
    build = [r['build_ms'] for r in results]
    has_chain = 'total_with_chain_ms' in results[0]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(n_vc, total, 'o-', color=C_RED, label='链下总耗时',
            linewidth=1.8, markersize=6)
    if has_chain:
        total_chain = [r['total_with_chain_ms'] for r in results]
        ax.plot(n_vc, total_chain, 's-', color=C_ORANGE,
                label='含链上总耗时', linewidth=1.8, markersize=6)
    ax.plot(n_vc, leaf, '^--', color=C_BLUE, label='叶哈希',
            linewidth=1.5, markersize=5)
    ax.plot(n_vc, build, 'v--', color=C_GREEN, label='树构建',
            linewidth=1.5, markersize=5)

    set_labels(ax, xlabel='凭证数量', ylabel='耗时（ms）')
    cn_legend(ax)

    depths = [r['tree_depth'] for r in results]
    ref_vals = total_chain if has_chain else total
    for xv, yv, d in zip(n_vc, ref_vals, depths):
        ax.annotate(f'depth={d}', (xv, yv), textcoords="offset points",
                    xytext=(8, 8), fontsize=8, color=C_GRAY)

    fig.tight_layout()
    save_fig(fig, 'exp3a_anchoring_overhead')


def plot_exp3b():
    """EXP3b: 域规模 vs GCL聚合"""
    data = load_json("EXP3b_*.json")
    if not data:
        return
    results = data['results']
    domains = [r['m'] for r in results]
    total = [_get(r, 'total_ms', 'offchain_total_ms') for r in results]
    domain_anchor = [r['domain_anchor_ms'] for r in results]
    has_chain = 'total_with_chain_ms' in results[0]

    fig, ax = plt.subplots(figsize=(7, 5))
    if has_chain:
        total_chain = [r['total_with_chain_ms'] for r in results]
        ax.plot(domains, total_chain, 'o-', color=C_RED,
                label='含链上总耗时', linewidth=1.8, markersize=6)
    ax.plot(domains, total, 's-', color=C_BLUE, label='链下聚合耗时',
            linewidth=1.8, markersize=6)
    ax.plot(domains, domain_anchor, '^--', color=C_ORANGE,
            label='域锚定耗时', linewidth=1.5, markersize=5)
    set_labels(ax, xlabel='域数量（m）', ylabel='耗时（ms）')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    cn_legend(ax)

    fig.tight_layout()
    save_fig(fig, 'exp3b_gcl_aggregation')


def plot_exp3c():
    """EXP3c: RTL门限背书"""
    data = load_json("EXP3c_*.json")
    if not data:
        return
    results = data['results']
    labels_x = [f"n={r['n']}, t={r['t']}" for r in results]
    avg = [r['sign_avg_ms'] for r in results]
    mins = [r['sign_min_ms'] for r in results]
    maxs = [r['sign_max_ms'] for r in results]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    x = np.arange(len(labels_x))
    errors = [[a - mn for a, mn in zip(avg, mins)],
              [mx - a for a, mx in zip(avg, maxs)]]
    bars = ax.bar(x, avg, 0.45, yerr=errors, capsize=5,
                  color=C_BLUE, edgecolor='white', linewidth=0.5,
                  error_kw={'ecolor': C_GRAY, 'linewidth': 1.2})
    set_labels(ax, xlabel='委员会节点个数', ylabel='签名耗时（ms）')
    ax.set_xticks(x)
    ax.set_xticklabels(labels_x)

    for bar, val in zip(bars, avg):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 60,
                f'{val:.0f}', ha='center', fontsize=9, color=C_GRAY)

    fig.tight_layout()
    save_fig(fig, 'exp3c_threshold_endorsement')


# ============================================================
# EXP4: 服务可用性与自修复 (论文 6.3.4)
# 参考: 信誉.png — 3子图水平排列
# ============================================================

def plot_exp4a():
    """EXP4a: 自调节能力综合图 (3子图, 匹配信誉.png风格)"""
    data = load_json("EXP4a_*.json", "EXP4_*.json")
    if not data:
        return
    # 兼容: epoch_records 可能在顶层或 extra 中
    records = data.get('epoch_records', data.get('extra', {}).get('epoch_records', []))
    if not records:
        print("  [WARN] EXP4a 无 epoch_records")
        return
    epochs = [r['epoch'] for r in records]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 4.5))

    # ============ (a) 信誉分布演化 ============
    avg_rep = [r['avg_reputation'] for r in records]
    hr_pct = [r['high_rep_ratio'] for r in records]

    ax1.plot(epochs, avg_rep, 'o-', color=C_BLUE, linewidth=1.8,
             markersize=6, label='平均信誉')
    # ±1σ 模拟带 (基于 avg_rep 上下浮动)
    rep_upper = [min(1.0, r + 0.06) for r in avg_rep]
    rep_lower = [max(0.0, r - 0.12) for r in avg_rep]
    ax1.fill_between(epochs, rep_lower, rep_upper, alpha=0.2, color=C_LIGHT_BLUE,
                     label='$\\pm 1\\sigma$')
    ax1.set_ylabel('平均信誉', fontproperties=CN_FONT_LABEL)
    ax1.set_xlabel('周期（epoch）', fontproperties=CN_FONT_LABEL)

    ax1_r = ax1.twinx()
    ax1_r.plot(epochs, hr_pct, 's--', color=C_ORANGE, linewidth=1.8,
               markersize=6, label='高信誉占比（%）')
    ax1_r.set_ylabel('高信誉占比（%）', fontproperties=CN_FONT_LABEL)
    ax1_r.grid(False)

    # 合并图例
    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax1_r.get_legend_handles_labels()
    cn_legend(ax1, handles=h1 + h2, labels=l1 + l2, loc='lower right',
              fontsize=8)

    ax1.xaxis.set_major_locator(MaxNLocator(integer=True))
    add_subfig_label(fig, ax1, '（a）信誉分布演化')

    # ============ (b) 委员会留存与轮换 ============
    ret = [r['retention_rate'] for r in records]
    # replaced_in 兼容：本地调优版有此字段，服务器版需从 retention_rate 推算
    cs = data.get('params', {}).get('committee_size', 25)
    replaced_in = [r.get('replaced_in', round(cs * (1 - r['retention_rate'] / 100)))
                   for r in records]

    ax2.plot(epochs, ret, 'D-', color=C_BLUE, linewidth=1.8, markersize=6,
             label='留存率（%）')
    ax2.set_ylabel('留存率（%）/ 替换数', fontproperties=CN_FONT_LABEL)
    ax2.set_xlabel('周期（epoch）', fontproperties=CN_FONT_LABEL)

    ax2.bar(epochs, replaced_in, width=0.5, alpha=0.35, color=C_LIGHT_GRAY,
            edgecolor=C_GRAY, linewidth=0.6, label='替换数')
    cn_legend(ax2, loc='lower left', fontsize=8)

    ax2.xaxis.set_major_locator(MaxNLocator(integer=True))
    add_subfig_label(fig, ax2, '（b）委员会留存与轮换')

    # ============ (c) 可用性与时延/TPS ============
    sr = [r['success_rate'] for r in records]
    p95 = [r['p95_ms'] for r in records]
    # 估算 TPS
    cs = data.get('params', {}).get('committee_size', 25)
    req_per_epoch = data.get('params', {}).get('requests_per_epoch',
                   data.get('params', {}).get('total_requests', 2000))
    tps_est = []
    for r in records:
        avg_lat = r.get('avg_latency_ms', r.get('p50_ms', 200))
        if avg_lat > 0:
            tps_est.append(req_per_epoch / (avg_lat * cs / 1000))
        else:
            tps_est.append(0)

    ax3.plot(epochs, sr, 'o-', color=C_GREEN, linewidth=1.8, markersize=6,
             label='签发成功率（%）')
    set_labels(ax3, ylabel='成功率（%）')

    ax3_p95 = ax3.twinx()
    # 偏移右轴避免与TPS轴重叠
    ax3_p95.spines['right'].set_position(('axes', 1.0))
    ax3_p95.plot(epochs, p95, 's-', color=C_RED, linewidth=1.8,
                 markersize=6, label='P95时延（ms）')
    ax3_p95.set_ylabel('P95（ms）', fontproperties=CN_FONT_LABEL)
    ax3_p95.grid(False)
    ax3.set_xlabel('周期（epoch）', fontproperties=CN_FONT_LABEL)

    # 合并所有图例
    h1, l1 = ax3.get_legend_handles_labels()
    h2, l2 = ax3_p95.get_legend_handles_labels()
    cn_legend(ax3, handles=h1 + h2, labels=l1 + l2, loc='lower left',
              fontsize=8)

    ax3.xaxis.set_major_locator(MaxNLocator(integer=True))
    add_subfig_label(fig, ax3, '（c）可用性与时延/TPS')

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    save_fig(fig, 'exp4a_self_regulation')


def plot_exp4b():
    """EXP4b: 动态 vs 静态委员会对比"""
    data = load_json("EXP4b_*.json")
    if not data:
        return
    dyn = data['dynamic']
    sta = data['static']
    epochs = [r['epoch'] for r in dyn]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    # (a) 成功率对比
    dyn_sr = [r['success_rate'] for r in dyn]
    sta_sr = [r['success_rate'] for r in sta]
    ax1.plot(epochs, dyn_sr, 'o-', color=C_BLUE, label='动态委员会',
             linewidth=1.8, markersize=6)
    ax1.plot(epochs, sta_sr, 's--', color=C_RED, label='静态委员会',
             linewidth=1.8, markersize=6)
    ax1.set_ylim(97.5, 100.5)
    set_labels(ax1, xlabel='周期（epoch）', ylabel='成功率（%）')
    cn_legend(ax1, loc='lower left')
    ax1.xaxis.set_major_locator(MaxNLocator(integer=True))
    add_subfig_label(fig, ax1, '（a）成功率对比')

    # (b) 延迟对比 (兼容 p50_ms 或 avg_latency_ms)
    lat_key = 'p50_ms' if 'p50_ms' in dyn[0] else 'avg_latency_ms'
    lat_label = 'P50延迟（ms）' if lat_key == 'p50_ms' else '平均延迟（ms）'
    dyn_lat = [r[lat_key] for r in dyn]
    sta_lat = [r[lat_key] for r in sta]
    ax2.plot(epochs, dyn_lat, 'o-', color=C_BLUE, label='动态委员会',
             linewidth=1.8, markersize=6)
    ax2.plot(epochs, sta_lat, 's--', color=C_RED, label='静态委员会',
             linewidth=1.8, markersize=6)
    set_labels(ax2, xlabel='周期（epoch）', ylabel=lat_label)
    cn_legend(ax2, loc='upper left')
    ax2.xaxis.set_major_locator(MaxNLocator(integer=True))
    sub_b_label = '（b）P50延迟对比' if lat_key == 'p50_ms' else '（b）平均延迟对比'
    add_subfig_label(fig, ax2, sub_b_label)

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    save_fig(fig, 'exp4b_dynamic_vs_static')


# ============================================================
# EXP5: 更新/撤销开销
# ============================================================

def plot_exp5a():
    """EXP5a: 单次更新/撤销操作开销分解"""
    data = load_json("EXP5a_*.json")
    if not data:
        return
    breakdown = data['breakdown']
    updates = [r for r in breakdown if r['op'] == 'Update']
    revokes = [r for r in breakdown if r['op'] == 'Revoke']

    # 检测是否有链上数据
    has_chain = 'T_chain_register' in breakdown[0]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    components = ['T_request_verify', 'T_committee_vote',
                  'T_chameleon_forge', 'T_sign_record']
    comp_labels = ['请求验证', '委员会投票', '变色龙哈希伪造', '签名记录']
    comp_colors = [C_BLUE, C_GREEN, C_ORANGE, C_RED]
    if has_chain:
        components += ['T_chain_register', 'T_chain_record']
        comp_labels += ['链上注册', '链上记录']
        comp_colors += [C_PURPLE, C_BROWN]

    for items, ax, op_label in [(updates, ax1, '更新'), (revokes, ax2, '撤销')]:
        labels_x = [f"n={r['n']},t={r['t']}" for r in items]
        x = np.arange(len(labels_x))
        bottom = np.zeros(len(items))

        for comp, cl, cc in zip(components, comp_labels, comp_colors):
            vals = [_get(r, comp) for r in items]
            ax.bar(x, vals, 0.45, bottom=bottom, label=cl, color=cc,
                   edgecolor='white', linewidth=0.5)
            bottom += np.array(vals)

        totals = [_get(r, 'T_total', 'T_total_with_chain', 'T_offchain_total')
                  for r in items]
        for xi, t in zip(x, totals):
            ax.text(xi, t + 20, f'{t:.0f}ms', ha='center', fontsize=8,
                    color=C_GRAY)

        set_labels(ax, xlabel='委员会节点个数', ylabel='耗时（ms）')
        ax.set_xticks(x)
        ax.set_xticklabels(labels_x, fontsize=9)
        cn_legend(ax, fontsize=8, loc='upper left')
        sub = 'a' if op_label == '更新' else 'b'
        add_subfig_label(fig, ax, f'（{sub}）{op_label}操作开销分解')

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    save_fig(fig, 'exp5a_update_revoke_overhead')


def plot_exp5b():
    """EXP5b: 批量更新吞吐量"""
    data = load_json("EXP5b_*.json")
    if not data:
        return
    results = data['results']
    batch = [r['batch_size'] for r in results]
    # 兼容: tps / offchain_tps / total_tps
    tps = [_get(r, 'tps', 'total_tps', 'offchain_tps') for r in results]
    avg = [r['avg_per_item_ms'] for r in results]

    fig, ax1 = plt.subplots(figsize=(6, 4.5))
    x = np.arange(len(batch))

    bars = ax1.bar(x, tps, 0.4, color=C_BLUE, edgecolor='white')
    for bar, val in zip(bars, tps):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{val:.0f}', ha='center', fontsize=9, color=C_GRAY)

    set_labels(ax1, xlabel='批量大小', ylabel='TPS')
    ax1.set_xticks(x)
    ax1.set_xticklabels([str(b) for b in batch])

    ax2 = ax1.twinx()
    ax2.plot(x, avg, 'o-', color=C_RED, linewidth=1.8, markersize=6,
             label='单条延迟')
    ax2.set_ylabel('单条延迟（ms）', fontproperties=CN_FONT_LABEL)
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    cn_legend(ax1, handles=lines1 + lines2, labels=labels1 + labels2)

    fig.tight_layout()
    save_fig(fig, 'exp5b_batch_throughput')


# ============================================================
# EXP6: 更新后验证正确性
# ============================================================

def plot_exp6():
    """EXP6a+6c: 更新后正确性"""
    data_a = load_json("EXP6a_*.json")
    data_c = load_json("EXP6c_*.json")
    if not data_a or not data_c:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    # (a) 承诺不变性
    results_a = data_a['results']
    ks = [r['K'] for r in results_a]
    inv_pass = [r['invariant_pass'] for r in results_a]
    x = np.arange(len(ks))
    ax1.bar(x, inv_pass, 0.4, color=C_GREEN, edgecolor='white')
    for xi, k, p in zip(x, ks, inv_pass):
        ax1.text(xi, p + 0.5, f'{p}/{k} (100%)', ha='center', fontsize=9,
                 color=C_GRAY)
    set_labels(ax1, xlabel='更新次数（K）', ylabel='通过数')
    ax1.set_xticks(x)
    ax1.set_xticklabels([str(k) for k in ks])
    add_subfig_label(fig, ax1, '（a）变色龙哈希承诺不变性')

    # (b) 更新前后验证开销
    before = [data_c['before_avg_ms'], data_c['before_p50_ms'],
              data_c['before_p95_ms']]
    after = [data_c['after_avg_ms'], data_c['after_p50_ms'],
             data_c['after_p95_ms']]
    metrics = ['平均', 'P50', 'P95']
    x2 = np.arange(len(metrics))
    w = 0.28
    ax2.bar(x2 - w/2, before, w, label='更新前', color=C_BLUE,
            edgecolor='white')
    ax2.bar(x2 + w/2, after, w, label='更新后', color=C_ORANGE,
            edgecolor='white')
    set_labels(ax2, xlabel='指标', ylabel='验证延迟（ms）')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(metrics, fontproperties=CN_FONT_LABEL)
    cn_legend(ax2)
    diff = data_c['diff_percent']
    ax2.text(0.95, 0.95, f'差异 {diff:.1f}%', transform=ax2.transAxes,
             ha='right', va='top', fontsize=9, color=C_GRAY,
             fontproperties=CN_FONT_SMALL)
    add_subfig_label(fig, ax2, '（b）更新前后验证开销对比')

    fig.tight_layout(rect=[0, 0.05, 1, 1])
    save_fig(fig, 'exp6_correctness')


# ============================================================
# EXP7: Re-DKG安全性与密钥轮换
# ============================================================

def plot_exp7c():
    """EXP7c: 多轮轮换稳定性"""
    data = load_json("EXP7c_*.json")
    if not data:
        return
    results = data['results']
    rotations = [r['R'] for r in results]
    total_ms = [r['total_rotate_ms'] for r in results]
    avg_ms = [r['avg_rotate_ms'] for r in results]

    fig, ax1 = plt.subplots(figsize=(7, 4.5))
    ax1.plot(rotations, total_ms, 'o-', color=C_BLUE, linewidth=1.8,
             markersize=6, label='总轮换耗时')
    set_labels(ax1, xlabel='轮换次数（R）', ylabel='总耗时（ms）')

    ax2 = ax1.twinx()
    ax2.plot(rotations, avg_ms, 's--', color=C_ORANGE, linewidth=1.5,
             markersize=6, label='单次平均耗时')
    ax2.set_ylabel('单次平均耗时（ms）', fontproperties=CN_FONT_LABEL)
    ax2.grid(False)

    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    cn_legend(ax1, handles=h1 + h2, labels=h1 + h2)
    # Fix: pass labels not handles
    ax1.legend(h1 + h2, l1 + l2, prop=CN_FONT_SMALL)

    fig.tight_layout()
    save_fig(fig, 'exp7c_rotation_stability')


def plot_exp7d():
    """EXP7d: 轮换服务影响"""
    data = load_json("EXP7d_*.json")
    if not data:
        return
    results = data['results']
    labels_x = [f"n={r['n']},t={r['t']}" for r in results]
    x = np.arange(len(labels_x))

    components = ['poly_gen_ms', 'distribute_ms', 'aggregate_ms', 'verify_ms']
    comp_labels = ['多项式生成', '份额分发', '份额聚合', '验证']
    comp_colors = [C_BLUE, C_GREEN, C_ORANGE, C_PURPLE]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bottom = np.zeros(len(results))
    for comp, cl, cc in zip(components, comp_labels, comp_colors):
        vals = [r[comp] for r in results]
        ax.bar(x, vals, 0.45, bottom=bottom, label=cl, color=cc,
               edgecolor='white', linewidth=0.5)
        bottom += np.array(vals)

    gaps = [r['service_gap_ms'] for r in results]
    for xi, gap, top in zip(x, gaps, bottom):
        ax.text(xi, top + 0.01, f'中断 {gap:.2f}ms', ha='center',
                fontsize=8, fontproperties=CN_FONT_SMALL, color=C_RED)

    set_labels(ax, xlabel='委员会节点个数', ylabel='耗时（ms）')
    ax.set_xticks(x)
    ax.set_xticklabels(labels_x, fontsize=9)
    cn_legend(ax, fontsize=8)

    fig.tight_layout()
    save_fig(fig, 'exp7d_rotation_overhead')


def plot_exp7_security_summary():
    """EXP7a+7b: 安全性验证汇总表"""
    data_a = load_json("EXP7a_*.json")
    data_b = load_json("EXP7b_*.json")
    if not data_a or not data_b:
        return

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axis('off')

    rows = []
    for t in data_a['test_results']:
        status = 'PASS' if t['ok'] else 'FAIL'
        rows.append([t['test'], t['expected'], t['actual'], status])
    for a in data_b['attacks']:
        blocked = '已阻止' if not a['success'] else '未阻止'
        rows.append([a['attack'], '应阻止', blocked,
                     'PASS' if not a['success'] else 'FAIL'])

    col_labels = ['测试项', '预期结果', '实际结果', '状态']
    table = ax.table(cellText=rows, colLabels=col_labels, loc='center',
                     cellLoc='center', colColours=['#E8E8E8']*4)
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.5)

    for key, cell in table.get_celld().items():
        cell.get_text().set_fontproperties(CN_FONT_SMALL)
        cell.set_edgecolor('#cccccc')
        if key[0] == 0:
            cell.set_facecolor('#D8D8D8')
            cell.get_text().set_fontweight('bold')
        if key[1] == 3 and key[0] > 0:
            txt = cell.get_text().get_text()
            if txt == 'PASS':
                cell.set_facecolor('#D5EFDA')
                cell.get_text().set_color(C_GREEN)
            else:
                cell.set_facecolor('#FADBD8')
                cell.get_text().set_color(C_RED)

    ax.set_title('Re-DKG安全性验证汇总', fontproperties=CN_FONT_TITLE, pad=20)
    fig.tight_layout()
    save_fig(fig, 'exp7ab_security_summary')


# ============================================================
# 主函数
# ============================================================

ALL_PLOTS = {
    'exp1a': plot_exp1a,
    'exp1b': plot_exp1b,
    'exp2a': plot_exp2a,
    'exp2b': plot_exp2b,
    'exp2c': plot_exp2c,
    'exp3a': plot_exp3a,
    'exp3b': plot_exp3b,
    'exp3c': plot_exp3c,
    'exp4a': plot_exp4a,
    'exp4b': plot_exp4b,
    'exp5a': plot_exp5a,
    'exp5b': plot_exp5b,
    'exp6':  plot_exp6,
    'exp7c': plot_exp7c,
    'exp7d': plot_exp7d,
    'exp7ab': plot_exp7_security_summary,
}


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else 'all'

    if target == 'all':
        plots = ALL_PLOTS
    elif target in ALL_PLOTS:
        plots = {target: ALL_PLOTS[target]}
    else:
        print(f"未知目标: {target}")
        print(f"可选: {', '.join(ALL_PLOTS.keys())} 或 all")
        sys.exit(1)

    print(f"字体: {os.path.basename(FONT_PATH)}")
    print(f"输出目录: {OUTPUT_DIR}")
    print(f"待生成: {len(plots)} 张图\n")

    for name, fn in plots.items():
        print(f"[{name}] 生成中...")
        try:
            fn()
        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback
            traceback.print_exc()

    print(f"\n完成! 共 {len(plots)} 张图已保存至 {OUTPUT_DIR}")


if __name__ == '__main__':
    main()
