# -*- coding: utf-8 -*-
"""
plot_phase_latency_scaling.py
绘制 Initialization / Public key generation / Credential issuance
三个阶段在不同委员会规模下的平均计算时延

数据来源: experiments/exp_issuance_bench.py → results/EXP_ISSUANCE_*.json
"""

import json, glob, os, sys
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# ── 尝试加载中文字体 ──
_font_path = os.path.join(os.path.dirname(__file__), '..', '..', 'fonts', 'wqy-microhei.ttc')
if os.path.exists(_font_path):
    _fp = fm.FontProperties(fname=_font_path)
else:
    _fp = fm.FontProperties(family='SimHei')  # Windows fallback

# ── 加载最新实验数据 ──
results_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'results')
pattern = os.path.join(results_dir, 'EXP_ISSUANCE_*.json')
files = sorted(glob.glob(pattern))
if not files:
    print("未找到 EXP_ISSUANCE_*.json, 请先运行 experiments/exp_issuance_bench.py")
    sys.exit(1)

with open(files[-1], 'r') as f:
    data = json.load(f)
print(f"加载数据: {files[-1]}")

results = data['results']
nodes       = [r['n'] for r in results]
init_time   = [r['init_avg_ms'] for r in results]
pubkey_time = [r['pubkey_avg_ms'] for r in results]
issue_time  = [r['issue_avg_ms'] for r in results]

# ── 绘图 ──
plt.figure(figsize=(6.4, 4.2))

# Initialization：红线 圆圈
plt.plot(nodes, init_time, 'o-', color='#d62728',
         markerfacecolor='none', markersize=7, linewidth=2,
         label='Initialization')

# Public key generation：橙线 方形
plt.plot(nodes, pubkey_time, 's-', color='#ff7f0e',
         markerfacecolor='none', markersize=7, linewidth=2,
         label='Public key generation')

# Credential issuance：绿线 倒三角
plt.plot(nodes, issue_time, 'v-', color='#2ca02c',
         markerfacecolor='none', markersize=7, linewidth=2,
         label='Credential issuance')

plt.xlabel("委员会节点个数", fontproperties=_fp, fontsize=11)
plt.ylabel("时延（ms）", fontproperties=_fp, fontsize=11)
plt.xticks(nodes)
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend(fontsize=10, loc='center right')
plt.tight_layout()

# 保存输出
out_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
os.makedirs(out_dir, exist_ok=True)
for ext in ['png', 'pdf']:
    plt.savefig(os.path.join(out_dir, f'issuance_phase_latency.{ext}'), dpi=300)
print("已保存: plots/output/issuance_phase_latency.{png,pdf}")
plt.show()
