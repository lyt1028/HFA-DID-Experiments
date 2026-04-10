"""
多场景对比实验: 证明自适应门限在未知威胁环境下的不可替代性
用Part A的BLS延迟映射做快速仿真, 无需重跑BLS
"""
import sys, os, json, random, statistics, glob, math
import numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.ticker import MaxNLocator

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.models.reputation import ReputationModel, NodeBehavior
from src.models.adaptive_threshold import AdaptiveThreshold, FixedThreshold

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')
PLOTS_DIR = os.path.join(SCRIPT_DIR, 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
FONT_PATH = os.path.join(PROJECT_DIR, 'fonts', 'wqy-microhei.ttc')
CN = FontProperties(fname=FONT_PATH, size=11)
CN_S = FontProperties(fname=FONT_PATH, size=9)
CN_L = FontProperties(fname=FONT_PATH, size=10)
CN_T = FontProperties(fname=FONT_PATH, size=12)

plt.rcParams.update({
    'axes.unicode_minus': False, 'axes.grid': True,
    'grid.linestyle': '--', 'grid.alpha': 0.5, 'grid.linewidth': 0.6,
    'lines.linewidth': 1.8, 'lines.markersize': 6,
    'xtick.direction': 'in', 'ytick.direction': 'in',
    'legend.framealpha': 0.9, 'legend.edgecolor': '#cccccc',
    'axes.edgecolor': '#333333', 'axes.linewidth': 0.8,
    'figure.facecolor': 'white', 'axes.facecolor': 'white',
})

C_BLUE = '#1f77b4'; C_ORANGE = '#ff7f0e'; C_GREEN = '#2ca02c'
C_RED = '#d62728'; C_PURPLE = '#9467bd'; C_GRAY = '#7f7f7f'

# BLS延迟映射 (从Part A实测数据)
LATENCY_MAP = {8: 1490, 9: 1573, 10: 1672, 11: 1741, 12: 1839, 13: 1900, 14: 1960}


def make_threat_schedule(peak, n_epochs=15):
    """生成对称的威胁调度: 0 -> peak -> 0"""
    mid = n_epochs // 2 + 1  # epoch 8
    schedule = {}
    for e in range(1, n_epochs + 1):
        dist = abs(e - mid)
        ratio = max(0, 1.0 - dist / (mid - 1))
        schedule[e] = round(peak * ratio, 2)
    return schedule


def simulate_scenario(n, peak_threat, strategy_name, threshold_obj, n_epochs=15):
    """仿真一个场景, 返回每轮结果"""
    schedule = make_threat_schedule(peak_threat, n_epochs)
    random.seed(42)
    nodes = {i: {'reputation': 0.6 + random.uniform(0, 0.3), 'corrupted': False}
             for i in range(1, n + 1)}
    rep_model = ReputationModel()
    results = []

    for epoch in range(1, n_epochs + 1):
        target = int(n * schedule[epoch])
        corrupted = [nid for nid, nd in nodes.items() if nd['corrupted']]
        honest = [nid for nid, nd in nodes.items() if not nd['corrupted']]
        if len(corrupted) < target:
            for nid in random.sample(honest, min(target - len(corrupted), len(honest))):
                nodes[nid]['corrupted'] = True
        elif len(corrupted) > target:
            for nid in random.sample(corrupted, len(corrupted) - target):
                nodes[nid]['corrupted'] = False

        behaviors = []
        for nid in sorted(nodes.keys()):
            b = NodeBehavior(node_id=nid)
            b.total_tasks = 50; b.requested = 50
            if nodes[nid]['corrupted']:
                b.response_time_ms = random.uniform(200, 500)
                b.participated = random.randint(10, 25)
                b.rejected = random.randint(15, 30)
                b.issued_count = random.randint(5, 15)
                b.revoked_count = random.randint(2, 8)
                b.anchor_submit_rate = random.uniform(0.3, 0.6)
                b.valid_sig_rate = random.uniform(0.4, 0.7)
                b.consistency_score = random.uniform(0.3, 0.6)
            else:
                b.response_time_ms = random.uniform(30, 80)
                b.participated = random.randint(40, 50)
                b.rejected = random.randint(0, 3)
                b.issued_count = random.randint(30, 50)
                b.revoked_count = random.randint(0, 2)
                b.anchor_submit_rate = random.uniform(0.85, 1.0)
                b.valid_sig_rate = random.uniform(0.9, 1.0)
                b.consistency_score = random.uniform(0.85, 1.0)
            behaviors.append(b)

        scores = rep_model.evaluate_all(behaviors)
        t_e, _ = threshold_obj.compute_threshold(scores)
        t_e = max(8, min(14, t_e))
        f_active = sum(1 for nd in nodes.values() if nd['corrupted'])
        margin = t_e - f_active
        latency = LATENCY_MAP.get(t_e, 1900)

        results.append({
            'epoch': epoch, 't_e': t_e, 'f_active': f_active,
            'margin': margin, 'breached': margin <= 0,
            'latency_ms': latency, 'threat': schedule[epoch],
        })

    return results


def run_multi_scenario():
    n = 20
    peak_threats = [0.0, 0.15, 0.30, 0.45, 0.60]
    fixed_ts = [8, 9, 10, 11, 12, 13]

    all_data = {}

    for peak in peak_threats:
        scenario_key = f"peak_{int(peak*100)}"
        all_data[scenario_key] = {}

        for ft in fixed_ts:
            name = f"fixed_t{ft}"
            obj = FixedThreshold(n, ft)
            res = simulate_scenario(n, peak, name, obj)
            avg_lat = statistics.mean(r['latency_ms'] for r in res)
            breach_count = sum(1 for r in res if r['breached'])
            min_margin = min(r['margin'] for r in res)
            all_data[scenario_key][name] = {
                'avg_latency': round(avg_lat), 'breach_epochs': breach_count,
                'min_margin': min_margin, 't': ft,
            }

        # Adaptive
        obj = AdaptiveThreshold(n, t_base=0.35, mu=0.6)
        res = simulate_scenario(n, peak, 'adaptive', obj)
        avg_lat = statistics.mean(r['latency_ms'] for r in res)
        breach_count = sum(1 for r in res if r['breached'])
        min_margin = min(r['margin'] for r in res)
        all_data[scenario_key]['adaptive'] = {
            'avg_latency': round(avg_lat), 'breach_epochs': breach_count,
            'min_margin': min_margin, 't': 'adaptive',
        }

    return all_data, peak_threats, fixed_ts


def print_and_save(all_data, peak_threats, fixed_ts):
    print("\n=== Multi-Scenario Results ===\n")
    strategies = [f"fixed_t{t}" for t in fixed_ts] + ['adaptive']
    header = f"{'Scenario':>12s}"
    for s in strategies:
        header += f" | {s:>12s}"
    print(header)
    print("-" * len(header))

    for peak in peak_threats:
        key = f"peak_{int(peak*100)}"
        row = f"{'peak='+str(int(peak*100))+'%':>12s}"
        for s in strategies:
            d = all_data[key][s]
            if d['breach_epochs'] > 0:
                cell = f"BREACH({d['breach_epochs']})"
            else:
                cell = f"{d['avg_latency']}ms"
            row += f" | {cell:>12s}"
        print(row)

    # Save
    filepath = os.path.join(RESULTS_DIR, 'EXP9_multi_scenario.json')
    with open(filepath, 'w') as f:
        json.dump(all_data, f, indent=2)
    print(f"\nSaved: {filepath}")


def plot_multi_scenario(all_data, peak_threats, fixed_ts):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    peaks_pct = [int(p * 100) for p in peak_threats]
    x = np.arange(len(peaks_pct))

    # Colors for fixed thresholds (gradient blue to red)
    ft_colors = {8: '#4fc3f7', 9: '#29b6f6', 10: '#039be5',
                 11: '#0277bd', 12: '#01579b', 13: '#002f6c'}

    # --- (a) Average Latency ---
    ax = axes[0]
    width = 0.1
    for i, ft in enumerate(fixed_ts):
        key = f"fixed_t{ft}"
        lats = []
        breached_mask = []
        for peak in peak_threats:
            sk = f"peak_{int(peak*100)}"
            d = all_data[sk][key]
            lats.append(d['avg_latency'])
            breached_mask.append(d['breach_epochs'] > 0)

        offset = (i - len(fixed_ts)/2 + 0.5) * width
        bars = ax.bar(x + offset, lats, width * 0.9, color=ft_colors[ft],
                      label=f'$t={ft}$', alpha=0.85)
        # Mark breached bars
        for j, breached in enumerate(breached_mask):
            if breached:
                ax.text(x[j] + offset, lats[j] + 20, '\u00d7',
                        ha='center', va='bottom', fontsize=14,
                        color=C_RED, fontweight='bold')

    # Adaptive as line overlay
    adaptive_lats = []
    for peak in peak_threats:
        sk = f"peak_{int(peak*100)}"
        adaptive_lats.append(all_data[sk]['adaptive']['avg_latency'])
    ax.plot(x, adaptive_lats, 'o-', color=C_GREEN, linewidth=2.5,
            markersize=8, label='\u81ea\u9002\u5e94', zorder=10)

    ax.set_xticks(x)
    ax.set_xticklabels([f'{p}%' for p in peaks_pct])
    ax.set_xlabel('\u5cf0\u503c\u5a01\u80c1\u7b49\u7ea7', fontproperties=CN_L)
    ax.set_ylabel('\u5e73\u5747\u7b7e\u53d1\u5ef6\u8fdf (ms)', fontproperties=CN_L)
    ax.set_title('(a) \u4e0d\u540c\u5a01\u80c1\u573a\u666f\u4e0b\u7684\u5e73\u5747\u5ef6\u8fdf',
                 fontproperties=CN_T)
    ax.legend(prop=CN_S, ncol=4, loc='upper left')
    ax.set_ylim(1400, 2200)
    ax.text(0.95, 0.05, '\u00d7 = \u5b89\u5168\u88ab\u7a81\u7834',
            transform=ax.transAxes, fontproperties=CN_S, color=C_RED,
            ha='right', va='bottom')

    # --- (b) Safety-Efficiency Pareto ---
    ax = axes[1]
    # For the 45% scenario (most interesting)
    sk = "peak_45"
    for ft in fixed_ts:
        key = f"fixed_t{ft}"
        d = all_data[sk][key]
        marker = 'x' if d['breach_epochs'] > 0 else 'o'
        color = C_RED if d['breach_epochs'] > 0 else ft_colors[ft]
        ax.scatter(d['avg_latency'], d['min_margin'], marker=marker,
                   s=100, color=color, zorder=5, linewidths=2)
        ax.annotate(f'$t={ft}$', (d['avg_latency'], d['min_margin']),
                    textcoords='offset points', xytext=(8, 5), fontsize=9)

    d_adp = all_data[sk]['adaptive']
    ax.scatter(d_adp['avg_latency'], d_adp['min_margin'], marker='*',
               s=200, color=C_GREEN, zorder=10, linewidths=1.5)
    ax.annotate('\u81ea\u9002\u5e94', (d_adp['avg_latency'], d_adp['min_margin']),
                textcoords='offset points', xytext=(8, 5),
                fontproperties=CN_S, fontsize=10, color=C_GREEN, fontweight='bold')

    ax.axhline(y=0, color=C_RED, linestyle='--', linewidth=1, alpha=0.7)
    ax.text(2100, 0.3, '\u5b89\u5168\u8fb9\u754c', fontproperties=CN_S,
            color=C_RED, alpha=0.8)
    ax.fill_between([1450, 2200], [-5, -5], [0, 0], alpha=0.08, color=C_RED)

    ax.set_xlabel('\u5e73\u5747\u7b7e\u53d1\u5ef6\u8fdf (ms)', fontproperties=CN_L)
    ax.set_ylabel('\u6700\u5c0f\u5b89\u5168\u88d5\u5ea6', fontproperties=CN_L)
    ax.set_title('(b) \u5b89\u5168-\u6548\u7387 Pareto\u5206\u5e03 (\u5cf0\u503c\u5a01\u80c145%)',
                 fontproperties=CN_T)
    ax.set_xlim(1450, 2200)

    plt.tight_layout()
    for ext in ['pdf', 'png']:
        fig.savefig(os.path.join(PLOTS_DIR, f'exp9_multi_scenario.{ext}'),
                    dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print('Plot saved: exp9_multi_scenario.pdf/png')


if __name__ == '__main__':
    data, peaks, fts = run_multi_scenario()
    print_and_save(data, peaks, fts)
    plot_multi_scenario(data, peaks, fts)
