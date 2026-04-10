"""
图4: 系统核心性能与跨域验证对比 (更新版)
(a) 不同委员会规模下的密码学计算时延
(b) 跨域验证延迟对比 (三种方案)
"""
import json, os, numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "fonts", "wqy-microhei.ttc")
if not os.path.exists(FONT_PATH):
    FONT_PATH = "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"
CN = FontProperties(fname=FONT_PATH, size=11)
CN_S = FontProperties(fname=FONT_PATH, size=9)
CN_L = FontProperties(fname=FONT_PATH, size=10)
CN_T = FontProperties(fname=FONT_PATH, size=13)

plt.rcParams.update({
    "axes.unicode_minus": False, "axes.grid": True,
    "grid.linestyle": "--", "grid.alpha": 0.5, "grid.linewidth": 0.6,
    "figure.facecolor": "white", "axes.facecolor": "white",
    "axes.edgecolor": "#333333", "axes.linewidth": 0.8,
})

# ---------- 数据 ----------
core = json.load(open(os.path.join(SCRIPT_DIR, "e2e/results/blspy_core_perf.json")))
relay = json.load(open(os.path.join(SCRIPT_DIR, "e2e/results/relay_comparison_20260324_171535.json")))

# ---------- 绘图 ----------
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6.5, 10))

# === (a) 密码学计算时延 ===
ns = [r["n"] for r in core]
dkg = [r["dkg_ms"] for r in core]
sign = [r["sign_ms"] for r in core]
verify = [r["verify_ms"] for r in core]
x = np.arange(len(ns))
w = 0.25

ax1.bar(x - w, dkg, w, color="#1f77b4", label="分布式密钥生成", edgecolor="black", hatch="///")
ax1.bar(x, sign, w, color="#2ca02c", label="凭证签发", edgecolor="black", hatch="\\\\")
ax1.bar(x + w, verify, w, color="#ff7f0e", label="BLS配对验证", edgecolor="black", hatch="||")

for i, r in enumerate(core):
    ax1.text(i, r["total_ms"] + 0.5, f"{r['total_ms']:.1f}ms",
             ha="center", va="bottom", fontsize=9, fontweight="bold")

ax1.set_xticks(x)
ax1.set_xticklabels([str(n) for n in ns])
ax1.set_xlabel("委员会规模 $n$", fontproperties=CN_L)
ax1.set_ylabel("密码学计算延迟 (ms)", fontproperties=CN_L)
ax1.set_title("(a) 不同委员会规模下的密码学计算时延", fontproperties=CN_T)
ax1.legend(prop=CN_S, loc="upper left")
ax1.set_ylim(0, 38)

# === (b) 跨域验证延迟对比 ===
ms = [r["m"] for r in relay]
hfa = [r["hfa_avg"] for r in relay]
serial = [r["serial_avg"] for r in relay]
parallel = [r["parallel_avg"] for r in relay]

ax2.plot(ms, hfa, "o-", color="#1f77b4", linewidth=2.2, markersize=7,
         markerfacecolor="white", markeredgewidth=2, label="HFA-DID方案", zorder=5)
ax2.plot(ms, serial, "s--", color="#d62728", linewidth=2, markersize=7,
         label="按需解析方案", zorder=4)
ax2.plot(ms, parallel, "^:", color="#ff7f0e", linewidth=2, markersize=7,
         label="CCAP方案", zorder=4)

ax2.set_yscale("log")
ax2.set_xlabel("域数量 $m$", fontproperties=CN_L)
ax2.set_ylabel("端到端验证延迟 (ms)", fontproperties=CN_L)
ax2.set_title("(b) 跨域验证延迟对比 (三种方案)", fontproperties=CN_T)
ax2.set_xticks(ms)
ax2.legend(prop=CN, loc="upper left")

# 标注关键数据点
annotations = [
    (ms[0], hfa[0], f"{hfa[0]:.1f}ms", "#1f77b4", (-15, -18)),
    (ms[2], hfa[2], f"{hfa[2]:.1f}ms", "#1f77b4", (0, -18)),
    (ms[-1], hfa[-1], f"{hfa[-1]:.1f}ms", "#1f77b4", (5, -18)),
    (ms[2], serial[2], f"{serial[2]:.0f}ms", "#d62728", (-5, 8)),
    (ms[3], serial[3], f"{serial[3]:.0f}ms", "#d62728", (-5, 8)),
    (ms[-1], serial[-1], f"{serial[-1]:.0f}ms", "#d62728", (5, 5)),
    (ms[2], parallel[2], f"{parallel[2]:.0f}ms", "#ff7f0e", (5, -15)),
    (ms[4], parallel[4], f"{parallel[4]:.0f}ms", "#ff7f0e", (5, -5)),
    (ms[-1], parallel[-1], f"{parallel[-1]:.0f}ms", "#ff7f0e", (8, 5)),
]
for xv, yv, txt, clr, ofs in annotations:
    ax2.annotate(txt, (xv, yv), textcoords="offset points", xytext=ofs,
                 fontsize=8, color=clr, fontweight="bold")

# 加速比标注
ax2.annotate(f"{serial[-1]/hfa[-1]:.0f}倍", xy=(ms[-1], serial[-1]),
             xytext=(ms[-1]-2, serial[-1]*0.85), fontsize=11, fontproperties=FontProperties(fname="/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", size=11),
             color="#d62728", fontweight="bold")
ax2.annotate(f"{parallel[-1]/hfa[-1]:.1f}倍", xy=(ms[-1], parallel[-1]),
             xytext=(ms[-1]-3, parallel[-1]*1.1), fontsize=11, fontproperties=FontProperties(fname="/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", size=11),
             color="#ff7f0e", fontweight="bold")

# 填充区域
ax2.fill_between(ms, hfa, serial, alpha=0.08, color="#d62728")

plt.tight_layout()
out_dir = os.path.join(SCRIPT_DIR, "plots")
os.makedirs(out_dir, exist_ok=True)
for ext in ["pdf", "png"]:
    fig.savefig(os.path.join(out_dir, f"exp_core_cross.{ext}"),
                dpi=300, bbox_inches="tight", facecolor="white")
print("Done: plots/exp_core_cross.pdf & .png")
plt.close()
