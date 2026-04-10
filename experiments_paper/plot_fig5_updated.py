import json, os, glob, numpy as np
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

files = sorted(glob.glob(os.path.join(SCRIPT_DIR, "results", "EXP_redkg_path_*.json")))
with open(files[-1]) as f:
    data = json.load(f)

part_a = data["part_a"]

# --- 只绘制 (b) 通信开销对比 ---
fig, ax = plt.subplots(figsize=(6, 4.5))

rhos = [r["rho"] for r in part_a]
full_comm = [r["full_comm"] for r in part_a]

x = np.arange(len(rhos))
w = 0.3

bars_full = ax.bar(x - w/2, full_comm, w, color="#d62728", alpha=0.85,
                   label="完整路径", edgecolor="white")

opt_vals = [r["opt_comm"] if r["opt_comm"] is not None else 0 for r in part_a]
bars_opt = ax.bar(x + w/2, opt_vals, w, color="#1f77b4", alpha=0.85,
                  label="乐观路径", edgecolor="white")

for i, r in enumerate(part_a):
    if r["opt_comm"] is None:
        bars_opt[i].set_color("#cccccc")
        bars_opt[i].set_alpha(0.4)
        ax.text(x[i] + w/2, 20, "N/A", ha="center", va="bottom",
                fontsize=8, color="#999999", fontweight="bold")
    elif r["comm_reduction_pct"] is not None and r["comm_reduction_pct"] > 0:
        ax.text(x[i] + w/2, r["opt_comm"] + 8,
                f"-{r['comm_reduction_pct']:.0f}%",
                ha="center", va="bottom", fontsize=8,
                color="#1f77b4", fontweight="bold")

# rho_th 分界线
ax.axvline(x=1.5, color="#ff7f0e", linestyle="--", linewidth=1.5, alpha=0.7)
ax.text(1.6, 430, r"$\rho_{th}=0.7$", fontsize=10, color="#ff7f0e",
        fontweight="bold")

ax.set_xticks(x)
ax.set_xticklabels([f"{r:.1f}" for r in rhos])
ax.set_xlabel(r"留存率 $\rho$", fontproperties=CN_L)
ax.set_ylabel("通信消息数", fontproperties=CN_L)
ax.set_title("(b) 乐观路径 vs 完整路径通信开销", fontproperties=CN_T)
ax.legend(prop=CN_S, loc="upper right")
ax.set_ylim(0, 480)

plt.tight_layout()
out_dir = os.path.join(SCRIPT_DIR, "plots")
os.makedirs(out_dir, exist_ok=True)
for ext in ["pdf", "png"]:
    fig.savefig(os.path.join(out_dir, f"exp5b_path_comm.{ext}"),
                dpi=300, bbox_inches="tight", facecolor="white")
print("Done: plots/exp5b_path_comm.pdf & .png")
plt.close()
