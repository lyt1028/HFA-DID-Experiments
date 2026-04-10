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
CN_T = FontProperties(fname=FONT_PATH, size=12)

plt.rcParams.update({
    "axes.unicode_minus": False, "axes.grid": True,
    "grid.linestyle": "--", "grid.alpha": 0.5, "grid.linewidth": 0.6,
    "figure.facecolor": "white", "axes.facecolor": "white",
    "axes.edgecolor": "#333333", "axes.linewidth": 0.8,
})

# Load data
rep_file = sorted(glob.glob(os.path.join(SCRIPT_DIR, "results", "EXP4v3_reputation_*.json")))[-1]
path_file = sorted(glob.glob(os.path.join(SCRIPT_DIR, "results", "EXP_redkg_path_*.json")))[-1]

with open(rep_file) as f:
    rep_data = json.load(f)
with open(path_file) as f:
    path_data = json.load(f)

rep = rep_data["reputation"]
rand = rep_data["random"]
part_a = path_data["part_a"]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

# === (a) reputation election ===
epochs = [r["epoch"] for r in rep]
mal_rep = [r["mal_in_committee"] for r in rep]
mal_rand = [r["mal_in_committee"] for r in rand]

ax1.plot(epochs, mal_rep, "o-", color="#1f77b4", linewidth=2, markersize=5, label="信誉选举")
ax1.plot(epochs, mal_rand, "s--", color="#d62728", linewidth=2, markersize=5, label="随机选举")

# success rate on right axis
ax1b = ax1.twinx()
sr_rep = [r["success_rate"] for r in rep]
sr_rand = [r["success_rate"] for r in rand]
ax1b.plot(epochs, sr_rep, "^-", color="#2ca02c", linewidth=1.5, markersize=4, alpha=0.7, label="签发成功率(信誉)")
ax1b.plot(epochs, sr_rand, "v--", color="#ff7f0e", linewidth=1.5, markersize=4, alpha=0.7, label="签发成功率(随机)")
ax1b.set_ylabel("签发成功率 (%)", fontproperties=CN_L)
ax1b.set_ylim(-5, 110)

# inject epochs annotation
ax1.axvline(x=4, color="#999999", linestyle=":", linewidth=1, alpha=0.6)
ax1.axvline(x=7, color="#999999", linestyle=":", linewidth=1, alpha=0.6)
ax1.text(4, max(mal_rand)*0.95, "注入6个", ha="center", fontproperties=FontProperties(fname=FONT_PATH, size=7), color="#999999")
ax1.text(7, max(mal_rand)*0.95, "追加3个", ha="center", fontproperties=FontProperties(fname=FONT_PATH, size=7), color="#999999")

ax1.set_xlabel("轮次 (epoch)", fontproperties=CN_L)
ax1.set_ylabel("委员会中恶意节点数", fontproperties=CN_L)
ax1.set_title("(a) 信誉驱动 vs 随机选举", fontproperties=CN_T)

l1, lb1 = ax1.get_legend_handles_labels()
l2, lb2 = ax1b.get_legend_handles_labels()
ax1.legend(l1+l2, lb1+lb2, prop=CN_S, loc="center right")

# === (b) path communication cost ===
rhos = [r["rho"] for r in part_a]
full_comm = [r["full_comm"] for r in part_a]

x = np.arange(len(rhos))
w = 0.3

ax2.bar(x - w/2, full_comm, w, color="#d62728", alpha=0.85, label="完整路径", edgecolor="black", hatch="///")

opt_vals = [r["opt_comm"] if r["opt_comm"] is not None else 0 for r in part_a]
bars_opt = ax2.bar(x + w/2, opt_vals, w, color="#1f77b4", alpha=0.85, label="乐观路径", edgecolor="black", hatch="\\\\")

for i, r in enumerate(part_a):
    if r["opt_comm"] is None:
        bars_opt[i].set_color("#cccccc")
        bars_opt[i].set_alpha(0.4)
        ax2.text(x[i] + w/2, 20, "N/A", ha="center", va="bottom", fontsize=8, color="#999999", fontweight="bold")
    elif r["comm_reduction_pct"] is not None and r["comm_reduction_pct"] > 0:
        ax2.text(x[i] + w/2, r["opt_comm"] + 8, f"-{r['comm_reduction_pct']:.0f}%",
                 ha="center", va="bottom", fontsize=8, color="#1f77b4", fontweight="bold")

ax2.axvline(x=1.5, color="#ff7f0e", linestyle="--", linewidth=1.5, alpha=0.7)
ax2.text(1.6, 430, r"$\rho_{th}=0.7$", fontsize=10, color="#ff7f0e", fontweight="bold")

ax2.set_xticks(x)
ax2.set_xticklabels([f"{r:.1f}" for r in rhos])
ax2.set_xlabel(r"留存率 $\rho$", fontproperties=CN_L)
ax2.set_ylabel("通信消息数", fontproperties=CN_L)
ax2.set_title("(b) 乐观路径 vs 完整路径通信开销", fontproperties=CN_T)
ax2.legend(prop=CN_S, loc="upper right")
ax2.set_ylim(0, 480)

plt.tight_layout()
out_dir = os.path.join(SCRIPT_DIR, "plots")
os.makedirs(out_dir, exist_ok=True)
for ext in ["pdf", "png"]:
    fig.savefig(os.path.join(out_dir, f"exp5_rep_path.{ext}"), dpi=300, bbox_inches="tight", facecolor="white")
print("Done: plots/exp5_rep_path.pdf & .png")
plt.close()
