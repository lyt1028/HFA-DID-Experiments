"""
实验9: 签发域离线可用性对比
HFA-DID (异步锚定, 查GCL链上数据) vs 按需拉取 (实时查签发域)

设计:
- m=10 个签发域, 每域预锚定凭证到 FISCO BCOS
- 变量: 签发域可用率 p in {100%, 80%, 60%, 40%, 20%, 0%}
- HFA-DID: 查链上已锚定数据 (始终可用)
- 按需拉取: 模拟逐域查询, 不可用域触发超时
- 每组 20 次重复, 统计均值+标准差
"""

import sys, os, time, random, hashlib, statistics, json
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.merkle import MerkleTree, build_credential_leaf
from src.utils import ExperimentResult, Timer, print_header

_fisco_client = None
def _get_chain_client():
    global _fisco_client
    if _fisco_client is None:
        from src.chain.fisco_client import FISCOClient
        _fisco_client = FISCOClient()
        _fisco_client.init()
    return _fisco_client

_bls_signer = None
def _get_bls_signer():
    global _bls_signer
    if _bls_signer is None:
        from blspy import PopSchemeMPL, PrivateKey
        seed = bytes([i for i in range(32)])
        sk = PopSchemeMPL.key_gen(seed)
        pk = sk.get_g1()
        _bls_signer = {"sk": sk, "pk": pk, "MPL": PopSchemeMPL}
    return _bls_signer


def setup_domains(m, creds_per_domain=64):
    """预构建m个域的凭证数据并锚定到链上"""
    print(f"  设置 {m} 个域, 每域 {creds_per_domain} 凭证...")
    fc = _get_chain_client()
    bls = _get_bls_signer()
    epoch = int(time.time())

    domains = {}
    for d in range(m):
        domain_id = f"AVAIL_DOM_{d}_{epoch}"
        items = [
            build_credential_leaf(domain_id, epoch, f"did:exp:{d}_{i}", "Active",
                                  hashlib.sha256(f"commit_{d}_{i}_{epoch}".encode()).digest())
            for i in range(creds_per_domain)
        ]
        tree = MerkleTree()
        root = tree.build(items, sort=False)

        msg = hashlib.sha256(root + domain_id.encode()).digest()
        sig = bls["MPL"].sign(bls["sk"], msg)

        sig_bytes = bytes(sig)[:48] if len(bytes(sig)) >= 48 else bytes(sig).ljust(48, b"\x00")
        _, anchor_ms = fc.anchor_domain_root(domain_id, epoch, root, sig_bytes, creds_per_domain)

        target_idx = random.randint(0, creds_per_domain - 1)
        proof = tree.get_proof(target_idx)

        domains[d] = {
            "domain_id": domain_id, "epoch": epoch,
            "tree": tree, "root": root, "proof": proof,
            "target_idx": target_idx, "target_leaf": tree.leaves[target_idx],
            "msg": msg, "sig": sig, "anchor_ms": anchor_ms,
        }
        print(f"    域{d} ({domain_id}): 锚定 {anchor_ms:.1f}ms")

    return domains, epoch


def hfa_did_verify(fc, domains, m, epoch):
    """HFA-DID: 查链上已锚定数据, 不依赖签发域"""
    results = {"success": 0, "fail": 0, "latencies": []}
    bls = _get_bls_signer()
    for d_idx in range(m):
        dom = domains[d_idx]
        t0 = time.perf_counter()
        stored_root, _ = fc.get_domain_root(dom["domain_id"], dom["epoch"])
        merkle_ok = MerkleTree.verify_proof(dom["target_leaf"], dom["proof"], dom["root"])
        bls_ok = bls["MPL"].verify(bls["pk"], dom["msg"], dom["sig"])
        total_ms = (time.perf_counter() - t0) * 1000
        if stored_root and merkle_ok and bls_ok:
            results["success"] += 1
        else:
            results["fail"] += 1
        results["latencies"].append(total_ms)
    return results


def relay_verify(fc, domains, m, domain_available, timeout_ms=500):
    """按需拉取: 逐域查签发域, 不可用域超时"""
    results = {"success": 0, "fail": 0, "latencies": []}
    bls = _get_bls_signer()
    for d_idx in range(m):
        dom = domains[d_idx]
        if not domain_available[d_idx]:
            time.sleep(timeout_ms / 1000.0 * 0.01)
            results["fail"] += 1
            results["latencies"].append(timeout_ms)
            continue
        t0 = time.perf_counter()
        stored_root, _ = fc.get_domain_root(dom["domain_id"], dom["epoch"])
        merkle_ok = MerkleTree.verify_proof(dom["target_leaf"], dom["proof"], dom["root"])
        bls_ok = bls["MPL"].verify(bls["pk"], dom["msg"], dom["sig"])
        total_ms = (time.perf_counter() - t0) * 1000
        if stored_root and merkle_ok and bls_ok:
            results["success"] += 1
        else:
            results["fail"] += 1
        results["latencies"].append(total_ms)
    return results


def run_experiment(m=10, availability_rates=None, n_repeats=20, creds=64):
    if availability_rates is None:
        availability_rates = [1.0, 0.8, 0.6, 0.4, 0.2, 0.0]

    print_header("实验9: 签发域离线可用性对比")
    print(f"  域数量: {m}, 重复: {n_repeats}")

    fc = _get_chain_client()
    domains, epoch = setup_domains(m, creds)
    all_results = {}

    for p in availability_rates:
        print(f"\n  === 可用率 p={p:.0%} ===")
        hfa_sr, hfa_lat, relay_sr, relay_lat = [], [], [], []

        for trial in range(n_repeats):
            domain_available = [random.random() < p for _ in range(m)]
            h = hfa_did_verify(fc, domains, m, epoch)
            hfa_sr.append(h["success"] / m * 100)
            hfa_lat.append(sum(h["latencies"]))
            r = relay_verify(fc, domains, m, domain_available)
            relay_sr.append(r["success"] / m * 100)
            relay_lat.append(sum(r["latencies"]))

        all_results[p] = {
            "hfa_success_mean": float(np.mean(hfa_sr)),
            "hfa_success_std": float(np.std(hfa_sr)),
            "hfa_latency_mean": float(np.mean(hfa_lat)),
            "hfa_latency_std": float(np.std(hfa_lat)),
            "relay_success_mean": float(np.mean(relay_sr)),
            "relay_success_std": float(np.std(relay_sr)),
            "relay_latency_mean": float(np.mean(relay_lat)),
            "relay_latency_std": float(np.std(relay_lat)),
        }
        r = all_results[p]
        print(f"    HFA-DID: {r['hfa_success_mean']:.1f}% +/- {r['hfa_success_std']:.1f}%,  {r['hfa_latency_mean']:.1f} ms")
        print(f"    Relay:   {r['relay_success_mean']:.1f}% +/- {r['relay_success_std']:.1f}%,  {r['relay_latency_mean']:.1f} ms")

    results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(results_dir, exist_ok=True)
    save_data = {str(k): v for k, v in all_results.items()}
    with open(os.path.join(results_dir, "exp9_availability.json"), "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  结果保存到 results/exp9_availability.json")
    return all_results


def plot_results(results_path=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams["font.sans-serif"] = ["WenQuanYi Micro Hei", "Noto Sans CJK SC", "SimHei"]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["font.size"] = 9

    if results_path is None:
        results_path = os.path.join(os.path.dirname(__file__), "..", "results", "exp9_availability.json")
    with open(results_path) as f:
        raw = json.load(f)
    results = {float(k): v for k, v in raw.items()}

    C_HFA, C_RELAY = "#1f77b4", "#d62728"
    avail_rates = sorted(results.keys(), reverse=True)
    avail_pct = [f"{p:.0%}" for p in avail_rates]
    x = np.arange(len(avail_rates))

    hfa_succ = [results[p]["hfa_success_mean"] for p in avail_rates]
    hfa_succ_std = [results[p]["hfa_success_std"] for p in avail_rates]
    relay_succ = [results[p]["relay_success_mean"] for p in avail_rates]
    relay_succ_std = [results[p]["relay_success_std"] for p in avail_rates]
    hfa_lat = [results[p]["hfa_latency_mean"] for p in avail_rates]
    hfa_lat_std = [results[p]["hfa_latency_std"] for p in avail_rates]
    relay_lat = [results[p]["relay_latency_mean"] for p in avail_rates]
    relay_lat_std = [results[p]["relay_latency_std"] for p in avail_rates]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6, 7))

    ax1.errorbar(x, hfa_succ, yerr=hfa_succ_std, fmt="o-", color=C_HFA,
                 linewidth=2, markersize=6, capsize=4, label="HFA-DID")
    ax1.errorbar(x, relay_succ, yerr=relay_succ_std, fmt="s--", color=C_RELAY,
                 linewidth=2, markersize=6, capsize=4, markerfacecolor="none",
                 markeredgewidth=1.5, label="按需拉取")
    ax1.set_ylabel("验证成功率 (%)", fontsize=10)
    ax1.set_xticks(x); ax1.set_xticklabels(avail_pct)
    ax1.set_ylim(-5, 115)
    ax1.legend(fontsize=9, loc="center right")
    ax1.grid(linestyle="--", alpha=0.3)
    ax1.set_title("(a) 不同签发域可用率下的验证成功率", fontsize=10.5)

    ax2.errorbar(x, hfa_lat, yerr=hfa_lat_std, fmt="o-", color=C_HFA,
                 linewidth=2, markersize=6, capsize=4, label="HFA-DID")
    ax2.errorbar(x, relay_lat, yerr=relay_lat_std, fmt="s--", color=C_RELAY,
                 linewidth=2, markersize=6, capsize=4, markerfacecolor="none",
                 markeredgewidth=1.5, label="按需拉取")
    ax2.set_xlabel("签发域可用率", fontsize=10)
    ax2.set_ylabel("总验证延迟 (ms)", fontsize=10)
    ax2.set_xticks(x); ax2.set_xticklabels(avail_pct)
    ax2.legend(fontsize=9, loc="center left")
    ax2.grid(linestyle="--", alpha=0.3)
    ax2.set_title("(b) 不同签发域可用率下的验证延迟", fontsize=10.5)

    plt.tight_layout(h_pad=2.0)
    out_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    plt.savefig(os.path.join(out_dir, "exp9_availability.pdf"), dpi=300, bbox_inches="tight")
    plt.savefig(os.path.join(out_dir, "exp9_availability.png"), dpi=200, bbox_inches="tight")
    print("  图表已保存到 results/")


if __name__ == "__main__":
    results = run_experiment(
        m=10 if "--full" in sys.argv else 5,
        n_repeats=20 if "--full" in sys.argv else 5,
        creds=64 if "--full" in sys.argv else 16,
    )
    plot_results()
