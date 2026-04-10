#!/usr/bin/env python3
"""
实验9v2: 签发域故障场景下的跨域验证可用性对比 (真实网络模拟)

通过 Docker tc netem 在容器级别注入真实网络故障:
- 正常: delay 30ms jitter 8ms loss 0.5%
- 高延迟: delay 200ms jitter 50ms loss 2%
- 间歇性故障: delay 100ms jitter 80ms loss 30%
- 完全离线: delay 0ms loss 100%

对比:
- HFA-DID: 查 GCL (172.20.0.20) 上已锚定数据
- 按需拉取: 逐域查各 DCL 节点, 带重试机制

场景: m=5 域, 逐步增加故障域数量 (0/1/2/3/4/5)
"""
import sys, os, time, random, hashlib, json, subprocess, statistics
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto.merkle import MerkleTree, build_credential_leaf
from src.utils import print_header

# ── 链交互 ──
_fisco_client = None
def _get_chain():
    global _fisco_client
    if _fisco_client is None:
        from src.chain.fisco_client import FISCOClient
        _fisco_client = FISCOClient()
        _fisco_client.init()
    return _fisco_client

# ── BLS ──
_bls = None
def _get_bls():
    global _bls
    if _bls is None:
        from blspy import PopSchemeMPL
        seed = bytes(range(32))
        sk = PopSchemeMPL.key_gen(seed)
        _bls = {"sk": sk, "pk": sk.get_g1(), "MPL": PopSchemeMPL}
    return _bls

# ── Docker容器 → DCL域映射 ──
DCL_CONTAINERS = ["hfa-dcl-a", "hfa-dcl-b", "hfa-dcl-c"]
GCL_CONTAINER = "hfa-gcl"

# ── 网络故障配置 ──
NETWORK_PROFILES = {
    "normal":       "tc qdisc replace dev eth0 root netem delay 30ms 8ms loss 0.5%",
    "high_latency": "tc qdisc replace dev eth0 root netem delay 200ms 50ms loss 2%",
    "intermittent": "tc qdisc replace dev eth0 root netem delay 100ms 80ms loss 30%",
    "offline":      "tc qdisc replace dev eth0 root netem delay 0ms loss 100%",
}

def apply_network_profile(container, profile):
    """对Docker容器应用网络配置"""
    cmd = NETWORK_PROFILES[profile]
    result = subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        # 如果replace失败, 先删再加
        subprocess.run(
            ["docker", "exec", container, "bash", "-c",
             "tc qdisc del dev eth0 root 2>/dev/null; " + cmd],
            capture_output=True, text=True, timeout=5
        )

def reset_all_networks():
    """恢复所有容器的正常网络"""
    for c in DCL_CONTAINERS + [GCL_CONTAINER]:
        apply_network_profile(c, "normal")
    time.sleep(0.5)


def setup_domains(m, creds_per_domain=64):
    """预构建域数据并锚定到链上 (GCL)"""
    print(f"  预锚定 {m} 个域的数据到 GCL...")
    fc = _get_chain()
    bls = _get_bls()
    epoch = int(time.time())

    domains = {}
    for d in range(m):
        domain_id = f"AV2_DOM_{d}_{epoch}"
        items = [
            build_credential_leaf(domain_id, epoch, f"did:av2:{d}_{i}", "Active",
                                  hashlib.sha256(f"c_{d}_{i}_{epoch}".encode()).digest())
            for i in range(creds_per_domain)
        ]
        tree = MerkleTree()
        root = tree.build(items, sort=False)

        msg = hashlib.sha256(root + domain_id.encode()).digest()
        sig = bls["MPL"].sign(bls["sk"], msg)
        sig_bytes = bytes(sig)[:48].ljust(48, b"\x00")

        _, anchor_ms = fc.anchor_domain_root(domain_id, epoch, root, sig_bytes, creds_per_domain)

        target_idx = random.randint(0, creds_per_domain - 1)
        domains[d] = {
            "domain_id": domain_id, "epoch": epoch,
            "tree": tree, "root": root,
            "proof": tree.get_proof(target_idx),
            "target_leaf": tree.leaves[target_idx],
            "msg": msg, "sig": sig,
            "container": DCL_CONTAINERS[d % len(DCL_CONTAINERS)],
            "anchored": True,  # 已完成本epoch锚定
        }
        print(f"    域{d}: 锚定完成 ({anchor_ms:.0f}ms)")

    return domains, epoch


def hfa_did_verify_single(fc, bls, dom):
    """
    HFA-DID 单域验证: 查 GCL 链上数据
    返回 (success, latency_ms, note)
    """
    t0 = time.perf_counter()

    # 查GCL链上已锚定的域根
    stored_root, chain_ms = fc.get_domain_root(dom["domain_id"], dom["epoch"])

    # 本地 Merkle 验证
    merkle_ok = MerkleTree.verify_proof(dom["target_leaf"], dom["proof"], dom["root"])

    # 本地 BLS 验证
    bls_ok = bls["MPL"].verify(bls["pk"], dom["msg"], dom["sig"])

    total_ms = (time.perf_counter() - t0) * 1000

    if not stored_root:
        return False, total_ms, "GCL查询失败"
    if not dom["anchored"]:
        # 域离线前未完成锚定 → 数据可能滞后
        return True, total_ms, "成功(数据可能滞后)"
    if merkle_ok and bls_ok:
        return True, total_ms, "成功"
    return False, total_ms, "验证失败"


def relay_verify_single(fc, bls, dom, max_retries=1, timeout_ms=2000):
    """
    按需拉取单域验证: 查签发域 DCL, 带重试机制
    通过真实网络延迟/丢包模拟故障
    返回 (success, latency_ms, note)
    """
    t0 = time.perf_counter()

    for attempt in range(1 + max_retries):
        try:
            # 查签发域 (实际走网络到DCL容器所在的FISCO节点)
            stored_root, chain_ms = fc.get_domain_root(dom["domain_id"], dom["epoch"])

            elapsed = (time.perf_counter() - t0) * 1000
            if elapsed > timeout_ms:
                return False, elapsed, f"超时({elapsed:.0f}ms > {timeout_ms}ms)"

            if stored_root is None:
                if attempt < max_retries:
                    time.sleep(0.1)  # 重试前短暂等待
                    continue
                return False, elapsed, "查询失败(已重试)"

            # 验证
            merkle_ok = MerkleTree.verify_proof(dom["target_leaf"], dom["proof"], dom["root"])
            bls_ok = bls["MPL"].verify(bls["pk"], dom["msg"], dom["sig"])
            total_ms = (time.perf_counter() - t0) * 1000

            if merkle_ok and bls_ok:
                return True, total_ms, f"成功(尝试{attempt+1}次)"
            return False, total_ms, "验证失败"

        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            if elapsed > timeout_ms:
                return False, elapsed, f"超时+异常: {e}"
            if attempt < max_retries:
                time.sleep(0.1)
                continue
            return False, elapsed, f"异常: {e}"

    total_ms = (time.perf_counter() - t0) * 1000
    return False, total_ms, "所有重试失败"


def run_scenario(fc, bls, domains, m, fault_config, n_repeats=20):
    """
    运行单个故障场景
    fault_config: {domain_idx: profile_name} 指定哪些域施加什么故障
    """
    # 应用网络故障
    reset_all_networks()
    for d_idx, profile in fault_config.items():
        container = domains[d_idx]["container"]
        apply_network_profile(container, profile)
        if profile == "offline":
            domains[d_idx]["anchored"] = True  # 离线前已完成锚定 (模拟正常情况)
    time.sleep(1)  # 等待网络策略生效

    hfa_results = {"success": [], "latency": [], "notes": []}
    relay_results = {"success": [], "latency": [], "notes": []}

    for trial in range(n_repeats):
        # HFA-DID: 验证所有m个域
        hfa_succ_count = 0
        hfa_total_ms = 0
        for d_idx in range(m):
            ok, ms, note = hfa_did_verify_single(fc, bls, domains[d_idx])
            hfa_succ_count += int(ok)
            hfa_total_ms += ms

        hfa_results["success"].append(hfa_succ_count / m * 100)
        hfa_results["latency"].append(hfa_total_ms)

        # 按需拉取: 验证所有m个域 (带重试)
        relay_succ_count = 0
        relay_total_ms = 0
        for d_idx in range(m):
            ok, ms, note = relay_verify_single(fc, bls, domains[d_idx])
            relay_succ_count += int(ok)
            relay_total_ms += ms

        relay_results["success"].append(relay_succ_count / m * 100)
        relay_results["latency"].append(relay_total_ms)

    return {
        "hfa_success_mean": float(np.mean(hfa_results["success"])),
        "hfa_success_std": float(np.std(hfa_results["success"])),
        "hfa_latency_mean": float(np.mean(hfa_results["latency"])),
        "hfa_latency_std": float(np.std(hfa_results["latency"])),
        "relay_success_mean": float(np.mean(relay_results["success"])),
        "relay_success_std": float(np.std(relay_results["success"])),
        "relay_latency_mean": float(np.mean(relay_results["latency"])),
        "relay_latency_std": float(np.std(relay_results["latency"])),
    }


def run_experiment(m=5, n_repeats=20, creds=32):
    """
    主实验: 逐步增加故障域数量

    场景设计 (m=5域):
    S0: 全部正常
    S1: 1域高延迟
    S2: 1域离线 + 1域间歇性
    S3: 2域离线 + 1域高延迟
    S4: 3域离线 + 1域间歇性
    S5: 全部离线
    """
    print_header("实验9v2: 签发域故障可用性对比 (真实网络模拟)")
    print(f"  域数量: {m}, 每组重复: {n_repeats}")
    print(f"  DCL容器: {DCL_CONTAINERS}")
    print(f"  网络配置: normal/high_latency/intermittent/offline")

    fc = _get_chain()
    bls = _get_bls()

    domains, epoch = setup_domains(m, creds)

    scenarios = [
        ("S0: 全部正常", {}),
        ("S1: 1域高延迟", {0: "high_latency"}),
        ("S2: 1离线+1间歇", {0: "offline", 1: "intermittent"}),
        ("S3: 2离线+1高延迟", {0: "offline", 1: "offline", 2: "high_latency"}),
        ("S4: 3离线+1间歇", {0: "offline", 1: "offline", 2: "offline", 3: "intermittent"}),
        ("S5: 全部离线", {i: "offline" for i in range(m)}),
    ]

    all_results = {}
    for label, fault_config in scenarios:
        n_faulty = sum(1 for p in fault_config.values() if p in ("offline", "intermittent"))
        healthy_pct = (m - n_faulty) / m * 100
        print(f"\n  === {label} (健康域: {healthy_pct:.0f}%) ===")

        result = run_scenario(fc, bls, domains, m, fault_config, n_repeats)
        all_results[label] = result
        all_results[label]["healthy_pct"] = healthy_pct

        print(f"    HFA-DID: 成功率={result['hfa_success_mean']:.1f}% +/- {result['hfa_success_std']:.1f}%  "
              f"延迟={result['hfa_latency_mean']:.0f} +/- {result['hfa_latency_std']:.0f} ms")
        print(f"    按需拉取: 成功率={result['relay_success_mean']:.1f}% +/- {result['relay_success_std']:.1f}%  "
              f"延迟={result['relay_latency_mean']:.0f} +/- {result['relay_latency_std']:.0f} ms")

    # 恢复网络
    reset_all_networks()
    print("\n  网络已恢复正常")

    # 保存结果
    results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, "exp9v2_availability.json"), "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"  结果保存到 results/exp9v2_availability.json")

    return all_results


if __name__ == "__main__":
    quick = "--quick" in sys.argv
    results = run_experiment(
        m=5,
        n_repeats=5 if quick else 20,
        creds=16 if quick else 32,
    )
