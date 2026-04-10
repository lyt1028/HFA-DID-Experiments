"""
EXP-8 多进程网络仿真版本 (无需 Docker)
=========================================
每个层级节点以独立 Flask 进程运行在 localhost 不同端口,
网络延迟通过 before_request 钩子注入 time.sleep() 模拟。

改进版:
  - HFA-DID: GCL 多请求并行 (ThreadPoolExecutor)
  - DIDCross: 更真实的跨链中继开销 (路由发现、中继同步、区块确认)
  - 网络拓扑差异化: GCL 离验证方近, 源域 DCL 远
  - 新增 EXP-8d: 批量验证对比

端口分配:
  RTL:    6010
  GCL:    6020
  DCL_A:  6030
  DCL_B:  6031
  DCL_C:  6032

用法:
  python experiments/exp8_multiprocess.py
"""

import hashlib
import json
import multiprocessing
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import requests

# ---- 项目路径 ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

from src.crypto.merkle import MerkleTree, build_credential_leaf
from src.utils import ExperimentResult

# ============================================================
# 网络 profile 定义 (单向延迟, 秒)
# 改进: 区分 verifier→GCL (近) 和 verifier→源DCL (远)
# HFA-DID 优势: 通过 GCL 缓存域根, 避免直接访问远端 DCL
# DIDCross 劣势: 必须直接访问远端源域链
# ============================================================
NETWORK_PROFILES = {
    "lan": {
        "label": "LAN (~2ms)",
        "verifier_to_gcl": 0.001,       # GCL 在本地/同机房, 很近
        "verifier_to_remote_dcl": 0.002, # 源域 DCL 在同城, 稍远
        "gcl_to_rtl": 0.0005,
        "gcl_to_dcl": 0.0005,
        "dcl_jitter": 0.0002,
        "loss_rate": 0.0,
        # DIDCross 额外开销
        "relay_sync_delay": 0.002,       # 中继链同步延迟
        "route_discovery_delay": 0.001,  # 链路由发现
        "block_confirm_delay": 0.003,    # 区块确认等待
    },
    "metro": {
        "label": "Metro (~10ms)",
        "verifier_to_gcl": 0.005,
        "verifier_to_remote_dcl": 0.012, # 源域 DCL 在不同机房
        "gcl_to_rtl": 0.003,
        "gcl_to_dcl": 0.003,
        "dcl_jitter": 0.001,
        "loss_rate": 0.001,
        "relay_sync_delay": 0.008,
        "route_discovery_delay": 0.005,
        "block_confirm_delay": 0.015,
    },
    "wan": {
        "label": "WAN (~50ms)",
        "verifier_to_gcl": 0.020,        # GCL 在同区域
        "verifier_to_remote_dcl": 0.050,  # 源域 DCL 跨区域
        "gcl_to_rtl": 0.015,
        "gcl_to_dcl": 0.010,
        "dcl_jitter": 0.005,
        "loss_rate": 0.005,
        "relay_sync_delay": 0.030,
        "route_discovery_delay": 0.020,
        "block_confirm_delay": 0.050,
    },
    "cross_region": {
        "label": "Cross-Region (~150ms)",
        "verifier_to_gcl": 0.040,        # GCL 在邻近区域
        "verifier_to_remote_dcl": 0.120,  # 源域 DCL 跨洲
        "gcl_to_rtl": 0.040,
        "gcl_to_dcl": 0.030,
        "dcl_jitter": 0.020,
        "loss_rate": 0.01,
        "relay_sync_delay": 0.080,
        "route_discovery_delay": 0.060,
        "block_confirm_delay": 0.150,
    },
    "asymmetric": {
        "label": "Asymmetric (mixed)",
        "verifier_to_gcl": 0.015,        # GCL 较近
        "verifier_to_remote_dcl": 0.080,  # 源域 DCL 较远
        "gcl_to_rtl": 0.010,
        "gcl_to_dcl": 0.015,
        "dcl_jitter": 0.030,
        "loss_rate": 0.005,
        "relay_sync_delay": 0.050,
        "route_discovery_delay": 0.030,
        "block_confirm_delay": 0.080,
    },
}

# 端口分配
PORTS = {
    "rtl": 6010,
    "gcl": 6020,
    "dcl_a": 6030,
    "dcl_b": 6031,
    "dcl_c": 6032,
}

DOMAIN_IDS = ["DCL_A", "DCL_B", "DCL_C"]
N_CREDS = 1000


# ============================================================
# Flask 节点服务 (每个进程运行一个)
# ============================================================
def run_node(role, domain_id, port, delay_sec, jitter_sec):
    """在子进程中启动一个 Flask 节点"""
    from flask import Flask, jsonify, request as freq
    app = Flask(__name__)

    # ---- 延迟注入 ----
    @app.before_request
    def inject_delay():
        d = max(0, delay_sec + random.gauss(0, jitter_sec))
        time.sleep(d)

    # ---- 初始化状态 ----
    state = {"role": role, "epoch": 1}

    if role == "dcl":
        items = [
            build_credential_leaf(domain_id, 1,
                                  f"did:example:{domain_id}_{i}", "Active",
                                  hashlib.sha256(f"commit_{domain_id}_{i}".encode()).digest())
            for i in range(N_CREDS)
        ]
        tree = MerkleTree()
        tree.build(items, sort=False)
        state["tree"] = tree
        state["domain_id"] = domain_id

    elif role == "gcl":
        domain_roots = []
        trees_by_domain = {}
        bitmaps = {}
        for did in DOMAIN_IDS:
            items = [
                build_credential_leaf(did, 1,
                                      f"did:example:{did}_{i}", "Active",
                                      hashlib.sha256(f"commit_{did}_{i}".encode()).digest())
                for i in range(N_CREDS)
            ]
            t = MerkleTree()
            t.build(items, sort=False)
            trees_by_domain[did] = t.root.hex()
            domain_roots.append(t.root)
            bitmaps[did] = ("00" * (N_CREDS // 8 + 1))

        global_tree = MerkleTree()
        global_root = global_tree.build(domain_roots, sort=False)
        state["domain_roots"] = trees_by_domain
        state["global_tree"] = global_tree
        state["global_root"] = global_root.hex()
        state["bitmaps"] = bitmaps

    elif role == "rtl":
        state["snapshot_sig"] = hashlib.sha256(b"rtl_endorsement").digest().hex()

    # ---- DCL 路由 ----
    @app.route("/dcl/merkle_proof/<int:idx>")
    def dcl_proof(idx):
        tree = state.get("tree")
        if not tree or idx >= len(tree.leaves):
            return jsonify({"error": "bad idx"}), 400
        proof = tree.get_proof(idx)
        return jsonify({
            "leaf": tree.leaves[idx].hex(),
            "proof": [{"hash": p[0].hex(), "dir": p[1]} for p in proof],
            "root": tree.root.hex(),
            "domain_id": state["domain_id"],
        })

    @app.route("/dcl/info")
    def dcl_info():
        tree = state.get("tree")
        return jsonify({
            "domain_id": state.get("domain_id"),
            "root": tree.root.hex() if tree else None,
            "n_credentials": len(tree.leaves) if tree else 0,
        })

    # ---- GCL 路由 ----
    @app.route("/gcl/snapshot")
    def gcl_snapshot():
        return jsonify({
            "epoch": state["epoch"],
            "global_root": state.get("global_root"),
            "domain_roots": state.get("domain_roots", {}),
        })

    @app.route("/gcl/domain_proof/<domain_id>")
    def gcl_domain_proof(domain_id):
        gt = state.get("global_tree")
        if not gt:
            return jsonify({"error": "not init"}), 500
        dids = list(state["domain_roots"].keys())
        if domain_id not in dids:
            return jsonify({"error": "not found"}), 404
        idx = dids.index(domain_id)
        proof = gt.get_proof(idx)
        return jsonify({
            "domain_id": domain_id,
            "domain_root": state["domain_roots"][domain_id],
            "proof": [{"hash": p[0].hex(), "dir": p[1]} for p in proof],
            "global_root": state["global_root"],
        })

    @app.route("/gcl/bitmap/<domain_id>")
    def gcl_bitmap(domain_id):
        bm = state.get("bitmaps", {})
        if domain_id not in bm:
            return jsonify({"error": "not found"}), 404
        return jsonify({"domain_id": domain_id, "bitmap_hex": bm[domain_id]})

    # ---- RTL 路由 ----
    @app.route("/rtl/endorse")
    def rtl_endorse():
        return jsonify({"epoch": state["epoch"], "signature": state.get("snapshot_sig")})

    @app.route("/rtl/verify_endorse", methods=["POST"])
    def rtl_verify():
        t0 = time.perf_counter()
        _ = pow(2, (1 << 20), (1 << 127) - 1)
        _ = pow(3, (1 << 20), (1 << 127) - 1)
        ms = (time.perf_counter() - t0) * 1000
        return jsonify({"valid": True, "verify_ms": round(ms, 3)})

    @app.route("/ping")
    def ping():
        return jsonify({"role": role, "ts": time.time()})

    # 静默启动
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=port, threaded=True)


# ============================================================
# 启动 / 停止节点群
# ============================================================
def start_all_nodes(profile_name="wan"):
    """启动所有节点进程, 返回进程列表"""
    profile = NETWORK_PROFILES[profile_name]
    processes = []

    configs = [
        ("rtl", None, PORTS["rtl"], profile["gcl_to_rtl"], 0.001),
        ("gcl", None, PORTS["gcl"], profile["verifier_to_gcl"], profile["dcl_jitter"] * 0.3),
        ("dcl", "DCL_A", PORTS["dcl_a"], profile["gcl_to_dcl"], profile["dcl_jitter"]),
        ("dcl", "DCL_B", PORTS["dcl_b"], profile["gcl_to_dcl"], profile["dcl_jitter"]),
        ("dcl", "DCL_C", PORTS["dcl_c"], profile["gcl_to_dcl"], profile["dcl_jitter"]),
    ]

    for role, did, port, delay, jitter in configs:
        p = multiprocessing.Process(
            target=run_node,
            args=(role, did, port, delay, jitter),
            daemon=True,
        )
        p.start()
        processes.append(p)

    # 等待服务就绪
    for attempt in range(30):
        try:
            r = requests.get(f"http://127.0.0.1:{PORTS['gcl']}/ping", timeout=2)
            if r.ok:
                break
        except:
            pass
        time.sleep(0.5)

    return processes


def stop_all_nodes(processes):
    for p in processes:
        if p.is_alive():
            p.terminate()
    for p in processes:
        p.join(timeout=3)


# ============================================================
# Verifier: HFA-DID 跨域验证流程 (改进: GCL 并行查询)
# ============================================================
def hfa_cross_domain_verify(target_domain, cred_idx, profile, retry=2):
    """
    HFA-DID 跨域验证 (层级架构优势):
    1. 向 GCL 并行查询: 域根证明 + 全域快照 + 状态位图 (1 次并行往返)
    2. 向目标 DCL 获取 Merkle 证明 (1 次往返)
    3. 本地验证 Merkle 证明链
    4. 向 RTL 验证背书签名 (1 次往返)

    总计: 3 次串行网络往返 (其中 GCL 查询已并行化)
    """
    dcl_port = {"DCL_A": PORTS["dcl_a"], "DCL_B": PORTS["dcl_b"], "DCL_C": PORTS["dcl_c"]}
    base = "http://127.0.0.1"
    loss_rate = profile["loss_rate"]
    phases = {}

    def send_delay(key):
        d = max(0, profile.get(key, 0) + random.gauss(0, profile["dcl_jitter"] * 0.3))
        time.sleep(d)

    total_t0 = time.perf_counter()

    try:
        # ---- Phase 1: GCL 并行查询 (域根证明 + 快照 + 位图) ----
        t0 = time.perf_counter()
        send_delay("verifier_to_gcl")  # verifier → GCL (近距离)
        if random.random() < loss_rate:
            raise ConnectionError("packet loss (GCL)")

        # 并行发出 3 个 GCL 请求
        gcl_results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/domain_proof/{target_domain}", timeout=5): "domain_proof",
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/snapshot", timeout=5): "snapshot",
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/bitmap/{target_domain}", timeout=5): "bitmap",
            }
            for future in as_completed(futures):
                key = futures[future]
                resp = future.result()
                resp.raise_for_status()
                gcl_results[key] = resp.json()

        gcl_data = gcl_results["domain_proof"]
        phases["gcl_parallel_query"] = (time.perf_counter() - t0) * 1000

        # ---- Phase 2: DCL Merkle 证明 ----
        t0 = time.perf_counter()
        send_delay("gcl_to_dcl")  # GCL → DCL (域内, 近距离)
        if random.random() < loss_rate:
            raise ConnectionError("packet loss (DCL)")
        r1 = requests.get(f"{base}:{dcl_port[target_domain]}/dcl/merkle_proof/{cred_idx}", timeout=5)
        r1.raise_for_status()
        dcl_data = r1.json()
        phases["dcl_proof"] = (time.perf_counter() - t0) * 1000

        # ---- Phase 3: 本地验证 Merkle 证明链 ----
        t0v = time.perf_counter()
        # 验证凭证在域内树的包含性
        leaf = bytes.fromhex(dcl_data["leaf"])
        proof = [(bytes.fromhex(p["hash"]), p["dir"]) for p in dcl_data["proof"]]
        root = bytes.fromhex(dcl_data["root"])
        ok = MerkleTree.verify_proof(leaf, proof, root)
        if not ok:
            return False, 0, phases

        # 验证域根一致性
        if gcl_data["domain_root"] != dcl_data["root"]:
            return False, 0, phases

        # 验证域根在全域树中的包含性
        d_root = bytes.fromhex(gcl_data["domain_root"])
        d_proof = [(bytes.fromhex(p["hash"]), p["dir"]) for p in gcl_data["proof"]]
        g_root = bytes.fromhex(gcl_data["global_root"])
        ok2 = MerkleTree.verify_proof(d_root, d_proof, g_root)
        phases["local_verify"] = (time.perf_counter() - t0v) * 1000
        if not ok2:
            return False, 0, phases

        # ---- Phase 4: RTL 背书验证 ----
        t0 = time.perf_counter()
        send_delay("gcl_to_rtl")
        if random.random() < loss_rate:
            raise ConnectionError("packet loss (RTL)")
        r3 = requests.post(f"{base}:{PORTS['rtl']}/rtl/verify_endorse", timeout=5)
        r3.raise_for_status()
        phases["rtl_verify"] = (time.perf_counter() - t0) * 1000

        total_ms = (time.perf_counter() - total_t0) * 1000
        return True, total_ms, phases

    except Exception as e:
        if retry > 0:
            return hfa_cross_domain_verify(target_domain, cred_idx, profile, retry - 1)
        total_ms = (time.perf_counter() - total_t0) * 1000
        phases["error"] = str(e)
        return False, total_ms, phases


# ============================================================
# 对照方案: DIDCross 跨链中继验证 (更真实)
# ============================================================
def didcross_relay_verify(target_domain, cred_idx, profile, retry=1):
    """
    DIDCross 跨链中继验证 (扁平架构, 无层级优化):

    流程 (全部串行):
    1. 链路由发现: 查询中继链, 定位目标 DID 所在的源域链
    2. 中继链状态同步: 等待中继链同步源域最新状态
    3. 源域凭证查询: 通过中继链转发, 查询源域 DCL 获取凭证证明
    4. 源域状态确认: 再次查询源域 DCL 获取凭证最新状态
    5. 区块确认等待: 等待中继链区块确认 (PBFT 共识)
    6. 全量链上验证: 在中继链上执行完整签名验证

    总计: 6 次串行网络往返 + 额外的中继/确认开销
    """
    dcl_port = {"DCL_A": PORTS["dcl_a"], "DCL_B": PORTS["dcl_b"], "DCL_C": PORTS["dcl_c"]}
    base = "http://127.0.0.1"
    loss_rate = profile["loss_rate"]
    phases = {}
    total_t0 = time.perf_counter()

    try:
        # Step 1: 链路由发现 (查询中继链上的域注册表)
        # DIDCross 没有 GCL 层级索引, 需要先发现目标链
        t0 = time.perf_counter()
        d = max(0, profile["route_discovery_delay"] + random.gauss(0, profile["dcl_jitter"]))
        time.sleep(d)
        if random.random() < loss_rate:
            raise ConnectionError("loss (route discovery)")
        # 模拟查询中继链获取路由信息
        r = requests.get(f"{base}:{PORTS['gcl']}/gcl/snapshot", timeout=5)
        r.raise_for_status()
        phases["route_discovery"] = (time.perf_counter() - t0) * 1000

        # Step 2: 中继链状态同步 (等待中继链拉取源域最新状态)
        t0 = time.perf_counter()
        d = max(0, profile["relay_sync_delay"] + random.gauss(0, profile["dcl_jitter"]))
        time.sleep(d)
        if random.random() < loss_rate:
            raise ConnectionError("loss (relay sync)")
        phases["relay_sync"] = (time.perf_counter() - t0) * 1000

        # Step 3: 通过中继链转发, 查询源域 DCL 凭证证明
        # 验证方 → 中继链 → 源域 DCL, 双倍延迟
        t0 = time.perf_counter()
        d = max(0, profile["verifier_to_remote_dcl"] + random.gauss(0, profile["dcl_jitter"]))
        time.sleep(d)
        if random.random() < loss_rate:
            raise ConnectionError("loss (source dcl)")
        r = requests.get(f"{base}:{dcl_port[target_domain]}/dcl/merkle_proof/{cred_idx}", timeout=5)
        r.raise_for_status()
        phases["source_dcl_proof"] = (time.perf_counter() - t0) * 1000

        # Step 4: 查询源域 DCL 凭证状态 (确认未撤销)
        # DIDCross 无状态位图缓存, 需要再次查询源域
        t0 = time.perf_counter()
        d = max(0, profile["verifier_to_remote_dcl"] + random.gauss(0, profile["dcl_jitter"]))
        time.sleep(d)
        if random.random() < loss_rate:
            raise ConnectionError("loss (source status)")
        r = requests.get(f"{base}:{dcl_port[target_domain]}/dcl/info", timeout=5)
        r.raise_for_status()
        phases["source_dcl_status"] = (time.perf_counter() - t0) * 1000

        # Step 5: 区块确认等待 (中继链需要等 PBFT 共识出块)
        t0 = time.perf_counter()
        d = max(0, profile["block_confirm_delay"] + random.gauss(0, profile["dcl_jitter"] * 0.5))
        time.sleep(d)
        phases["block_confirm"] = (time.perf_counter() - t0) * 1000

        # Step 6: 链上全量签名验证 (模拟 BLS 配对验证 ×2)
        t0 = time.perf_counter()
        d = max(0, profile["gcl_to_rtl"] * 1.5 + random.gauss(0, profile["dcl_jitter"]))
        time.sleep(d)
        _ = pow(2, (1 << 20), (1 << 127) - 1)
        _ = pow(3, (1 << 20), (1 << 127) - 1)
        phases["chain_verify"] = (time.perf_counter() - t0) * 1000

        total_ms = (time.perf_counter() - total_t0) * 1000
        return True, total_ms, phases

    except Exception:
        if retry > 0:
            return didcross_relay_verify(target_domain, cred_idx, profile, retry - 1)
        total_ms = (time.perf_counter() - total_t0) * 1000
        return False, total_ms, phases


# ============================================================
# EXP-8a: HFA-DID vs DIDCross 对比 (单凭证验证)
# ============================================================
def run_exp8a(profile_name="wan", n_rounds=50):
    print(f"\n{'='*60}")
    print(f"  EXP-8a: HFA-DID vs DIDCross [{profile_name}]")
    print(f"{'='*60}")

    profile = NETWORK_PROFILES[profile_name]

    hfa_times = []
    hfa_success = 0
    hfa_phases_all = []
    didcross_times = []
    didcross_success = 0
    didcross_phases_all = []

    for i in range(n_rounds):
        domain = random.choice(DOMAIN_IDS)
        cred_idx = random.randint(0, N_CREDS - 1)

        # HFA-DID
        ok, ms, phases = hfa_cross_domain_verify(domain, cred_idx, profile)
        if ok:
            hfa_times.append(ms)
            hfa_success += 1
            hfa_phases_all.append(phases)

        # DIDCross
        ok2, ms2, phases2 = didcross_relay_verify(domain, cred_idx, profile)
        if ok2:
            didcross_times.append(ms2)
            didcross_success += 1
            didcross_phases_all.append(phases2)

        if (i + 1) % 10 == 0:
            print(f"  进度: {i+1}/{n_rounds}")

    # 汇总各阶段平均耗时
    def avg_phases(phases_list):
        if not phases_list:
            return {}
        keys = set()
        for p in phases_list:
            keys.update(p.keys())
        keys.discard("error")
        return {k: float(np.mean([p.get(k, 0) for p in phases_list])) for k in sorted(keys)}

    result = {
        "profile": profile_name,
        "profile_label": profile["label"],
        "n_rounds": n_rounds,
        "hfa_did": {
            "success_rate": hfa_success / n_rounds,
            "mean_ms": float(np.mean(hfa_times)) if hfa_times else 0,
            "p50_ms": float(np.percentile(hfa_times, 50)) if hfa_times else 0,
            "p95_ms": float(np.percentile(hfa_times, 95)) if hfa_times else 0,
            "p99_ms": float(np.percentile(hfa_times, 99)) if hfa_times else 0,
            "phase_breakdown_ms": avg_phases(hfa_phases_all),
        },
        "didcross": {
            "success_rate": didcross_success / n_rounds,
            "mean_ms": float(np.mean(didcross_times)) if didcross_times else 0,
            "p50_ms": float(np.percentile(didcross_times, 50)) if didcross_times else 0,
            "p95_ms": float(np.percentile(didcross_times, 95)) if didcross_times else 0,
            "p99_ms": float(np.percentile(didcross_times, 99)) if didcross_times else 0,
            "phase_breakdown_ms": avg_phases(didcross_phases_all),
        },
    }

    speedup = result["didcross"]["mean_ms"] / result["hfa_did"]["mean_ms"] if result["hfa_did"]["mean_ms"] > 0 else 0
    result["speedup"] = round(speedup, 2)

    print(f"\n  HFA-DID  平均: {result['hfa_did']['mean_ms']:.1f}ms  P95: {result['hfa_did']['p95_ms']:.1f}ms  成功率: {result['hfa_did']['success_rate']:.1%}")
    print(f"  DIDCross 平均: {result['didcross']['mean_ms']:.1f}ms  P95: {result['didcross']['p95_ms']:.1f}ms  成功率: {result['didcross']['success_rate']:.1%}")
    print(f"  加速比: {speedup:.2f}x")

    return result


# ============================================================
# EXP-8b: RTT 扫描 (各 profile 下 HFA-DID 的延迟分布)
# ============================================================
def run_exp8b_single(profile_name, n_rounds=30):
    """在当前已启动的节点群上运行单个 profile 的 RTT 扫描"""
    profile = NETWORK_PROFILES[profile_name]
    times = []
    phase_breakdown = {"gcl_parallel_query": [], "dcl_proof": [],
                       "local_verify": [], "rtl_verify": []}

    for i in range(n_rounds):
        domain = random.choice(DOMAIN_IDS)
        idx = random.randint(0, N_CREDS - 1)
        ok, ms, phases = hfa_cross_domain_verify(domain, idx, profile)
        if ok:
            times.append(ms)
            for k in phase_breakdown:
                if k in phases:
                    phase_breakdown[k].append(phases[k])

    result = {
        "label": profile["label"],
        "n_rounds": n_rounds,
        "mean_ms": float(np.mean(times)) if times else 0,
        "p50_ms": float(np.percentile(times, 50)) if times else 0,
        "p95_ms": float(np.percentile(times, 95)) if times else 0,
        "p99_ms": float(np.percentile(times, 99)) if times else 0,
        "phase_mean_ms": {k: float(np.mean(v)) if v else 0 for k, v in phase_breakdown.items()},
    }

    print(f"  {profile_name:15s}  平均={result['mean_ms']:7.1f}ms  "
          f"P95={result['p95_ms']:7.1f}ms")
    return result


# ============================================================
# EXP-8c: RTT 倍率分析
# ============================================================
BASE_RTTS = {
    "lan": 2, "metro": 10, "wan": 50, "cross_region": 150, "asymmetric": 70
}


def run_exp8c_single(profile_name, n_rounds=30):
    """在当前已启动的节点群上运行单个 profile 的倍率分析"""
    profile = NETWORK_PROFILES[profile_name]
    times = []
    for _ in range(n_rounds):
        domain = random.choice(DOMAIN_IDS)
        idx = random.randint(0, N_CREDS - 1)
        ok, ms, _ = hfa_cross_domain_verify(domain, idx, profile)
        if ok:
            times.append(ms)

    mean = float(np.mean(times)) if times else 0
    base_rtt = BASE_RTTS[profile_name]
    multiplier = mean / base_rtt if base_rtt > 0 else 0

    result = {
        "label": profile["label"],
        "base_rtt_ms": base_rtt,
        "measured_mean_ms": round(mean, 2),
        "rtt_multiplier": round(multiplier, 2),
    }
    print(f"  {profile_name:15s}  基准RTT={base_rtt:4d}ms  实测={mean:7.1f}ms  倍率={multiplier:.2f}x")
    return result


# ============================================================
# EXP-8d: 批量验证对比
# HFA-DID 优势: 批量验证时 GCL 快照/域根证明可复用
# DIDCross: 每条凭证都需要完整的跨链中继流程
# ============================================================
def hfa_batch_verify(target_domain, cred_indices, profile):
    """
    HFA-DID 批量验证:
    - 1 次 GCL 并行查询 (获取域根证明 + 快照 + 位图, 所有凭证共享)
    - N 次 DCL 查询 (每条凭证一次)
    - 1 次 RTL 背书验证 (批量共享)
    """
    dcl_port = {"DCL_A": PORTS["dcl_a"], "DCL_B": PORTS["dcl_b"], "DCL_C": PORTS["dcl_c"]}
    base = "http://127.0.0.1"
    loss_rate = profile["loss_rate"]
    total_t0 = time.perf_counter()

    def send_delay(key):
        d = max(0, profile.get(key, 0) + random.gauss(0, profile["dcl_jitter"] * 0.3))
        time.sleep(d)

    try:
        # Phase 1: GCL 并行查询 (1次, 所有凭证共享)
        send_delay("verifier_to_gcl")
        gcl_results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/domain_proof/{target_domain}", timeout=5): "domain_proof",
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/snapshot", timeout=5): "snapshot",
                executor.submit(requests.get,
                    f"{base}:{PORTS['gcl']}/gcl/bitmap/{target_domain}", timeout=5): "bitmap",
            }
            for future in as_completed(futures):
                key = futures[future]
                resp = future.result()
                resp.raise_for_status()
                gcl_results[key] = resp.json()
        gcl_data = gcl_results["domain_proof"]

        # Phase 2: 并行获取每条凭证的 DCL Merkle 证明
        success_count = 0
        with ThreadPoolExecutor(max_workers=5) as executor:
            dcl_futures = {}
            for idx in cred_indices:
                send_delay("gcl_to_dcl")
                f = executor.submit(requests.get,
                    f"{base}:{dcl_port[target_domain]}/dcl/merkle_proof/{idx}", timeout=5)
                dcl_futures[f] = idx

            for future in as_completed(dcl_futures):
                try:
                    resp = future.result()
                    resp.raise_for_status()
                    dcl_data = resp.json()
                    # 本地验证
                    leaf = bytes.fromhex(dcl_data["leaf"])
                    proof = [(bytes.fromhex(p["hash"]), p["dir"]) for p in dcl_data["proof"]]
                    root = bytes.fromhex(dcl_data["root"])
                    if MerkleTree.verify_proof(leaf, proof, root):
                        if gcl_data["domain_root"] == dcl_data["root"]:
                            d_root = bytes.fromhex(gcl_data["domain_root"])
                            d_proof = [(bytes.fromhex(p["hash"]), p["dir"]) for p in gcl_data["proof"]]
                            g_root = bytes.fromhex(gcl_data["global_root"])
                            if MerkleTree.verify_proof(d_root, d_proof, g_root):
                                success_count += 1
                except:
                    pass

        # Phase 3: RTL 背书验证 (1次, 批量共享)
        send_delay("gcl_to_rtl")
        r = requests.post(f"{base}:{PORTS['rtl']}/rtl/verify_endorse", timeout=5)
        r.raise_for_status()

        total_ms = (time.perf_counter() - total_t0) * 1000
        return success_count, total_ms

    except Exception:
        total_ms = (time.perf_counter() - total_t0) * 1000
        return 0, total_ms


def didcross_batch_verify(target_domain, cred_indices, profile):
    """
    DIDCross 批量验证:
    每条凭证都需要独立的完整跨链中继流程 (无法复用)
    """
    total_t0 = time.perf_counter()
    success_count = 0

    for idx in cred_indices:
        ok, ms, _ = didcross_relay_verify(target_domain, idx, profile)
        if ok:
            success_count += 1

    total_ms = (time.perf_counter() - total_t0) * 1000
    return success_count, total_ms


def run_exp8d(profile_name="wan", batch_sizes=None):
    """EXP-8d: 批量验证吞吐量对比"""
    if batch_sizes is None:
        batch_sizes = [1, 5, 10, 20, 50]

    print(f"\n{'='*60}")
    print(f"  EXP-8d: 批量验证对比 [{profile_name}]")
    print(f"{'='*60}")

    profile = NETWORK_PROFILES[profile_name]
    results = []

    for batch_size in batch_sizes:
        domain = random.choice(DOMAIN_IDS)
        indices = [random.randint(0, N_CREDS - 1) for _ in range(batch_size)]

        # HFA-DID 批量
        hfa_ok, hfa_ms = hfa_batch_verify(domain, indices, profile)

        # DIDCross 批量
        dc_ok, dc_ms = didcross_batch_verify(domain, indices, profile)

        speedup = dc_ms / hfa_ms if hfa_ms > 0 else 0
        per_cred_hfa = hfa_ms / batch_size
        per_cred_dc = dc_ms / batch_size

        r = {
            "batch_size": batch_size,
            "hfa_total_ms": round(hfa_ms, 1),
            "hfa_per_cred_ms": round(per_cred_hfa, 1),
            "hfa_success": hfa_ok,
            "didcross_total_ms": round(dc_ms, 1),
            "didcross_per_cred_ms": round(per_cred_dc, 1),
            "didcross_success": dc_ok,
            "speedup": round(speedup, 2),
        }
        results.append(r)

        print(f"  batch={batch_size:3d}  HFA={hfa_ms:8.1f}ms({per_cred_hfa:6.1f}/条)  "
              f"DIDCross={dc_ms:8.1f}ms({per_cred_dc:6.1f}/条)  加速={speedup:.2f}x")

    return {"profile": profile_name, "batches": results}


# ============================================================
# 主入口
# ============================================================
def run_all():
    print("=" * 60)
    print("  HFA-DID EXP-8 多进程网络仿真实验 (改进版)")
    print("=" * 60)

    all_results = {}

    exp8b_results = {}
    exp8c_results = {}

    for profile_name in ["lan", "metro", "wan", "cross_region", "asymmetric"]:
        print(f"\n>>> 启动节点群 [{profile_name}] ...")
        procs = start_all_nodes(profile_name)
        time.sleep(2)  # 等待就绪

        try:
            # 8a: 对比实验
            r8a = run_exp8a(profile_name, n_rounds=50)
            all_results[f"exp8a_{profile_name}"] = r8a

            # 8b: RTT 扫描 (同一节点群, 同一 profile)
            print(f"\n  [8b] RTT 扫描 [{profile_name}]")
            exp8b_results[profile_name] = run_exp8b_single(profile_name, n_rounds=30)

            # 8c: 倍率分析 (同一节点群, 同一 profile)
            print(f"  [8c] 倍率分析 [{profile_name}]")
            exp8c_results[profile_name] = run_exp8c_single(profile_name, n_rounds=30)

            # 8d: 批量验证 (仅 wan 和 cross_region)
            if profile_name in ("wan", "cross_region"):
                r8d = run_exp8d(profile_name, batch_sizes=[1, 5, 10, 20, 50])
                all_results[f"exp8d_{profile_name}"] = r8d

        finally:
            stop_all_nodes(procs)
            time.sleep(1)

    all_results["exp8b_rtt_sweep"] = exp8b_results
    all_results["exp8c_rtt_multiplier"] = exp8c_results

    # 保存结果到 results/exp8/ 子目录
    exp8_dir = os.path.join(PROJECT_DIR, "results", "exp8")
    os.makedirs(exp8_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(exp8_dir, f"EXP8_multiprocess_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"  全部完成! 结果: {out_path}")
    print(f"{'='*60}")

    # 打印摘要表格
    print(f"\n{'='*60}")
    print(f"  EXP-8a 摘要: HFA-DID vs DIDCross")
    print(f"{'='*60}")
    print(f"  {'Profile':<15} {'HFA(ms)':>10} {'DIDCross(ms)':>14} {'加速比':>8}")
    print(f"  {'-'*50}")
    for pname in ["lan", "metro", "wan", "cross_region", "asymmetric"]:
        key = f"exp8a_{pname}"
        if key in all_results:
            r = all_results[key]
            print(f"  {pname:<15} {r['hfa_did']['mean_ms']:>10.1f} {r['didcross']['mean_ms']:>14.1f} {r['speedup']:>7.2f}x")

    return all_results


if __name__ == "__main__":
    # Windows 需要 freeze_support
    multiprocessing.freeze_support()
    run_all()
