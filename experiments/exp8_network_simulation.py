"""
实验8: 基于 Docker + tc netem 的半真实网络仿真跨域验证实验
对应论文 5.3.3 节补充实验

目标:
  在 Docker 容器间注入真实网络延迟/抖动/丢包, 测量 HFA-DID 与 DIDCross
  在不同网络条件下的跨域验证端到端延迟, 验证 HFA-DID 的延迟优势在真实
  网络环境中仍然成立.

前置条件:
  1. docker compose up -d          # 启动 6 个容器
  2. bash setup_network.sh <profile> # 注入网络条件
  3. docker exec hfa-verifier python experiments/exp8_network_simulation.py

网络 profile 对照:
  lan          → RTT ~2ms    (同机房基准)
  metro        → RTT ~10ms   (同城跨机房)
  wan          → RTT ~50ms   (跨城市广域网)
  cross_region → RTT ~150ms  (跨地域)
  asymmetric   → 异构 (各域延迟差异大)
"""

import hashlib
import json
import os
import random
import statistics
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.merkle import MerkleTree
from src.utils import ExperimentResult

# ---- 服务地址 ----
RTL_URL = "http://172.20.0.10:5000"
GCL_URL = "http://172.20.0.20:5000"
DCL_URLS = {
    "DCL_A": "http://172.20.0.30:5000",
    "DCL_B": "http://172.20.0.40:5000",
    "DCL_C": "http://172.20.0.50:5000",
}
DOMAIN_IDS = list(DCL_URLS.keys())
N_CREDS = 1000


def _timed_get(url, timeout=10):
    """发送 GET 请求, 返回 (json_data, elapsed_ms)"""
    t0 = time.perf_counter()
    resp = requests.get(url, timeout=timeout)
    elapsed = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    return resp.json(), elapsed


def _timed_post(url, data=None, timeout=10):
    """发送 POST 请求, 返回 (json_data, elapsed_ms)"""
    t0 = time.perf_counter()
    resp = requests.post(url, json=data or {}, timeout=timeout)
    elapsed = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    return resp.json(), elapsed


def measure_rtt():
    """测量验证方到各服务的实际 RTT"""
    print("\n=== 网络 RTT 测量 ===")
    targets = {"RTL": RTL_URL, "GCL": GCL_URL}
    targets.update({k: v for k, v in DCL_URLS.items()})
    results = {}
    for name, url in targets.items():
        rtts = []
        for _ in range(10):
            _, ms = _timed_get(f"{url}/ping")
            rtts.append(ms)
        avg = statistics.mean(rtts)
        p95 = sorted(rtts)[int(len(rtts) * 0.95)]
        results[name] = {'avg_ms': round(avg, 2), 'p95_ms': round(p95, 2)}
        print(f"  {name:8s}: avg={avg:.2f}ms, p95={p95:.2f}ms")
    return results


# ============================================================
# HFA-DID 跨域验证 (1 RTT to GCL + 本地验证)
# ============================================================

def hfadid_cross_domain_verify(domain_id, cred_idx):
    """
    HFA-DID 完整跨域验证流程, 每次调用产生真实网络请求
    返回 dict: 各阶段延迟 (ms) + 总延迟
    """
    stages = {}

    # Step 1: 从 GCL 获取全域快照 (1 RTT)
    snapshot, ms = _timed_get(f"{GCL_URL}/gcl/snapshot")
    stages['gcl_snapshot'] = ms

    # Step 2: 从 GCL 获取目标域在全域树中的证明 (1 RTT)
    domain_proof_data, ms = _timed_get(f"{GCL_URL}/gcl/domain_proof/{domain_id}")
    stages['gcl_domain_proof'] = ms

    # Step 3: 从 GCL 获取撤销状态位图 (1 RTT, 可与 Step2 合并, 此处分开测量)
    bitmap_data, ms = _timed_get(f"{GCL_URL}/gcl/bitmap/{domain_id}")
    stages['gcl_bitmap'] = ms

    # Step 4: 从 RTL 获取背书签名 (1 RTT)
    endorse_data, ms = _timed_get(f"{RTL_URL}/rtl/endorse")
    stages['rtl_endorse'] = ms

    # Step 5: 本地 Merkle 验证 (无网络)
    t0 = time.perf_counter()
    # 验证域根在全域树中的包含性
    domain_root = bytes.fromhex(domain_proof_data['domain_root'])
    global_proof = [(bytes.fromhex(p['hash']), p['dir']) for p in domain_proof_data['proof']]
    global_root = bytes.fromhex(domain_proof_data['global_root'])
    global_valid = MerkleTree.verify_proof(domain_root, global_proof, global_root)
    # 验证快照根与全域根一致
    snapshot_valid = (snapshot['global_root'] == domain_proof_data['global_root'])
    stages['local_verify'] = (time.perf_counter() - t0) * 1000

    # Step 6: 本地撤销位查询 (O(1))
    t0 = time.perf_counter()
    bitmap_bytes = bytes.fromhex(bitmap_data['bitmap_hex'])
    byte_idx = cred_idx // 8
    bit_idx = cred_idx % 8
    revoked = bool(bitmap_bytes[byte_idx] & (1 << bit_idx)) if byte_idx < len(bitmap_bytes) else False
    stages['bitmap_check'] = (time.perf_counter() - t0) * 1000

    stages['total'] = sum(stages.values())
    stages['valid'] = global_valid and snapshot_valid and not revoked
    return stages


# ============================================================
# DIDCross 跨域验证 (模拟多 RTT 的 SPV 验证)
# ============================================================

def didcross_cross_domain_verify(domain_id, cred_idx):
    """
    模拟 DIDCross SPV 轻客户端跨域验证流程:
      - 需要从源域获取区块头 + SPV 证明 (多次 RTT)
      - 需要跨链中继头同步
    通过直接请求源域 DCL 容器来产生真实网络延迟
    """
    stages = {}
    dcl_url = DCL_URLS[domain_id]

    # Step 1: 从源域获取凭证 Merkle 证明 (1 RTT to source DCL)
    proof_data, ms = _timed_get(f"{dcl_url}/dcl/merkle_proof/{cred_idx}")
    stages['source_merkle_proof'] = ms

    # Step 2: 从源域获取域信息 / 区块头 (1 RTT to source DCL)
    info_data, ms = _timed_get(f"{dcl_url}/dcl/info")
    stages['source_block_header'] = ms

    # Step 3: 跨链中继头同步 — 通过 GCL 中继 (1 RTT to GCL)
    _, ms = _timed_get(f"{GCL_URL}/gcl/snapshot")
    stages['relay_header_sync'] = ms

    # Step 4: 共识摘要检查 — 再次请求源域 (1 RTT to source DCL)
    _, ms = _timed_get(f"{dcl_url}/dcl/info")
    stages['consensus_check'] = ms

    # Step 5: 本地 SPV 证明验证
    t0 = time.perf_counter()
    leaf = bytes.fromhex(proof_data['leaf'])
    proof = [(bytes.fromhex(p['hash']), p['dir']) for p in proof_data['proof']]
    root = bytes.fromhex(proof_data['root'])
    valid = MerkleTree.verify_proof(leaf, proof, root)
    # 模拟深层 SPV 重建开销 (多次哈希)
    for _ in range(50):
        hashlib.sha256(root).digest()
    stages['local_spv_verify'] = (time.perf_counter() - t0) * 1000

    stages['total'] = sum(stages.values())
    stages['valid'] = valid
    return stages


# ============================================================
# 实验 8a: 不同网络条件下 HFA-DID vs DIDCross
# ============================================================

def run_exp8a(num_trials=100):
    """
    在当前 tc netem 配置下, 对比 HFA-DID 与 DIDCross 的跨域验证延迟

    注意: 需在不同 profile 下各运行一次, 汇总结果
    """
    print("\n" + "=" * 60)
    print("实验8a: HFA-DID vs DIDCross 跨域验证 (真实网络延迟)")
    print("=" * 60)

    # 先测 RTT 基线
    rtt_results = measure_rtt()

    hfa_latencies = []
    hfa_stages_all = {k: [] for k in [
        'gcl_snapshot', 'gcl_domain_proof', 'gcl_bitmap',
        'rtl_endorse', 'local_verify', 'bitmap_check', 'total'
    ]}
    hfa_success = 0

    did_latencies = []
    did_stages_all = {k: [] for k in [
        'source_merkle_proof', 'source_block_header',
        'relay_header_sync', 'consensus_check',
        'local_spv_verify', 'total'
    ]}
    did_success = 0

    for i in range(num_trials):
        domain_id = random.choice(DOMAIN_IDS)
        cred_idx = random.randint(0, N_CREDS - 1)

        # HFA-DID
        try:
            hfa = hfadid_cross_domain_verify(domain_id, cred_idx)
            hfa_latencies.append(hfa['total'])
            for k in hfa_stages_all:
                if k in hfa:
                    hfa_stages_all[k].append(hfa[k])
            if hfa.get('valid'):
                hfa_success += 1
        except Exception as e:
            hfa_latencies.append(10000)  # 超时
            print(f"  [HFA-DID] trial {i} 失败: {e}")

        # DIDCross
        try:
            did = didcross_cross_domain_verify(domain_id, cred_idx)
            did_latencies.append(did['total'])
            for k in did_stages_all:
                if k in did:
                    did_stages_all[k].append(did[k])
            if did.get('valid'):
                did_success += 1
        except Exception as e:
            did_latencies.append(10000)
            print(f"  [DIDCross] trial {i} 失败: {e}")

        if (i + 1) % 20 == 0:
            print(f"  进度: {i + 1}/{num_trials}")

    # 统计
    def _stats(arr):
        if not arr:
            return {}
        s = sorted(arr)
        return {
            'avg': round(statistics.mean(s), 2),
            'p50': round(s[len(s) // 2], 2),
            'p95': round(s[int(len(s) * 0.95)], 2),
            'std': round(statistics.stdev(s), 2) if len(s) > 1 else 0,
        }

    print("\n--- HFA-DID 各阶段延迟 (ms) ---")
    hfa_breakdown = {}
    for k, v in hfa_stages_all.items():
        st = _stats(v)
        hfa_breakdown[k] = st
        if v:
            print(f"  {k:25s}: avg={st['avg']:8.2f}, p50={st['p50']:8.2f}, p95={st['p95']:8.2f}")
    print(f"  成功率: {hfa_success}/{num_trials} ({hfa_success / num_trials * 100:.1f}%)")

    print("\n--- DIDCross 各阶段延迟 (ms) ---")
    did_breakdown = {}
    for k, v in did_stages_all.items():
        st = _stats(v)
        did_breakdown[k] = st
        if v:
            print(f"  {k:25s}: avg={st['avg']:8.2f}, p50={st['p50']:8.2f}, p95={st['p95']:8.2f}")
    print(f"  成功率: {did_success}/{num_trials} ({did_success / num_trials * 100:.1f}%)")

    hfa_total = _stats(hfa_latencies)
    did_total = _stats(did_latencies)

    print("\n--- 总延迟对比 ---")
    print(f"  HFA-DID  : avg={hfa_total['avg']:.2f}ms, p50={hfa_total['p50']:.2f}ms, p95={hfa_total['p95']:.2f}ms")
    print(f"  DIDCross : avg={did_total['avg']:.2f}ms, p50={did_total['p50']:.2f}ms, p95={did_total['p95']:.2f}ms")
    if hfa_total['avg'] > 0:
        ratio = did_total['avg'] / hfa_total['avg']
        print(f"  DIDCross / HFA-DID = {ratio:.2f}x")

    # 保存结果
    result = ExperimentResult(
        experiment_id='EXP8a',
        experiment_name='Network Simulation: HFA-DID vs DIDCross',
        params={
            'num_trials': num_trials,
            'n_credentials': N_CREDS,
            'domains': DOMAIN_IDS,
        },
        extra={
            'rtt_baseline': rtt_results,
            'hfa_did': {
                'total_stats': hfa_total,
                'breakdown': hfa_breakdown,
                'success_rate': hfa_success / num_trials,
            },
            'didcross': {
                'total_stats': did_total,
                'breakdown': did_breakdown,
                'success_rate': did_success / num_trials,
            },
        },
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return result


# ============================================================
# 实验 8b: 网络 RTT 对验证延迟的影响 (RTT 扫描)
# ============================================================

def run_exp8b_rtt_sweep(num_trials=50):
    """
    在当前 tc 配置下测量, 需配合外部脚本多次切换 profile 运行
    本函数单次运行: 测量当前网络条件下的详细延迟分解

    完整实验流程 (在宿主机执行):
      for p in lan metro wan cross_region; do
        bash setup_network.sh $p
        sleep 2
        docker exec hfa-verifier python experiments/exp8_network_simulation.py rtt_sweep
      done
    """
    print("\n" + "=" * 60)
    print("实验8b: RTT 扫描 (当前网络条件)")
    print("=" * 60)

    rtt_results = measure_rtt()

    # HFA-DID: 只请求 GCL + RTL (不请求源域)
    hfa_network_ms = []
    hfa_local_ms = []
    for i in range(num_trials):
        domain_id = random.choice(DOMAIN_IDS)
        cred_idx = random.randint(0, N_CREDS - 1)
        stages = hfadid_cross_domain_verify(domain_id, cred_idx)
        # 网络部分: gcl_snapshot + gcl_domain_proof + gcl_bitmap + rtl_endorse
        net = stages['gcl_snapshot'] + stages['gcl_domain_proof'] + \
              stages['gcl_bitmap'] + stages['rtl_endorse']
        loc = stages['local_verify'] + stages['bitmap_check']
        hfa_network_ms.append(net)
        hfa_local_ms.append(loc)

    # DIDCross: 需要请求源域 (更多 RTT)
    did_network_ms = []
    did_local_ms = []
    for i in range(num_trials):
        domain_id = random.choice(DOMAIN_IDS)
        cred_idx = random.randint(0, N_CREDS - 1)
        stages = didcross_cross_domain_verify(domain_id, cred_idx)
        net = stages['source_merkle_proof'] + stages['source_block_header'] + \
              stages['relay_header_sync'] + stages['consensus_check']
        loc = stages['local_spv_verify']
        did_network_ms.append(net)
        did_local_ms.append(loc)

    def _s(arr):
        return round(statistics.mean(arr), 2) if arr else 0

    print(f"\n  HFA-DID  网络: {_s(hfa_network_ms):.2f}ms, 本地: {_s(hfa_local_ms):.2f}ms, "
          f"总计: {_s(hfa_network_ms) + _s(hfa_local_ms):.2f}ms")
    print(f"  DIDCross 网络: {_s(did_network_ms):.2f}ms, 本地: {_s(did_local_ms):.2f}ms, "
          f"总计: {_s(did_network_ms) + _s(did_local_ms):.2f}ms")

    summary = {
        'rtt_baseline': rtt_results,
        'hfa_did': {
            'network_avg_ms': _s(hfa_network_ms),
            'local_avg_ms': _s(hfa_local_ms),
            'total_avg_ms': _s(hfa_network_ms) + _s(hfa_local_ms),
        },
        'didcross': {
            'network_avg_ms': _s(did_network_ms),
            'local_avg_ms': _s(did_local_ms),
            'total_avg_ms': _s(did_network_ms) + _s(did_local_ms),
        },
    }

    result = ExperimentResult(
        experiment_id='EXP8b',
        experiment_name='RTT Sweep: Network vs Local Breakdown',
        params={'num_trials': num_trials},
        extra=summary,
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return summary


# ============================================================
# 实验 8c: HFA-DID 网络请求数与 RTT 倍数分析
# ============================================================

def run_exp8c_rtt_multiplier(num_trials=100):
    """
    核心论证: HFA-DID 只需 4 次 RTT (到 GCL×3 + RTL×1),
    DIDCross 需要 4 次 RTT (到源域×2 + GCL×1 + 源域×1),
    但 HFA-DID 全部请求集中在 GCL/RTL (可缓存/就近部署),
    DIDCross 必须访问源域 (跨域延迟不可避免)
    """
    print("\n" + "=" * 60)
    print("实验8c: RTT 倍数与请求路径分析")
    print("=" * 60)

    rtt = measure_rtt()

    # 统计每种方案的请求目标分布
    hfa_targets = {'GCL': 0, 'RTL': 0, 'source_DCL': 0}
    did_targets = {'GCL': 0, 'RTL': 0, 'source_DCL': 0}

    hfa_total_rtt = []
    did_total_rtt = []

    for _ in range(num_trials):
        domain_id = random.choice(DOMAIN_IDS)
        cred_idx = random.randint(0, N_CREDS - 1)

        # HFA-DID
        hfa = hfadid_cross_domain_verify(domain_id, cred_idx)
        hfa_targets['GCL'] += 3   # snapshot + domain_proof + bitmap
        hfa_targets['RTL'] += 1   # endorse
        hfa_total_rtt.append(hfa['total'])

        # DIDCross
        did = didcross_cross_domain_verify(domain_id, cred_idx)
        did_targets['source_DCL'] += 2  # merkle_proof + block_header
        did_targets['GCL'] += 1          # relay_header_sync
        did_targets['source_DCL'] += 1   # consensus_check
        did_total_rtt.append(did['total'])

    print(f"\n  HFA-DID  请求分布: {hfa_targets}")
    print(f"  DIDCross 请求分布: {did_targets}")
    print(f"\n  HFA-DID  avg total: {statistics.mean(hfa_total_rtt):.2f}ms")
    print(f"  DIDCross avg total: {statistics.mean(did_total_rtt):.2f}ms")
    print(f"\n  关键差异: HFA-DID 从不访问源域, DIDCross 每次验证需 2-3 次源域 RTT")
    print(f"  当源域位于高延迟网络时, DIDCross 延迟劣势将被放大")

    result = ExperimentResult(
        experiment_id='EXP8c',
        experiment_name='RTT Multiplier Analysis',
        params={'num_trials': num_trials},
        extra={
            'hfa_did': {
                'request_targets': hfa_targets,
                'avg_ms': round(statistics.mean(hfa_total_rtt), 2),
            },
            'didcross': {
                'request_targets': did_targets,
                'avg_ms': round(statistics.mean(did_total_rtt), 2),
            },
            'rtt_baseline': rtt,
        },
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return result


# ============================================================
# 入口
# ============================================================

def run_all():
    """运行全部网络仿真实验"""
    run_exp8a(num_trials=100)
    run_exp8b_rtt_sweep(num_trials=50)
    run_exp8c_rtt_multiplier(num_trials=100)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'rtt_sweep':
            run_exp8b_rtt_sweep()
        elif cmd == 'rtt_multiplier':
            run_exp8c_rtt_multiplier()
        elif cmd == '8a':
            run_exp8a()
        else:
            run_all()
    else:
        run_all()
