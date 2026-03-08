"""
实验3: 分层锚定与版本协调机制评估
对应论文 5.2.4 节

目标: (1) 展示 DCL→GCL→RTL 端到端流水线各阶段开销
      (2) 对比逐条锚定/扁平Merkle/分层Merkle三种策略
      (3) 验证聚合时间窗口对域纳入率与延迟的影响
      (4) 评估多周期快照一致性与扰动恢复能力

优先级: P1
"""

import sys
import os
import time
import random
import math
import hashlib
import json
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.merkle import MerkleTree, build_credential_leaf
from src.crypto.bls_threshold import BLSThresholdSignature
from src.utils import ExperimentResult, Timer, print_header, print_result_table

# 链交互（可选）
_fisco_client = None

def _get_chain_client():
    global _fisco_client
    if _fisco_client is None:
        from src.chain.fisco_client import FISCOClient
        _fisco_client = FISCOClient()
        _fisco_client.init()
    return _fisco_client


# ============================================================
# EXP3a: DCL→GCL→RTL 端到端流水线开销
# ============================================================

def run_exp3a_e2e_pipeline(domain_counts=(2, 5, 10, 15, 20),
                            credentials_per_domain=1000,
                            rtl_n=5, rtl_t=3,
                            num_trials=5, use_chain=True):
    """
    实验3a: 端到端分层锚定流水线开销

    测量完整 DCL→GCL→RTL 流水线六个阶段的时间开销,
    展示每增加一层治理层级, 额外开销主要来自一次固定 PBFT 共识写入。

    自变量: 域数量 m
    因变量: 6 个阶段耗时 (DCL建树/DCL锚定/GCL聚合/GCL锚定/RTL签名/RTL锚定)
    """
    print_header("实验3a: DCL→GCL→RTL 端到端流水线开销")

    if use_chain:
        print("  [链上模式] 域根与快照将锚定到 FISCO BCOS")
        fc = _get_chain_client()

    # 预初始化 BLS 密钥 (避免每次 trial 重复 keygen)
    print(f"  初始化 RTL 委员会 (n={rtl_n}, t={rtl_t})...")
    member_ids = list(range(1, rtl_n + 1))
    bls_ts = BLSThresholdSignature(rtl_t, rtl_n)
    bls_ts.keygen(member_ids)
    print("  BLS 密钥生成完成")

    all_results = []
    chain_epoch_counter = int(time.time())

    for m in domain_counts:
        print(f"\n  域数 m={m}, 每域 {credentials_per_domain} 凭证, 重复 {num_trials} 次")

        stages = {
            'dcl_merkle_ms': [], 'dcl_chain_ms': [],
            'gcl_aggregate_ms': [], 'gcl_chain_ms': [],
            'rtl_sign_ms': [], 'rtl_chain_ms': [],
            'total_offchain_ms': [], 'total_chain_ms': [], 'total_ms': [],
        }

        for trial in range(num_trials):
            chain_epoch_counter += 1
            epoch = chain_epoch_counter

            # ===== Stage 1: DCL 域内 Merkle 建树 (并行, 取 max) =====
            domain_roots = []
            domain_build_times = []
            for d in range(m):
                t0 = time.perf_counter()
                leaves = [build_credential_leaf(
                    f"DCL_{d}", epoch, f"did:example:{d}_{i}",
                    "Active",
                    hashlib.sha256(f"commit_{d}_{i}".encode()).digest()
                ) for i in range(credentials_per_domain)]
                tree = MerkleTree()
                root = tree.build(leaves, sort=True)
                domain_build_times.append((time.perf_counter() - t0) * 1000)
                domain_roots.append({
                    'domain_id': f"DCL_{d}",
                    'root': root,
                    'epoch': epoch,
                })
            dcl_merkle_ms = max(domain_build_times)  # 并行取最慢

            # ===== Stage 2: DCL 域根链上锚定 (并行, 取 max) =====
            dcl_chain_ms = 0
            if use_chain:
                sig_placeholder = b"\x00" * 48
                tx_times = []
                for dr in domain_roots:
                    _, tx_ms = fc.anchor_domain_root(
                        dr['domain_id'], epoch, dr['root'],
                        sig_placeholder, credentials_per_domain
                    )
                    tx_times.append(tx_ms)
                dcl_chain_ms = max(tx_times)

            # ===== Stage 3: GCL 全域聚合 =====
            t0 = time.perf_counter()
            sorted_roots = sorted(domain_roots, key=lambda x: x['domain_id'])
            root_bytes = [dr['root'] for dr in sorted_roots]
            global_tree = MerkleTree()
            global_root = global_tree.build(root_bytes, sort=False)
            gcl_aggregate_ms = (time.perf_counter() - t0) * 1000

            # ===== Stage 4: GCL 快照链上锚定 =====
            gcl_chain_ms = 0
            if use_chain:
                _, gcl_chain_ms = fc.anchor_global_snapshot(
                    epoch, global_root, sig_placeholder, m
                )

            # ===== Stage 5: RTL 门限背书 =====
            sig, timings = bls_ts.sign_and_time(global_root, member_ids[:rtl_t])
            rtl_sign_ms = timings['total_ms']

            # ===== Stage 6: RTL 背书快照链上锚定 =====
            rtl_chain_ms = 0
            if use_chain:
                endorsed_epoch = epoch + 500000  # 避免 epoch 冲突
                _, rtl_chain_ms = fc.anchor_global_snapshot(
                    endorsed_epoch, global_root, sig_placeholder, m
                )

            # 汇总
            offchain = dcl_merkle_ms + gcl_aggregate_ms + rtl_sign_ms
            chain_total = dcl_chain_ms + gcl_chain_ms + rtl_chain_ms
            total = offchain + chain_total

            stages['dcl_merkle_ms'].append(dcl_merkle_ms)
            stages['dcl_chain_ms'].append(dcl_chain_ms)
            stages['gcl_aggregate_ms'].append(gcl_aggregate_ms)
            stages['gcl_chain_ms'].append(gcl_chain_ms)
            stages['rtl_sign_ms'].append(rtl_sign_ms)
            stages['rtl_chain_ms'].append(rtl_chain_ms)
            stages['total_offchain_ms'].append(offchain)
            stages['total_chain_ms'].append(chain_total)
            stages['total_ms'].append(total)

        row = {k: round(statistics.mean(v), 2) for k, v in stages.items()}
        row['m'] = m
        all_results.append(row)

        print(f"    DCL: 建树{row['dcl_merkle_ms']}ms + 锚定{row['dcl_chain_ms']}ms | "
              f"GCL: 聚合{row['gcl_aggregate_ms']}ms + 锚定{row['gcl_chain_ms']}ms | "
              f"RTL: 签名{row['rtl_sign_ms']}ms + 锚定{row['rtl_chain_ms']}ms | "
              f"总计: {row['total_ms']}ms")

    print("\n  结果汇总:")
    print_result_table(all_results, ['m', 'dcl_merkle_ms', 'dcl_chain_ms',
                                      'gcl_aggregate_ms', 'gcl_chain_ms',
                                      'rtl_sign_ms', 'rtl_chain_ms', 'total_ms'])

    result = ExperimentResult(
        experiment_id='EXP3a',
        experiment_name='E2E Pipeline Overhead (DCL→GCL→RTL)',
        params={
            'domain_counts': list(domain_counts),
            'credentials_per_domain': credentials_per_domain,
            'rtl_n': rtl_n, 'rtl_t': rtl_t,
            'use_chain': use_chain,
        },
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


# ============================================================
# EXP3b: 锚定策略对比
# ============================================================

def run_exp3b_strategy_comparison(total_creds_list=(100, 500, 1000, 5000, 10000),
                                   m=5, num_trials=5):
    """
    实验3b: 锚定策略对比 — 逐条锚定 vs 扁平Merkle vs 分层Merkle

    定量对比三种策略的链上交互次数、链下计算时间与验证证明深度,
    展示分层 Merkle 聚合在多域场景下的优势。

    链上时间使用实测 PBFT 共识常量 (1011ms) 进行模拟,
    因为逐条锚定 10000 凭证实际需要 ~2.8 小时。

    自变量: 总凭证数 N
    因变量: 链上交易次数, 链下计算时间, 总延迟, 证明深度
    """
    print_header("实验3b: 锚定策略对比 (逐条/扁平/分层)")

    PBFT_MS = 1011.0  # 实测 PBFT 共识延迟均值

    all_results = []

    for N in total_creds_list:
        n_per_domain = N // m
        print(f"\n  总凭证 N={N}, m={m} 域, 每域 {n_per_domain} 凭证")

        trial_data = {
            'per_cred_compute_ms': [], 'flat_compute_ms': [], 'hier_compute_ms': [],
        }

        for trial in range(num_trials):
            # ===== 策略1: 逐条锚定 =====
            t0 = time.perf_counter()
            for i in range(N):
                _ = hashlib.sha256(f"cred_{trial}_{i}".encode()).digest()
            per_cred_compute = (time.perf_counter() - t0) * 1000
            trial_data['per_cred_compute_ms'].append(per_cred_compute)

            # ===== 策略2: 扁平 Merkle =====
            t0 = time.perf_counter()
            all_leaves = [hashlib.sha256(f"cred_{trial}_{i}".encode()).digest()
                          for i in range(N)]
            flat_tree = MerkleTree()
            flat_root = flat_tree.build(all_leaves, sort=True)
            flat_compute = (time.perf_counter() - t0) * 1000
            trial_data['flat_compute_ms'].append(flat_compute)

            # ===== 策略3: 分层 Merkle (HFA-DID) =====
            t0 = time.perf_counter()
            domain_roots = []
            max_domain_depth = 0
            for d in range(m):
                start = d * n_per_domain
                end = start + n_per_domain
                leaves = [hashlib.sha256(f"cred_{trial}_{i}".encode()).digest()
                          for i in range(start, end)]
                dtree = MerkleTree()
                droot = dtree.build(leaves, sort=True)
                domain_roots.append(droot)
                max_domain_depth = max(max_domain_depth, dtree.depth)
            global_tree = MerkleTree()
            global_root = global_tree.build(domain_roots, sort=False)
            hier_compute = (time.perf_counter() - t0) * 1000
            trial_data['hier_compute_ms'].append(hier_compute)

        # 计算均值
        per_cred_compute_avg = statistics.mean(trial_data['per_cred_compute_ms'])
        flat_compute_avg = statistics.mean(trial_data['flat_compute_ms'])
        hier_compute_avg = statistics.mean(trial_data['hier_compute_ms'])

        # 链上交易次数
        per_cred_tx = N
        flat_tx = 1
        # 分层: 并行优化后, 域根并行锚定(1次PBFT) + 全局快照(1次PBFT) = 2次
        hier_tx_parallel = 2
        # 非并行: m次域根 + 1次全局 = m+1次
        hier_tx_sequential = m + 1

        # 总延迟
        per_cred_total = per_cred_compute_avg + per_cred_tx * PBFT_MS
        flat_total = flat_compute_avg + flat_tx * PBFT_MS
        hier_total_parallel = hier_compute_avg + hier_tx_parallel * PBFT_MS

        # 证明深度 (验证时需要的哈希步数)
        flat_proof_depth = flat_tree.depth if hasattr(flat_tree, 'depth') else int(math.log2(N)) + 1
        hier_proof_depth = max_domain_depth + global_tree.depth

        row = {
            'N': N,
            # 逐条锚定
            'per_cred_tx': per_cred_tx,
            'per_cred_compute_ms': round(per_cred_compute_avg, 2),
            'per_cred_total_ms': round(per_cred_total, 1),
            # 扁平 Merkle
            'flat_tx': flat_tx,
            'flat_compute_ms': round(flat_compute_avg, 2),
            'flat_total_ms': round(flat_total, 1),
            'flat_proof_depth': flat_proof_depth,
            # 分层 Merkle (HFA-DID)
            'hier_tx_parallel': hier_tx_parallel,
            'hier_tx_sequential': hier_tx_sequential,
            'hier_compute_ms': round(hier_compute_avg, 2),
            'hier_total_ms': round(hier_total_parallel, 1),
            'hier_proof_depth': hier_proof_depth,
            # 优势比
            'tx_reduction_vs_percred': round((1 - hier_tx_parallel / per_cred_tx) * 100, 2),
            'speedup_vs_percred': round(per_cred_total / hier_total_parallel, 1),
        }
        all_results.append(row)

        print(f"    逐条: {per_cred_tx}次链上写入, 总{row['per_cred_total_ms']}ms")
        print(f"    扁平: {flat_tx}次链上写入, 证明深度{flat_proof_depth}, 总{row['flat_total_ms']}ms")
        print(f"    分层: {hier_tx_parallel}次链上写入(并行), 证明深度{hier_proof_depth}, 总{row['hier_total_ms']}ms")
        print(f"    → 链上交互减少 {row['tx_reduction_vs_percred']}%, 加速比 {row['speedup_vs_percred']}x")

    print("\n  结果汇总:")
    print_result_table(all_results, ['N', 'per_cred_tx', 'flat_tx', 'hier_tx_parallel',
                                      'flat_proof_depth', 'hier_proof_depth',
                                      'per_cred_total_ms', 'flat_total_ms', 'hier_total_ms',
                                      'speedup_vs_percred'])

    result = ExperimentResult(
        experiment_id='EXP3b',
        experiment_name='Anchoring Strategy Comparison',
        params={'total_creds_list': list(total_creds_list), 'm': m},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


# ============================================================
# EXP3c: 聚合时间窗口与版本协调
# ============================================================

def run_exp3c_time_window(domain_counts=(5, 10, 20),
                           window_widths=(500, 1000, 2000, 3000, 5000, 8000, 10000),
                           delay_sigmas=(0.3, 0.5, 0.8),
                           num_epochs=50,
                           num_trials=5):
    """
    实验3c: 聚合时间窗口对域纳入率与快照延迟的影响

    模拟 m 个域异步提交 Merkle 根, GCL 在时间窗口 [0, W] 内收集并过滤,
    验证论文算法 3.2 的版本化锚定机制。

    延迟模型: LogNormal(μ=ln(1500), σ)
      - μ=ln(1500) 对应实测中位数 ~1500ms (PBFT 1011ms + Merkle + 网络)
      - σ 控制域间异质性 (0.3=低方差, 0.5=中等, 0.8=高方差)

    自变量: 窗口宽度 W (ms)
    参数: 域数 m, 延迟离散度 σ
    因变量: 域纳入率(%), 端到端快照延迟(ms), 不完整epoch数
    """
    print_header("实验3c: 聚合时间窗口与版本协调")

    MU = math.log(1500)  # 中位数 ~1500ms
    GCL_AGGREGATE_MS = 2.0  # GCL Merkle 聚合开销 (实测极小)
    RTL_ENDORSE_MS = 1100.0  # RTL 门限签名 (实测 ~1072-1240ms 均值)
    CHAIN_ANCHOR_MS = 1011.0  # PBFT 共识写入

    random.seed(42)  # 可复现

    all_results = []

    for m in domain_counts:
        for sigma in delay_sigmas:
            for W in window_widths:
                trial_metrics = {
                    'inclusion_rates': [],
                    'e2e_latencies': [],
                    'incomplete_epochs': [],
                    'avg_wait_ms': [],
                }

                for trial in range(num_trials):
                    epoch_inclusions = []
                    epoch_waits = []

                    for epoch in range(num_epochs):
                        # 模拟 m 个域的异步提交延迟
                        submission_delays = []
                        for d in range(m):
                            # 基础延迟: DCL处理 + PBFT共识 + 网络传播
                            delay = random.lognormvariate(MU, sigma)
                            # 域级随机偏移 (不同域启动时间不完全同步)
                            offset = random.uniform(0, 200)
                            submission_delays.append(delay + offset)

                        # GCL 版本协调: 仅接受 [0, W] 内到达的锚定记录
                        # 对应论文公式 3.8: Anchor_j.ts_anchor ∈ [t_s, t_e]
                        included = [d for d in submission_delays if d <= W]
                        inclusion_rate = len(included) / m

                        epoch_inclusions.append(inclusion_rate)

                        # 实际等待时间 = 最后一个纳入域的提交时间
                        if included:
                            actual_wait = max(included)
                        else:
                            actual_wait = 0
                        epoch_waits.append(actual_wait)

                    avg_inclusion = statistics.mean(epoch_inclusions)
                    incomplete = sum(1 for r in epoch_inclusions if r < 1.0)

                    # 端到端延迟 = 窗口宽度 + GCL聚合 + RTL背书 + 链上锚定
                    e2e = W + GCL_AGGREGATE_MS + RTL_ENDORSE_MS + CHAIN_ANCHOR_MS
                    avg_wait = statistics.mean(epoch_waits)

                    trial_metrics['inclusion_rates'].append(avg_inclusion)
                    trial_metrics['e2e_latencies'].append(e2e)
                    trial_metrics['incomplete_epochs'].append(incomplete)
                    trial_metrics['avg_wait_ms'].append(avg_wait)

                row = {
                    'm': m,
                    'sigma': sigma,
                    'window_ms': W,
                    'inclusion_rate_pct': round(
                        statistics.mean(trial_metrics['inclusion_rates']) * 100, 1),
                    'e2e_latency_ms': round(
                        statistics.mean(trial_metrics['e2e_latencies']), 1),
                    'incomplete_epochs_of_50': round(
                        statistics.mean(trial_metrics['incomplete_epochs']), 1),
                    'avg_actual_wait_ms': round(
                        statistics.mean(trial_metrics['avg_wait_ms']), 1),
                }
                all_results.append(row)

                if row['inclusion_rate_pct'] < 100:
                    print(f"    m={m}, σ={sigma}, W={W}ms → "
                          f"纳入率={row['inclusion_rate_pct']}%, "
                          f"延迟={row['e2e_latency_ms']}ms, "
                          f"不完整epoch={row['incomplete_epochs_of_50']}/50")
                else:
                    print(f"    m={m}, σ={sigma}, W={W}ms → "
                          f"纳入率=100%, 延迟={row['e2e_latency_ms']}ms")

    print(f"\n  共 {len(all_results)} 组配置")

    result = ExperimentResult(
        experiment_id='EXP3c',
        experiment_name='Aggregation Time Window & Version Coordination',
        params={
            'domain_counts': list(domain_counts),
            'window_widths': list(window_widths),
            'delay_sigmas': list(delay_sigmas),
            'delay_mu': MU,
            'num_epochs': num_epochs,
        },
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


# ============================================================
# EXP3d: 多周期快照一致性与扰动恢复
# ============================================================

def run_exp3d_multi_epoch(num_epochs=20, m=10, window_ms=3000,
                           num_trials=10):
    """
    实验3d: 多周期快照一致性与扰动恢复

    模拟 20 个连续 epoch, 在不同阶段引入域延迟、故障和网络分区,
    评估分层锚定机制的鲁棒性。

    与 exp4 的区别: exp4 侧重 TPS/签发成功率, 本实验侧重快照纳入率/全局根一致性。

    扰动时间表:
      epoch 1-5:   正常 (所有域按时提交)
      epoch 6-8:   域0,1 延迟翻倍
      epoch 9-12:  域2,3,4 各epoch有50%概率失败
      epoch 13-15: 域5,6 完全不可达 (网络分区)
      epoch 16-20: 恢复正常
    """
    print_header("实验3d: 多周期快照一致性与扰动恢复")

    MU = math.log(1500)
    SIGMA = 0.5

    random.seed(42)

    # 扰动配置
    perturbation_schedule = [
        # (epoch_start, epoch_end, affected_domains, perturbation_type, params)
        (6, 8, [0, 1], 'delay_multiplier', 2.5),
        (9, 12, [2, 3, 4], 'random_failure', 0.5),
        (13, 15, [5, 6], 'partition', None),
    ]

    all_trial_records = []

    for trial in range(num_trials):
        epoch_records = []
        prev_included_set = None

        for epoch in range(1, num_epochs + 1):
            submissions = {}

            for d in range(m):
                # 基础延迟
                delay = random.lognormvariate(MU, SIGMA)
                offset = random.uniform(0, 200)
                total_delay = delay + offset
                submitted = True

                # 应用扰动
                for e_start, e_end, affected, ptype, param in perturbation_schedule:
                    if e_start <= epoch <= e_end and d in affected:
                        if ptype == 'delay_multiplier':
                            total_delay *= param
                        elif ptype == 'random_failure':
                            if random.random() < param:
                                submitted = False
                        elif ptype == 'partition':
                            submitted = False

                if submitted:
                    submissions[d] = total_delay

            # GCL 版本协调: 仅接受 [0, W] 内到达的记录
            included_domains = set()
            for d, delay in submissions.items():
                if delay <= window_ms:
                    included_domains.add(d)

            inclusion_rate = len(included_domains) / m

            # 构建快照 (简化: 仅计算全局根)
            if included_domains:
                domain_roots = []
                for d in sorted(included_domains):
                    root = hashlib.sha256(
                        f"epoch{epoch}_domain{d}_trial{trial}".encode()
                    ).digest()
                    domain_roots.append(root)
                global_tree = MerkleTree()
                global_root = global_tree.build(domain_roots, sort=False)
            else:
                global_root = hashlib.sha256(b"empty_snapshot").digest()

            # 一致性检查: 与上一 epoch 的纳入域集合是否相同
            consistent = (included_domains == prev_included_set) \
                if prev_included_set is not None else True

            record = {
                'epoch': epoch,
                'included_count': len(included_domains),
                'total_domains': m,
                'inclusion_rate_pct': round(inclusion_rate * 100, 1),
                'included_set': sorted(included_domains),
                'global_root_prefix': global_root.hex()[:16],
                'consistent_with_prev': consistent,
            }
            epoch_records.append(record)
            prev_included_set = included_domains

        all_trial_records.append(epoch_records)

    # 聚合多次 trial 的统计
    aggregated = []
    for epoch_idx in range(num_epochs):
        inclusions = [t[epoch_idx]['inclusion_rate_pct']
                      for t in all_trial_records]
        included_counts = [t[epoch_idx]['included_count']
                           for t in all_trial_records]
        consistencies = [t[epoch_idx]['consistent_with_prev']
                         for t in all_trial_records]

        agg = {
            'epoch': epoch_idx + 1,
            'avg_inclusion_rate_pct': round(statistics.mean(inclusions), 1),
            'min_inclusion_rate_pct': round(min(inclusions), 1),
            'max_inclusion_rate_pct': round(max(inclusions), 1),
            'avg_included_count': round(statistics.mean(included_counts), 1),
            'consistency_rate_pct': round(
                sum(consistencies) / len(consistencies) * 100, 1),
        }
        aggregated.append(agg)

        # 判断扰动状态
        perturbation = "正常"
        for e_start, e_end, affected, ptype, _ in perturbation_schedule:
            if e_start <= agg['epoch'] <= e_end:
                perturbation = f"{ptype}(域{affected})"
                break

        print(f"    Epoch {agg['epoch']:2d}: "
              f"纳入率={agg['avg_inclusion_rate_pct']:5.1f}% "
              f"(min={agg['min_inclusion_rate_pct']}%, "
              f"max={agg['max_inclusion_rate_pct']}%) "
              f"一致性={agg['consistency_rate_pct']}% "
              f"[{perturbation}]")

    # 计算恢复指标
    # 找到扰动结束后第一个 100% 纳入的 epoch
    recovery_epoch = None
    for agg in aggregated:
        if agg['epoch'] >= 16 and agg['avg_inclusion_rate_pct'] >= 99:
            recovery_epoch = agg['epoch']
            break

    if recovery_epoch:
        print(f"\n  恢复指标: 扰动结束 (epoch 15) 后, 在 epoch {recovery_epoch} 恢复至 ≥99% 纳入率"
              f" (恢复延迟: {recovery_epoch - 15} 个 epoch)")

    result = ExperimentResult(
        experiment_id='EXP3d',
        experiment_name='Multi-Epoch Snapshot Consistency',
        params={
            'num_epochs': num_epochs,
            'm': m,
            'window_ms': window_ms,
            'num_trials': num_trials,
            'perturbation_schedule': [
                {'epochs': f'{s}-{e}', 'domains': a, 'type': t}
                for s, e, a, t, _ in perturbation_schedule
            ],
        },
        extra={
            'aggregated': aggregated,
            'recovery_epoch': recovery_epoch,
        },
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return aggregated


# ============================================================
# 入口
# ============================================================

def run_all(use_chain=True):
    """运行实验3全部子实验"""
    print_header("实验3: 分层锚定与版本协调机制评估 (论文 5.2.4)")

    results = {}

    # EXP3a: 需要链上交互
    results['exp3a'] = run_exp3a_e2e_pipeline(
        domain_counts=(2, 5, 10, 15, 20),
        credentials_per_domain=1000,
        rtl_n=5, rtl_t=3,
        num_trials=5,
        use_chain=use_chain,
    )

    # EXP3b: 纯模拟 (链上时间用常量)
    results['exp3b'] = run_exp3b_strategy_comparison(
        total_creds_list=(100, 500, 1000, 5000, 10000),
        m=5,
        num_trials=5,
    )

    # EXP3c: 纯模拟 (版本协调逻辑)
    results['exp3c'] = run_exp3c_time_window(
        domain_counts=(5, 10, 20),
        window_widths=(500, 1000, 2000, 3000, 5000, 8000, 10000),
        delay_sigmas=(0.3, 0.5, 0.8),
        num_epochs=50,
        num_trials=5,
    )

    # EXP3d: 纯模拟 (多周期扰动)
    results['exp3d'] = run_exp3d_multi_epoch(
        num_epochs=20, m=10, window_ms=3000,
        num_trials=10,
    )

    return results


if __name__ == '__main__':
    # 默认无链模式运行 (本地测试)
    import sys
    use_chain = '--chain' in sys.argv
    if not use_chain:
        print("提示: 使用 --chain 参数启用链上模式")
        print("      无链模式下 EXP3a 的链上阶段将显示为 0ms\n")
    run_all(use_chain=use_chain)
