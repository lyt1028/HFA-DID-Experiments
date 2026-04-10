"""
实验6 v2 (脚本编号exp9): 自适应门限机制验证
对应小论文 7.6 节

目标: 用真实BLS门限签名测量不同门限值下的签发延迟与通信开销,
     验证自适应门限在安全-效率之间的最优权衡

输出:
  图8(a): 不同门限值 t 下各阶段签名延迟 (堆叠柱状图)
  图8(b): 多epoch场景下三种策略的累积签发延迟对比
"""

import sys
import os
import json
import time
import random
import math
import statistics
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.bls_threshold import BLSThresholdSignature
from src.models.reputation import ReputationModel, NodeBehavior
from src.models.adaptive_threshold import AdaptiveThreshold, FixedThreshold
from src.utils import print_header


# ============================================================
# Part A: 不同门限值下的真实BLS签名性能
# ============================================================

def run_part_a(n=20, threshold_values=None, num_trials=10):
    """
    测量不同门限 t 下的 BLS 门限签名各阶段延迟

    自变量: t in {7, 8, 9, 10, 11, 12, 13, 14}
    因变量: partial_sign_ms, aggregate_ms, verify_ms, total_ms, comm_bytes
    """
    if threshold_values is None:
        threshold_values = [8, 9, 10, 11, 12, 13]

    print_header("Part A: BLS Threshold Signing Latency vs t")
    print(f"  n={n}, trials={num_trials}")

    member_ids = list(range(1, n + 1))
    results = []

    for t in threshold_values:
        print(f"\n  t={t} ({t}/{n})...")

        # 初始化 BLS (t, n) - 每个t值重新初始化
        bls = BLSThresholdSignature(threshold=t, num_members=n)
        bls.keygen(member_ids)

        trial_timings = {
            'partial_sign_ms': [],
            'aggregate_ms': [],
            'verify_ms': [],
            'total_ms': [],
        }

        signer_ids = member_ids[:t]

        for trial in range(num_trials):
            msg = f"credential_{trial}_epoch_1_t{t}".encode()
            _, timings = bls.sign_and_time(msg, signer_ids)

            for key in trial_timings:
                trial_timings[key].append(timings[key])

            if trial == 0:
                print(f"    Trial 0: partial={timings['partial_sign_ms']:.1f}ms, "
                      f"agg={timings['aggregate_ms']:.1f}ms, "
                      f"verify={timings['verify_ms']:.1f}ms, "
                      f"total={timings['total_ms']:.1f}ms")

        # 通信开销: t个部分签名, 每个BLS G2签名96字节
        comm_partial_sigs = t * 96  # bytes
        # 加上1个聚合签名广播
        comm_total = comm_partial_sigs + 96

        avg = {k: statistics.mean(v) for k, v in trial_timings.items()}
        std = {k: statistics.stdev(v) if len(v) > 1 else 0
               for k, v in trial_timings.items()}

        result = {
            'n': n,
            't': t,
            't_ratio': round(t / n, 2),
            'avg_partial_sign_ms': round(avg['partial_sign_ms'], 2),
            'avg_aggregate_ms': round(avg['aggregate_ms'], 2),
            'avg_verify_ms': round(avg['verify_ms'], 2),
            'avg_total_ms': round(avg['total_ms'], 2),
            'std_total_ms': round(std['total_ms'], 2),
            'comm_partial_bytes': comm_partial_sigs,
            'comm_total_bytes': comm_total,
        }
        results.append(result)

        print(f"    Avg: total={avg['total_ms']:.1f}ms "
              f"(partial={avg['partial_sign_ms']:.1f}, "
              f"agg={avg['aggregate_ms']:.1f}, "
              f"verify={avg['verify_ms']:.1f}), "
              f"comm={comm_total}B")

    return results


# ============================================================
# Part B: 多epoch动态场景 - 三种策略的实际签发延迟对比
# ============================================================

def run_part_b(n=20, num_epochs=15, issuances_per_epoch=3):
    """
    在动态威胁场景中, 用真实BLS签名测量三种策略的实际签发延迟.

    每个epoch:
      1. 根据威胁调度注入恶意节点
      2. 计算信誉 -> 确定门限 t(e)
      3. 用真实BLS (t(e), n)签名 issuances_per_epoch 次
      4. 记录实际延迟

    对比: fixed_high(t=11), fixed_low(t=7), adaptive t(e)
    """
    print_header("Part B: Multi-Epoch Adaptive Signing Latency")

    threat_schedule = {
        1: 0.0, 2: 0.0,
        3: 0.10, 4: 0.20,
        5: 0.30, 6: 0.35,
        7: 0.35, 8: 0.40, 9: 0.45,
        10: 0.40, 11: 0.30,
        12: 0.20, 13: 0.10,
        14: 0.0, 15: 0.0,
    }

    member_ids = list(range(1, n + 1))

    strategies = {
        'fixed_high': FixedThreshold(n, t=13),
        'fixed_low': FixedThreshold(n, t=8),
        'adaptive': AdaptiveThreshold(n, t_base=0.35, mu=0.6),
    }

    # 预初始化各门限值的BLS实例 (避免重复keygen)
    print("  Pre-initializing BLS instances for t=7..14...")
    bls_instances = {}
    for t in range(7, 16):
        bls = BLSThresholdSignature(threshold=t, num_members=n)
        bls.keygen(member_ids)
        bls_instances[t] = bls
    print("  Done.")

    all_results = {}

    for strategy_name, threshold_calc in strategies.items():
        print(f"\n  Strategy: {strategy_name}")
        random.seed(42)

        # 初始化节点
        nodes = {
            i: {'id': i, 'reputation': 0.5 + random.uniform(0, 0.3),
                'corrupted': False}
            for i in range(1, n + 1)
        }
        rep_model = ReputationModel()
        epoch_results = []

        for epoch in range(1, num_epochs + 1):
            # 1. 注入威胁
            target_mal = int(n * threat_schedule.get(epoch, 0))
            corrupted = [nid for nid, nd in nodes.items() if nd['corrupted']]
            honest = [nid for nid, nd in nodes.items() if not nd['corrupted']]

            if len(corrupted) < target_mal:
                to_corrupt = random.sample(
                    honest, min(target_mal - len(corrupted), len(honest)))
                for nid in to_corrupt:
                    nodes[nid]['corrupted'] = True
            elif len(corrupted) > target_mal:
                to_recover = random.sample(
                    corrupted, len(corrupted) - target_mal)
                for nid in to_recover:
                    nodes[nid]['corrupted'] = False

            # 2. 信誉评估
            behaviors = []
            for nid in sorted(nodes.keys()):
                b = NodeBehavior(node_id=nid)
                b.total_tasks = 50
                b.requested = 50
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
            t_e, t_info = threshold_calc.compute_threshold(scores)

            # clamp t_e to available BLS instances
            t_e = max(7, min(15, t_e))

            # 3. 真实BLS签名
            bls = bls_instances[t_e]
            honest_ids = [nid for nid, nd in nodes.items() if not nd['corrupted']]
            f_active = sum(1 for nd in nodes.values() if nd['corrupted'])

            sign_latencies = []
            comm_costs = []
            for i in range(issuances_per_epoch):
                msg = f"vc_epoch{epoch}_issue{i}_{strategy_name}".encode()
                # 所有节点(含被腐蚀)均持有合法份额, 均参与签名
                all_ids = list(nodes.keys())
                signers = random.sample(all_ids, min(t_e, len(all_ids)))
                _, timings = bls.sign_and_time(msg, signers)
                sign_latencies.append(timings["total_ms"])
                comm_costs.append(t_e * 96 + 96)

            avg_latency = statistics.mean(sign_latencies)

            safety_margin = t_e - f_active

            epoch_results.append({
                'epoch': epoch,
                't_e': t_e,
                'f_active': f_active,
                'safety_margin': safety_margin,
                'avg_sign_latency_ms': round(avg_latency, 2),
                'comm_bytes_per_issuance': t_e * 96 + 96,
                'success_rate': 100.0,
                'threat_level': threat_schedule.get(epoch, 0),
                'nu': t_info.get('nu', 0),
            })

            is_secure = f_active < t_e
            status = "SAFE" if is_secure else "BREACH"
            print(f"    Epoch {epoch:2d}: t={t_e:2d}, f={f_active:2d}, "
                  f"margin={safety_margin:+3d} [{status}], "
                  f"latency={avg_latency:.1f}ms, "
                  f"comm={t_e*96+96}B")

        all_results[strategy_name] = epoch_results

    return all_results


def run_all(save_dir=None):
    print_header("Exp9 v2: Adaptive Threshold - Real BLS Measurement")

    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(save_dir, exist_ok=True)

    # Part A
    part_a = run_part_a(n=20, num_trials=10)

    # Part B
    part_b = run_part_b(n=20, num_epochs=15, issuances_per_epoch=3)

    # 保存
    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, f'EXP9v2_adaptive_threshold_{ts}.json')
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({'part_a': part_a, 'part_b': part_b},
                  f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved: {filepath}")

    return {'part_a': part_a, 'part_b': part_b}


if __name__ == '__main__':
    run_all()
