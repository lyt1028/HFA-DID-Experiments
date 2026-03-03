"""
实验7: 陷门继承安全性与轮换影响
对应论文 5.5.3 节

目标: 验证 Re-DKG 轮转后变色龙哈希陷门的安全继承:
  (1) 新委员会能否使用新份额执行更新/撤销
  (2) 旧委员会退出节点的旧份额是否失效
  (3) 跨周期份额是否独立
  (4) 多轮连续轮换稳定性
  (5) 轮换对服务连续性的影响

优先级: P1
"""

import sys
import os
import time
import random
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.shamir import ShamirSecretSharing
from src.crypto.chameleon_hash import ChameleonHash, ThresholdChameleonHash
from src.crypto.redkg import ReDKG
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


def run_exp7a_functional_correctness(ch_bits=128):
    """
    实验7a: 功能正确性验证

    验证:
      - 旧委员会能正常使用陷门
      - Re-DKG 轮转后陷门总值不变
      - 新委员会能使用新份额执行更新
      - 退出节点不能重构陷门
    """
    print_header("实验7a: Re-DKG 功能正确性验证")

    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()
    q = ch.q
    threshold = 7
    n = 10

    sss = ShamirSecretSharing(q)
    test_results = []

    # ===== 测试1: 旧委员会执行更新 =====
    print("  [1] 旧委员会执行凭证更新...")
    old_committee = list(range(1, n + 1))
    old_shares = sss.split(td, threshold, n, old_committee)

    m1 = random.randint(1, q - 1)
    r1 = random.randint(1, q - 1)
    commit = ch.hash(m1, r1)

    tch = ThresholdChameleonHash(ch, threshold, n)
    tch.shares = old_shares
    m2 = random.randint(1, q - 1)

    share_subset = {mid: old_shares[mid] for mid in old_committee[:threshold]}
    r2 = tch.threshold_forge(share_subset, m1, r1, m2)
    old_update_ok = ch.hash(m2, r2) == commit

    test_results.append({
        'test': '旧委员会执行更新',
        'expected': 'PASS',
        'actual': 'PASS' if old_update_ok else 'FAIL',
        'ok': old_update_ok,
    })
    print(f"      结果: {'PASS' if old_update_ok else 'FAIL'}")

    # ===== 测试2: Re-DKG 轮转 =====
    print("  [2] 执行 Re-DKG 轮转...")
    new_committee = list(range(3, 13))  # n1,n2 退出; n11,n12 加入; n3-n10 留任
    redkg = ReDKG(q, threshold)
    new_shares, timings = redkg.rotate(old_committee, new_committee, old_shares)

    # 验证陷门不变: 通过拉格朗日插值重构
    old_td = sss.reconstruct(old_shares, threshold)
    new_td = sss.reconstruct(new_shares, threshold)
    td_invariant = (old_td == new_td == td)

    test_results.append({
        'test': '陷门总值不变性 (Re-DKG后)',
        'expected': 'PASS',
        'actual': 'PASS' if td_invariant else 'FAIL',
        'ok': td_invariant,
    })
    print(f"      陷门不变: {'PASS' if td_invariant else 'FAIL'} "
          f"(轮转耗时 {timings['total_ms']:.2f} ms)")

    # ===== 测试3: 新委员会执行更新 =====
    print("  [3] 新委员会执行凭证更新...")
    new_share_subset = {mid: new_shares[mid] for mid in new_committee[:threshold]}
    m3 = random.randint(1, q - 1)
    # 用新份额重构陷门
    td_new_reconstructed = sss.reconstruct(new_share_subset, threshold)
    assert td_new_reconstructed == td

    # 手动碰撞计算
    td_inv = pow(td_new_reconstructed, -1, q)
    r3 = (r2 + (m2 - m3) * td_inv) % q
    new_update_ok = ch.hash(m3, r3) == commit

    test_results.append({
        'test': '新委员会执行更新',
        'expected': 'PASS',
        'actual': 'PASS' if new_update_ok else 'FAIL',
        'ok': new_update_ok,
    })
    print(f"      结果: {'PASS' if new_update_ok else 'FAIL'}")

    # ===== 测试4: 退出节点攻击 =====
    print("  [4] 退出节点尝试重构陷门...")
    exited = [1, 2]
    exited_shares = {nid: old_shares[nid] for nid in exited}
    # 2 个份额 < threshold=7, 拉格朗日插值不等于真实 td
    td_attack = sss.reconstruct(exited_shares, len(exited))
    attack_failed = (td_attack != td)

    test_results.append({
        'test': '退出节点攻击 (旧份额 < 门限)',
        'expected': 'BLOCKED',
        'actual': 'BLOCKED' if attack_failed else 'BREACHED',
        'ok': attack_failed,
    })
    print(f"      结果: {'BLOCKED (符合预期)' if attack_failed else 'BREACHED (安全漏洞!)'}")

    # ===== 测试5: 退出节点旧份额 + 新委员会混合 =====
    print("  [5] 退出节点旧份额 + 新成员新份额混合攻击...")
    mixed_shares = {}
    mixed_shares[1] = old_shares[1]  # 旧份额
    mixed_shares[2] = old_shares[2]  # 旧份额
    for mid in list(new_committee[:threshold - 2]):
        mixed_shares[mid] = new_shares[mid]

    # 混合份额来自不同多项式, 插值结果不正确
    td_mixed = sss.reconstruct(mixed_shares, threshold)
    mixed_attack_failed = (td_mixed != td)

    test_results.append({
        'test': '混合份额攻击 (旧+新)',
        'expected': 'BLOCKED',
        'actual': 'BLOCKED' if mixed_attack_failed else 'BREACHED',
        'ok': mixed_attack_failed,
    })
    print(f"      结果: {'BLOCKED (符合预期)' if mixed_attack_failed else 'BREACHED (安全漏洞!)'}")

    # 汇总
    print("\n  功能正确性汇总:")
    all_pass = all(r['ok'] for r in test_results)
    for r in test_results:
        status = 'OK' if r['ok'] else 'FAIL'
        print(f"    [{status}] {r['test']}: 预期={r['expected']}, 实际={r['actual']}")
    print(f"\n  总结: {'全部通过' if all_pass else '存在失败项!'}")

    result = ExperimentResult(
        experiment_id='EXP7a',
        experiment_name='Re-DKG Functional Correctness',
        params={'committee_old': old_committee, 'committee_new': new_committee, 'threshold': threshold},
        extra={'test_results': test_results, 'all_pass': all_pass},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return test_results


def run_exp7b_cross_epoch_independence(num_epochs=3, ch_bits=128):
    """
    实验7b: 跨周期份额独立性验证

    验证: 收集历史周期的 <t 个份额无法重构陷门,
         混合不同周期份额也无法重构
    """
    print_header("实验7b: 跨周期份额独立性")

    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()
    q = ch.q
    threshold = 5
    n = 8
    sss = ShamirSecretSharing(q)

    # 初始分发
    current_ids = list(range(1, n + 1))
    current_shares = sss.split(td, threshold, n, current_ids)
    all_epoch_shares = [current_shares.copy()]
    all_epoch_ids = [current_ids[:]]
    next_id = n + 1

    # 多轮轮转
    redkg = ReDKG(q, threshold)
    for e in range(num_epochs - 1):
        num_rotate = 2
        staying = current_ids[:-num_rotate]
        new_members = list(range(next_id, next_id + num_rotate))
        next_id += num_rotate
        new_ids = staying + new_members

        new_shares, _ = redkg.rotate(current_ids, new_ids, current_shares)
        all_epoch_shares.append(new_shares.copy())
        all_epoch_ids.append(new_ids[:])
        current_ids = new_ids
        current_shares = new_shares

    # 攻击测试
    attacks = []

    # 攻击1: 单周期 t-1 个份额
    for e_idx in range(num_epochs):
        e_shares = all_epoch_shares[e_idx]
        e_ids = all_epoch_ids[e_idx]
        subset = {mid: e_shares[mid] for mid in e_ids[:threshold - 1]}
        td_attack = sss.reconstruct(subset, threshold - 1)
        success = (td_attack == td)
        attacks.append({
            'attack': f'单周期E{e_idx+1} ({threshold-1}份额)',
            'success': success,
        })
        print(f"  攻击: 单周期E{e_idx+1} ({threshold-1}份额) -> {'成功(漏洞!)' if success else '失败(安全)'}")

    # 攻击2: 跨周期混合 — 从不同周期取份额, 凑满 threshold 个
    # 关键: 不同周期的份额位于不同多项式上, 混合插值结果不正确
    if num_epochs >= 2:
        mixed = {}
        # 从每个周期选不同的节点ID, 确保收集足够份额
        per_epoch = max(2, threshold // num_epochs + 1)
        for e_idx in range(num_epochs):
            e_shares = all_epoch_shares[e_idx]
            e_ids = all_epoch_ids[e_idx]
            count = 0
            for mid in e_ids:
                if mid not in mixed and count < per_epoch:
                    mixed[mid] = e_shares[mid]
                    count += 1

        # 确保至少有 threshold 个
        if len(mixed) >= threshold:
            mixed_items = dict(list(mixed.items())[:threshold])
            td_mixed = sss.reconstruct(mixed_items, threshold)
            mix_success = (td_mixed == td)
        else:
            # 若不足, 也算攻击失败 (无法凑够门限)
            mix_success = False
            mixed_items = mixed
            td_mixed = None

        attacks.append({
            'attack': f'跨周期混合 ({len(mixed_items)}份额)',
            'success': mix_success,
        })
        print(f"  攻击: 跨周期混合 ({len(mixed_items)}份额) -> {'成功(漏洞!)' if mix_success else '失败(安全)'}")

    all_failed = all(not a['success'] for a in attacks)
    print(f"\n  跨周期独立性: {'验证通过' if all_failed else '存在安全漏洞!'}")

    result = ExperimentResult(
        experiment_id='EXP7b',
        experiment_name='Cross-Epoch Share Independence',
        params={'num_epochs': num_epochs, 'threshold': threshold},
        extra={'attacks': attacks, 'all_attacks_failed': all_failed},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return attacks


def run_exp7c_multi_round_stability(rotation_counts=(1, 3, 5, 10, 20),
                                      updates_per_round=10,
                                      ch_bits=128, use_chain=True):
    """
    实验7c: 多轮连续轮换稳定性

    自变量: 连续轮换次数
    因变量: 更新成功率, 陷门不变性, 轮转耗时, 链上记录耗时
    """
    print_header("实验7c: 多轮连续轮换稳定性")
    if use_chain:
        print("  [链上模式] 轮换事件将记录到 FISCO BCOS")
        fc = _get_chain_client()
    all_results = []

    for R in rotation_counts:
        print(f"\n  连续轮换 R={R} 次")

        ch = ChameleonHash(bits=ch_bits)
        pk, td = ch.keygen()
        q = ch.q
        threshold = 3
        committee_size = 5
        sss = ShamirSecretSharing(q)

        # 初始化
        current_ids = list(range(1, committee_size + 1))
        current_shares = sss.split(td, threshold, committee_size, current_ids)
        next_id = committee_size + 1

        redkg = ReDKG(q, threshold)
        total_updates = 0
        successful_updates = 0
        total_rotate_ms = 0
        total_chain_ms = 0
        td_invariant_count = 0

        # 链上: 发布初始委员会名单
        if use_chain:
            members_str = [f"node_{mid}" for mid in current_ids]
            fc.publish_roster("DCL_EXP7", 0, members_str, threshold)

        for r in range(R):
            # 轮换
            num_rotate = 1
            staying = current_ids[:-num_rotate]
            new_members = list(range(next_id, next_id + num_rotate))
            next_id += num_rotate
            new_ids = staying + new_members

            new_shares, timings = redkg.rotate(current_ids, new_ids, current_shares)
            total_rotate_ms += timings['total_ms']

            # 链上: 记录轮换事件 + 发布新名单
            if use_chain:
                stay_count = len(set(current_ids) & set(new_ids))
                join_count = len(set(new_ids) - set(current_ids))
                exit_count = len(set(current_ids) - set(new_ids))
                _, rot_ms = fc.record_rotation(
                    "DCL_EXP7", r, r + 1,
                    stay_count, join_count, exit_count,
                    int(timings['total_ms'])
                )
                new_members_str = [f"node_{mid}" for mid in new_ids]
                _, pub_ms = fc.publish_roster("DCL_EXP7", r + 1, new_members_str, threshold)
                total_chain_ms += rot_ms + pub_ms

            # 检查陷门不变
            td_check = sss.reconstruct(new_shares, threshold)
            if td_check == td:
                td_invariant_count += 1

            # 用新份额执行更新
            for _ in range(updates_per_round):
                m_old = random.randint(1, q - 1)
                r_old = random.randint(1, q - 1)
                commit = ch.hash(m_old, r_old)
                m_new = random.randint(1, q - 1)

                subset = {mid: new_shares[mid] for mid in new_ids[:threshold]}
                td_reconstructed = sss.reconstruct(subset, threshold)
                td_inv = pow(td_reconstructed, -1, q)
                r_new = (r_old + (m_old - m_new) * td_inv) % q

                total_updates += 1
                if ch.hash(m_new, r_new) == commit:
                    successful_updates += 1

            current_ids = new_ids
            current_shares = new_shares

        row = {
            'R': R,
            'update_success': f'{successful_updates}/{total_updates}',
            'success_rate': f'{successful_updates / total_updates * 100:.0f}%' if total_updates > 0 else 'N/A',
            'td_invariant': f'{td_invariant_count}/{R}',
            'avg_rotate_ms': round(total_rotate_ms / R, 2),
            'total_rotate_ms': round(total_rotate_ms, 2),
        }
        if use_chain:
            row['total_chain_ms'] = round(total_chain_ms, 1)
            row['avg_chain_per_rotation_ms'] = round(total_chain_ms / R, 1)

        all_results.append(row)
        msg = (f"    更新成功率: {row['success_rate']}, 陷门不变: {row['td_invariant']}, "
               f"平均轮转: {row['avg_rotate_ms']} ms")
        if use_chain:
            msg += f", 链上记录: {row['avg_chain_per_rotation_ms']} ms/轮"
        print(msg)

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP7c',
        experiment_name='Multi-Round Rotation Stability',
        params={'rotation_counts': list(rotation_counts), 'updates_per_round': updates_per_round,
                'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp7d_rotation_service_impact(committee_sizes=(4, 6, 8, 10),
                                        ch_bits=128, use_chain=True):
    """
    实验7d: 轮换期间服务中断测量

    自变量: 委员会规模
    因变量: 轮转总耗时 (各阶段分解), 服务不可用窗口, 链上记录耗时
    """
    print_header("实验7d: 轮换服务中断测量")
    if use_chain:
        print("  [链上模式] 轮换完成后将记录到链并发布新名单")
        fc = _get_chain_client()
    all_results = []

    for n in committee_sizes:
        t = max(2, int(n * 0.6) + 1)
        print(f"\n  委员会规模 n={n}, 门限 t={t}")

        ch = ChameleonHash(bits=ch_bits)
        pk, td = ch.keygen()
        q = ch.q
        sss = ShamirSecretSharing(q)

        old_ids = list(range(1, n + 1))
        old_shares = sss.split(td, t, n, old_ids)

        num_rotate = max(1, n // 3)
        staying = old_ids[:-num_rotate]
        new_members = list(range(n + 1, n + 1 + num_rotate))
        new_ids = staying + new_members

        # 分阶段计时
        redkg = ReDKG(q, t)

        t_start = time.perf_counter()

        # Phase 1: 零秘密多项式生成 + 子份额计算
        t0 = time.perf_counter()
        sub_shares = {}
        for from_id in old_ids:
            zero_shares, _ = sss.split_zero(t, len(new_ids), new_ids)
            for to_id in new_ids:
                sub_shares[(from_id, to_id)] = zero_shares[to_id]
        poly_ms = (time.perf_counter() - t0) * 1000

        # Phase 2: 份额分发 (模拟网络传输)
        t0 = time.perf_counter()
        for (from_id, to_id), val in sub_shares.items():
            _ = val  # 模拟传输
        distribute_ms = (time.perf_counter() - t0) * 1000

        # Phase 3: 新份额聚合
        t0 = time.perf_counter()
        new_shares = {}
        old_set = set(old_ids)
        for to_id in new_ids:
            received = sum(sub_shares[(from_id, to_id)] for from_id in old_ids) % q
            if to_id in old_set and to_id in old_shares:
                new_shares[to_id] = (old_shares[to_id] + received) % q
            else:
                new_shares[to_id] = received % q
        aggregate_ms = (time.perf_counter() - t0) * 1000

        # Phase 4: 一致性验证
        t0 = time.perf_counter()
        old_secret = sss.reconstruct(old_shares, t)
        new_secret = sss.reconstruct(new_shares, t)
        verify_ok = (old_secret == new_secret)
        verify_ms = (time.perf_counter() - t0) * 1000

        t_end = time.perf_counter()
        total_ms = (t_end - t_start) * 1000

        # Phase 5 (链上): 记录轮换事件 + 发布新名单
        chain_rotate_ms = 0
        chain_roster_ms = 0
        if use_chain:
            stay_count = len(set(old_ids) & set(new_ids))
            join_count = len(set(new_ids) - set(old_ids))
            exit_count = len(set(old_ids) - set(new_ids))
            _, chain_rotate_ms = fc.record_rotation(
                f"DCL_EXP7d_{n}", 0, 1,
                stay_count, join_count, exit_count,
                int(total_ms)
            )
            new_members_str = [f"node_{mid}" for mid in new_ids]
            _, chain_roster_ms = fc.publish_roster(
                f"DCL_EXP7d_{n}", 1, new_members_str, t)

        row = {
            'n': n,
            't': t,
            'rotated': num_rotate,
            'poly_gen_ms': round(poly_ms, 3),
            'distribute_ms': round(distribute_ms, 3),
            'aggregate_ms': round(aggregate_ms, 3),
            'verify_ms': round(verify_ms, 3),
            'total_ms': round(total_ms, 3),
            'service_gap_ms': round(poly_ms + distribute_ms + aggregate_ms, 3),
            'invariant_ok': verify_ok,
        }
        if use_chain:
            row['chain_rotate_ms'] = round(chain_rotate_ms, 1)
            row['chain_roster_ms'] = round(chain_roster_ms, 1)
            row['total_with_chain_ms'] = round(total_ms + chain_rotate_ms + chain_roster_ms, 1)

        all_results.append(row)
        msg = (f"    总耗时: {row['total_ms']} ms, 服务间隙: {row['service_gap_ms']} ms, "
               f"一致性: {'OK' if verify_ok else 'FAIL'}")
        if use_chain:
            msg += f", 链上记录: {row['chain_rotate_ms']:.0f}+{row['chain_roster_ms']:.0f} ms"
        print(msg)

    print("\n  结果汇总:")
    cols = ['n', 't', 'rotated', 'poly_gen_ms', 'aggregate_ms', 'verify_ms',
            'total_ms', 'service_gap_ms']
    if use_chain:
        cols.extend(['chain_rotate_ms', 'chain_roster_ms', 'total_with_chain_ms'])
    print_result_table(all_results, cols)

    result = ExperimentResult(
        experiment_id='EXP7d',
        experiment_name='Rotation Service Impact',
        params={'committee_sizes': list(committee_sizes), 'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_all(use_chain=True):
    """运行实验7全部子实验"""
    print_header("实验7: 陷门继承安全性与轮换影响 (论文 5.5.3)")

    results_7a = run_exp7a_functional_correctness(ch_bits=128)
    results_7b = run_exp7b_cross_epoch_independence(num_epochs=3, ch_bits=128)
    results_7c = run_exp7c_multi_round_stability(
        rotation_counts=(1, 3, 5, 10, 20),
        updates_per_round=10,
        ch_bits=128,
        use_chain=use_chain,
    )
    results_7d = run_exp7d_rotation_service_impact(
        committee_sizes=(4, 6, 8, 10),
        ch_bits=128,
        use_chain=use_chain,
    )

    return {'exp7a': results_7a, 'exp7b': results_7b,
            'exp7c': results_7c, 'exp7d': results_7d}


if __name__ == '__main__':
    run_all()
