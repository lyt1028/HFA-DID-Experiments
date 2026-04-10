"""
实验3: RA-ReDKG乐观路径 vs 完整路径对比
对应小论文 7.4 节

目标: 量化不同留存率下两种轮转路径的延迟与通信开销差异

输出:
  图6(a): 不同留存率下两条路径的轮转延迟对比
  图6(b): 通信消息数对比
"""

import sys, os, json, time, random, statistics

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.crypto.shamir import ShamirSecretSharing
from src.crypto.redkg import ReDKG
from src.utils import print_header


def run_path_comparison(n=20, threshold=11, num_trials=5):
    """
    对比乐观路径与完整路径在不同留存率下的性能

    自变量: 留存率 rho in {0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
    因变量: 轮转延迟(ms), 通信消息数
    """
    print_header("Exp: Optimistic vs Full Path Comparison")

    q = 2**127 - 1
    sss = ShamirSecretSharing(q)
    secret = random.randint(1, q - 1)

    retention_rates = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    results = []

    for rho in retention_rates:
        n_stay = int(n * rho)
        n_join = n - n_stay
        n_exit = n_join  # keep committee size constant

        old_ids = list(range(1, n + 1))
        stay_ids = old_ids[:n_stay]
        exit_ids = old_ids[n_stay:]
        join_ids = list(range(n + 1, n + 1 + n_join))
        new_ids = stay_ids + join_ids

        print(f"\n  rho={rho:.1f}: stay={n_stay}, join={n_join}, exit={n_exit}")

        # 初始份额
        old_shares = sss.split(secret, threshold, n, old_ids)

        # 完整路径
        full_timings_list = []
        for trial in range(num_trials):
            redkg = ReDKG(q, threshold)
            _, timings = redkg.rotate_full(old_ids, new_ids, old_shares)
            full_timings_list.append(timings)

        # 乐观路径 (仅当 rho >= 0.7 且 n_stay >= threshold)
        opt_timings_list = []
        if rho >= 0.7 and n_stay >= threshold:
            for trial in range(num_trials):
                redkg = ReDKG(q, threshold)
                _, timings = redkg.rotate_optimistic(old_ids, new_ids, old_shares)
                opt_timings_list.append(timings)

        # 汇总
        full_avg = statistics.mean(t['total_ms'] for t in full_timings_list)
        full_comm = full_timings_list[0]['comm_messages']
        full_p1 = statistics.mean(t['phase1_redistribute_ms'] for t in full_timings_list)
        full_p2 = statistics.mean(t['phase2_aggregate_ms'] for t in full_timings_list)
        full_p3 = statistics.mean(t['phase3_verify_ms'] for t in full_timings_list)

        result = {
            'rho': rho,
            'n_stay': n_stay,
            'n_join': n_join,
            'full_total_ms': round(full_avg, 2),
            'full_p1_ms': round(full_p1, 2),
            'full_p2_ms': round(full_p2, 2),
            'full_p3_ms': round(full_p3, 2),
            'full_comm': full_comm,
        }

        if opt_timings_list:
            opt_avg = statistics.mean(t['total_ms'] for t in opt_timings_list)
            opt_comm = opt_timings_list[0]['comm_messages']
            opt_p1 = statistics.mean(t['phase1_perturb_ms'] for t in opt_timings_list)
            opt_p2 = statistics.mean(t['phase2_aggregate_ms'] for t in opt_timings_list)
            opt_p3 = statistics.mean(t['phase3_verify_ms'] for t in opt_timings_list)
            speedup = full_avg / opt_avg if opt_avg > 0 else 0
            comm_reduction = (1 - opt_comm / full_comm) * 100 if full_comm > 0 else 0

            result.update({
                'opt_total_ms': round(opt_avg, 2),
                'opt_p1_ms': round(opt_p1, 2),
                'opt_p2_ms': round(opt_p2, 2),
                'opt_p3_ms': round(opt_p3, 2),
                'opt_comm': opt_comm,
                'speedup': round(speedup, 2),
                'comm_reduction_pct': round(comm_reduction, 1),
            })
            print(f"    Full:  {full_avg:.1f}ms, {full_comm} msgs")
            print(f"    Opt:   {opt_avg:.1f}ms, {opt_comm} msgs")
            print(f"    Speedup: {speedup:.2f}x, Comm reduction: {comm_reduction:.1f}%")
        else:
            result.update({
                'opt_total_ms': None,
                'opt_comm': None,
                'speedup': None,
                'comm_reduction_pct': None,
            })
            print(f"    Full:  {full_avg:.1f}ms, {full_comm} msgs")
            print(f"    Opt:   N/A (n_stay={n_stay} < threshold={threshold})")

        results.append(result)

    return results


def run_scale_comparison(committee_sizes=None, threshold_ratio=0.55, rho=0.8, num_trials=5):
    """
    固定留存率, 测试不同委员会规模下两条路径的延迟

    自变量: n in {10, 15, 20, 25, 30}
    """
    if committee_sizes is None:
        committee_sizes = [10, 15, 20, 25, 30]

    print_header("Exp: Path Comparison vs Committee Size")

    q = 2**127 - 1
    sss = ShamirSecretSharing(q)
    results = []

    for n in committee_sizes:
        t = max(2, int(n * threshold_ratio) + 1)
        n_stay = int(n * rho)
        n_join = n - n_stay
        secret = random.randint(1, q - 1)

        old_ids = list(range(1, n + 1))
        stay_ids = old_ids[:n_stay]
        join_ids = list(range(n + 1, n + 1 + n_join))
        new_ids = stay_ids + join_ids

        old_shares = sss.split(secret, t, n, old_ids)

        print(f"\n  n={n}, t={t}, rho={rho}, stay={n_stay}, join={n_join}")

        # Full
        full_lats = []
        full_comm = 0
        for trial in range(num_trials):
            redkg = ReDKG(q, t)
            _, timings = redkg.rotate_full(old_ids, new_ids, old_shares)
            full_lats.append(timings['total_ms'])
            full_comm = timings['comm_messages']

        # Optimistic
        opt_lats = []
        opt_comm = 0
        if n_stay >= t:
            for trial in range(num_trials):
                redkg = ReDKG(q, t)
                _, timings = redkg.rotate_optimistic(old_ids, new_ids, old_shares)
                opt_lats.append(timings['total_ms'])
                opt_comm = timings['comm_messages']

        result = {
            'n': n, 't': t, 'rho': rho,
            'full_ms': round(statistics.mean(full_lats), 2),
            'full_comm': full_comm,
            'opt_ms': round(statistics.mean(opt_lats), 2) if opt_lats else None,
            'opt_comm': opt_comm if opt_lats else None,
        }
        if opt_lats:
            result['speedup'] = round(statistics.mean(full_lats) / statistics.mean(opt_lats), 2)
        results.append(result)

        print(f"    Full: {result['full_ms']:.1f}ms ({full_comm} msgs)")
        if opt_lats:
            print(f"    Opt:  {result['opt_ms']:.1f}ms ({opt_comm} msgs), speedup={result['speedup']:.2f}x")

    return results


def run_all(save_dir=None):
    print_header("Exp: RA-ReDKG Path Comparison")

    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)

    part_a = run_path_comparison(n=20, threshold=11, num_trials=5)
    part_b = run_scale_comparison(committee_sizes=[10, 15, 20, 25, 30], num_trials=5)

    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, f'EXP_redkg_path_{ts}.json')
    with open(filepath, 'w') as f:
        json.dump({'part_a': part_a, 'part_b': part_b}, f, indent=2)
    print(f"\nResults saved: {filepath}")

    return {'part_a': part_a, 'part_b': part_b}


if __name__ == '__main__':
    run_all()
