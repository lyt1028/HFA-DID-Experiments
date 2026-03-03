"""
实验5: 更新与撤销执行开销
对应论文 5.5.1 节

目标: 测量变色龙哈希机制下凭证更新和撤销的各阶段延迟,
     并与传统撤销列表(CRL)方案进行对比

优先级: P0 (论文第四章核心贡献)
"""

import sys
import os
import time
import random
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.chameleon_hash import ChameleonHash, ThresholdChameleonHash
from src.crypto.bls_threshold import BLSThresholdSignature
from src.crypto.merkle import MerkleTree
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


def run_exp5a_single_operation(committee_sizes=(4, 6, 8, 10),
                                num_trials=50,
                                ch_bits=128, use_chain=True):
    """
    实验5a: 单次更新/撤销操作各阶段开销分解

    自变量: 委员会规模 n
    因变量: 各阶段延迟 (ms), 链上记录延迟
    """
    print_header("实验5a: 单次操作开销分解")
    if use_chain:
        print("  [链上模式] 更新/撤销记录将写入 FISCO BCOS")
        fc = _get_chain_client()
    all_results = []

    chain_cred_counter = int(time.time())

    for n in committee_sizes:
        t = max(2, int(n * 0.6) + 1)  # 门限
        print(f"\n  委员会规模 n={n}, 门限 t={t}, 试验次数={num_trials}")

        # 初始化变色龙哈希
        print("  [1/4] 初始化变色龙哈希密钥...")
        ch = ChameleonHash(bits=ch_bits)
        pk, td = ch.keygen()

        # 门限分发
        member_ids = list(range(1, n + 1))
        tch = ThresholdChameleonHash(ch, t, n)
        shares = tch.distribute_trapdoor(td, member_ids)

        # 初始化 BLS 门限签名
        print("  [2/4] 初始化 BLS 门限签名...")
        bls_ts = BLSThresholdSignature(t, n)
        bls_ts.keygen(member_ids)

        for op_type in ['Update', 'Revoke']:
            stage_totals = {
                'T_request_verify': [],
                'T_committee_vote': [],
                'T_chameleon_forge': [],
                'T_sign_record': [],
                'T_chain_register': [],
                'T_chain_record': [],
                'T_total': [],
                'T_total_with_chain': [],
            }

            print(f"  [3/4] 执行 {op_type} 操作 x{num_trials}...")

            for trial in range(num_trials):
                chain_cred_counter += 1
                # 生成测试凭证
                m_old = random.randint(1, ch.q - 1)
                r_old = random.randint(1, ch.q - 1)
                commit_old = ch.hash(m_old, r_old)
                m_new = random.randint(1, ch.q - 1)

                # --- Stage 0 (链上): 注册凭证初始承诺 ---
                chain_register_ms = 0
                cred_id = hashlib.sha256(f"cred_{chain_cred_counter}".encode()).digest()
                commit_bytes = commit_old.to_bytes(
                    (commit_old.bit_length() + 7) // 8, 'big')
                if use_chain:
                    _, chain_register_ms = fc.register_credential(
                        cred_id, commit_bytes, "DCL_A", 1
                    )
                stage_totals['T_chain_register'].append(chain_register_ms)

                # --- Stage 1: 请求验证 ---
                with Timer() as t1:
                    # 模拟验证持有人签名 + 状态检查
                    _ = pow(ch.g, random.randint(1, ch.q - 1), ch.p)  # 模拟签名验证
                stage_totals['T_request_verify'].append(t1.elapsed_ms)

                # --- Stage 2: 委员会投票 ---
                with Timer() as t2:
                    # 模拟 t 个节点投票 (收集同意信号)
                    votes = []
                    for mid in member_ids[:t]:
                        votes.append((mid, True))
                    vote_passed = sum(1 for _, v in votes if v) >= t
                stage_totals['T_committee_vote'].append(t2.elapsed_ms)

                # --- Stage 3: 变色龙哈希碰撞计算 ---
                share_subset = {mid: shares[mid] for mid in member_ids[:t]}
                r_new, forge_timings = tch.threshold_forge_timed(
                    share_subset, m_old, r_old, m_new
                )
                stage_totals['T_chameleon_forge'].append(forge_timings['total_ms'])

                # --- Stage 4: 状态更新记录签名 ---
                record_msg = f"{m_new}:{r_new}:{op_type}".encode()
                with Timer() as t4:
                    partial_sigs = {}
                    for mid in member_ids[:t]:
                        partial_sigs[mid] = bls_ts.partial_sign(mid, record_msg)
                    agg_sig = bls_ts.aggregate_partial_sigs(partial_sigs)
                stage_totals['T_sign_record'].append(t4.elapsed_ms)

                offchain_total = (t1.elapsed_ms + t2.elapsed_ms +
                         forge_timings['total_ms'] + t4.elapsed_ms)
                stage_totals['T_total'].append(offchain_total)

                # --- Stage 5 (链上): 记录更新/撤销到链 ---
                chain_record_ms = 0
                if use_chain:
                    sig_bytes = b"\x00" * 48
                    new_r_bytes = hashlib.sha256(str(r_new).encode()).digest()
                    if op_type == 'Update':
                        _, chain_record_ms = fc.record_update(
                            cred_id, new_r_bytes, sig_bytes, 1
                        )
                    else:
                        _, chain_record_ms = fc.record_revocation(
                            cred_id, sig_bytes, 1
                        )
                stage_totals['T_chain_record'].append(chain_record_ms)
                stage_totals['T_total_with_chain'].append(
                    offchain_total + chain_record_ms)

            # 汇总
            import statistics
            row = {
                'n': n,
                't': t,
                'op': op_type,
                'T_request_verify': round(statistics.mean(stage_totals['T_request_verify']), 3),
                'T_committee_vote': round(statistics.mean(stage_totals['T_committee_vote']), 3),
                'T_chameleon_forge': round(statistics.mean(stage_totals['T_chameleon_forge']), 3),
                'T_sign_record': round(statistics.mean(stage_totals['T_sign_record']), 3),
                'T_offchain_total': round(statistics.mean(stage_totals['T_total']), 3),
            }
            if use_chain:
                row['T_chain_register'] = round(statistics.mean(stage_totals['T_chain_register']), 1)
                row['T_chain_record'] = round(statistics.mean(stage_totals['T_chain_record']), 1)
                row['T_total_with_chain'] = round(statistics.mean(stage_totals['T_total_with_chain']), 1)

            all_results.append(row)
            if use_chain:
                print(f"    {op_type}: 链下={row['T_offchain_total']:.3f} ms + "
                      f"链上记录={row['T_chain_record']:.1f} ms = "
                      f"总计={row['T_total_with_chain']:.1f} ms")
            else:
                print(f"    {op_type}: 总延迟 = {row['T_offchain_total']:.3f} ms")

    print("\n  结果汇总:")
    if use_chain:
        print_result_table(all_results, ['n', 't', 'op', 'T_chameleon_forge',
                                          'T_sign_record', 'T_offchain_total',
                                          'T_chain_record', 'T_total_with_chain'])
    else:
        print_result_table(all_results, ['n', 't', 'op', 'T_request_verify',
                                          'T_committee_vote', 'T_chameleon_forge',
                                          'T_sign_record', 'T_offchain_total'])

    # 保存
    result = ExperimentResult(
        experiment_id='EXP5a',
        experiment_name='Single Update/Revoke Overhead',
        params={'committee_sizes': list(committee_sizes), 'num_trials': num_trials,
                'use_chain': use_chain},
        extra={'breakdown': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp5b_batch_performance(batch_sizes=(10, 50, 100),
                                 committee_size=10,
                                 ch_bits=128, use_chain=True):
    """
    实验5b: 批量更新/撤销吞吐率

    自变量: 批量大小
    因变量: 链下TPS, 含链上TPS, 总耗时
    """
    print_header("实验5b: 批量操作吞吐率")
    if use_chain:
        print("  [链上模式] 批量更新将记录到 FISCO BCOS")
        fc = _get_chain_client()

    t = max(2, int(committee_size * 0.6) + 1)
    member_ids = list(range(1, committee_size + 1))

    # 初始化
    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()
    tch = ThresholdChameleonHash(ch, t, committee_size)
    shares = tch.distribute_trapdoor(td, member_ids)

    all_results = []
    chain_cred_counter = int(time.time()) + 500000

    for batch in batch_sizes:
        print(f"\n  批量大小 = {batch}")

        # 链下批量处理
        t0 = time.perf_counter()
        success = 0
        forge_results = []
        for _ in range(batch):
            chain_cred_counter += 1
            m_old = random.randint(1, ch.q - 1)
            r_old = random.randint(1, ch.q - 1)
            m_new = random.randint(1, ch.q - 1)

            share_subset = {mid: shares[mid] for mid in member_ids[:t]}
            r_new = tch.threshold_forge(share_subset, m_old, r_old, m_new)

            if ch.hash(m_old, r_old) == ch.hash(m_new, r_new):
                success += 1

            forge_results.append({
                'cred_id': hashlib.sha256(f"batch_cred_{chain_cred_counter}".encode()).digest(),
                'commit': ch.hash(m_old, r_old),
                'r_new': r_new,
            })

        offchain_time_s = time.perf_counter() - t0
        offchain_tps = batch / offchain_time_s if offchain_time_s > 0 else 0

        # 链上批量记录
        chain_total_ms = 0
        if use_chain:
            for fr in forge_results:
                commit_bytes = fr['commit'].to_bytes(
                    (fr['commit'].bit_length() + 7) // 8, 'big')
                # 注册
                _, reg_ms = fc.register_credential(
                    fr['cred_id'], commit_bytes, "DCL_A", 1)
                # 记录更新
                new_r_bytes = hashlib.sha256(str(fr['r_new']).encode()).digest()
                _, upd_ms = fc.record_update(
                    fr['cred_id'], new_r_bytes, b"\x00" * 48, 1)
                chain_total_ms += reg_ms + upd_ms

        total_time_s = offchain_time_s + chain_total_ms / 1000
        total_tps = batch / total_time_s if total_time_s > 0 else 0

        row = {
            'batch_size': batch,
            'offchain_time_ms': round(offchain_time_s * 1000, 1),
            'offchain_tps': round(offchain_tps, 2),
            'avg_per_item_ms': round(offchain_time_s * 1000 / batch, 3),
            'success_rate': round(success / batch * 100, 1),
        }
        if use_chain:
            row['chain_total_ms'] = round(chain_total_ms, 1)
            row['total_time_ms'] = round(total_time_s * 1000, 1)
            row['total_tps'] = round(total_tps, 2)

        all_results.append(row)
        if use_chain:
            print(f"    链下TPS = {offchain_tps:.2f}, 含链上TPS = {total_tps:.2f}, "
                  f"链上总耗时 = {chain_total_ms:.0f} ms")
        else:
            print(f"    TPS = {offchain_tps:.2f}, 平均每条 = {row['avg_per_item_ms']:.3f} ms")

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP5b',
        experiment_name='Batch Update Throughput',
        params={'batch_sizes': list(batch_sizes), 'committee_size': committee_size,
                'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_all(use_chain=True):
    """运行实验5全部子实验"""
    print_header("实验5: 更新与撤销执行开销 (论文 5.5.1)")
    print("  变色龙哈希位数使用 128-bit (实验速度), 论文中可改为 256-bit")

    results_5a = run_exp5a_single_operation(
        committee_sizes=(4, 6, 8, 10),
        num_trials=30,
        ch_bits=128,
        use_chain=use_chain,
    )

    results_5b = run_exp5b_batch_performance(
        batch_sizes=(10, 50, 100),
        committee_size=8,
        ch_bits=128,
        use_chain=use_chain,
    )

    return {'exp5a': results_5a, 'exp5b': results_5b}


if __name__ == '__main__':
    run_all()
