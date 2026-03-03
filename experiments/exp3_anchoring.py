"""
实验3: 锚定与快照构建开销评估
对应论文 5.3.4 节

目标: 分别测量域内 Merkle 锚定、GCL 全域聚合、RTL 门限背书三个阶段的
     时间与存储开销, 分析系统在域数量和凭证数量增长时的可扩展性

优先级: P1
"""

import sys
import os
import time
import random
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


def run_exp3a_credential_scale(credential_counts=(100, 500, 1000, 5000, 10000),
                                num_trials=5, use_chain=True):
    """
    实验3a: 域内凭证规模对 Merkle 建树与锚定开销的影响

    自变量: 单域凭证数
    因变量: 叶子哈希时间, 排序时间, 建树时间, 链上锚定时间, 树深度, 存储开销
    """
    print_header("实验3a: 凭证规模 vs 域内锚定开销")
    if use_chain:
        print("  [链上模式] 域根将锚定到 FISCO BCOS")
        fc = _get_chain_client()

    all_results = []
    chain_epoch_counter = int(time.time())  # 使用时间戳作为唯一纪元号

    for n_vc in credential_counts:
        print(f"\n  凭证数 n_vc={n_vc}, 重复 {num_trials} 次")

        trial_results = {
            'leaf_hash_ms': [], 'sort_ms': [], 'build_ms': [],
            'chain_anchor_ms': [], 'chain_query_ms': [],
            'total_ms': [], 'total_with_chain_ms': [],
            'tree_depth': [], 'storage_bytes': [],
        }

        for trial in range(num_trials):
            domain_id = "DCL_A"
            chain_epoch_counter += 1
            epoch = chain_epoch_counter

            # Stage 1: 叶子哈希计算
            t0 = time.perf_counter()
            leaves = []
            for i in range(n_vc):
                leaf = build_credential_leaf(
                    domain_id, epoch, f"did:example:{i}",
                    "Active",
                    hashlib.sha256(f"commit_{i}".encode()).digest()
                )
                leaves.append(leaf)
            leaf_hash_ms = (time.perf_counter() - t0) * 1000

            # Stage 2: 排序
            t0 = time.perf_counter()
            leaves_sorted = sorted(leaves)
            sort_ms = (time.perf_counter() - t0) * 1000

            # Stage 3: Merkle 树构建
            t0 = time.perf_counter()
            tree = MerkleTree()
            tree.leaves = leaves_sorted
            current = leaves_sorted[:]
            tree.layers = [current[:]]
            while len(current) > 1:
                if len(current) % 2 == 1:
                    current.append(current[-1])
                next_layer = []
                for j in range(0, len(current), 2):
                    parent = tree._hash_pair(current[j], current[j + 1])
                    next_layer.append(parent)
                tree.layers.append(next_layer)
                current = next_layer
            tree.root = current[0]
            build_ms = (time.perf_counter() - t0) * 1000

            offchain_total = leaf_hash_ms + sort_ms + build_ms

            # Stage 4: 链上锚定（FISCO BCOS 写交易）
            chain_anchor_ms = 0
            chain_query_ms = 0
            if use_chain:
                sig_placeholder = b"\x00" * 48  # BLS签名占位
                receipt, chain_anchor_ms = fc.anchor_domain_root(
                    domain_id, epoch, tree.root, sig_placeholder, n_vc
                )
                # Stage 5: 链上查询验证
                query_result, chain_query_ms = fc.get_domain_root(domain_id, epoch)

            # 锚定记录
            anchor_record = {
                'domain_id': domain_id,
                'epoch': epoch,
                'root': tree.root.hex(),
                'timestamp': time.time(),
                'leaf_count': n_vc,
                'tree_depth': tree.depth,
            }
            storage = len(json.dumps(anchor_record).encode('utf-8'))

            trial_results['leaf_hash_ms'].append(leaf_hash_ms)
            trial_results['sort_ms'].append(sort_ms)
            trial_results['build_ms'].append(build_ms)
            trial_results['chain_anchor_ms'].append(chain_anchor_ms)
            trial_results['chain_query_ms'].append(chain_query_ms)
            trial_results['total_ms'].append(offchain_total)
            trial_results['total_with_chain_ms'].append(offchain_total + chain_anchor_ms)
            trial_results['tree_depth'].append(tree.depth)
            trial_results['storage_bytes'].append(storage)

        row = {
            'n_vc': n_vc,
            'leaf_hash_ms': round(statistics.mean(trial_results['leaf_hash_ms']), 2),
            'sort_ms': round(statistics.mean(trial_results['sort_ms']), 2),
            'build_ms': round(statistics.mean(trial_results['build_ms']), 2),
            'chain_anchor_ms': round(statistics.mean(trial_results['chain_anchor_ms']), 1),
            'chain_query_ms': round(statistics.mean(trial_results['chain_query_ms']), 2),
            'offchain_total_ms': round(statistics.mean(trial_results['total_ms']), 2),
            'total_with_chain_ms': round(statistics.mean(trial_results['total_with_chain_ms']), 1),
            'tree_depth': trial_results['tree_depth'][0],
            'storage_bytes': trial_results['storage_bytes'][0],
        }
        all_results.append(row)
        if use_chain:
            print(f"    链下: {row['offchain_total_ms']} ms + 链上锚定: {row['chain_anchor_ms']} ms = 总计: {row['total_with_chain_ms']} ms")
        else:
            print(f"    总耗时: {row['offchain_total_ms']} ms, 树深: {row['tree_depth']}")

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP3a',
        experiment_name='Credential Scale vs Anchoring Overhead',
        params={'credential_counts': list(credential_counts)},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp3b_domain_scale(domain_counts=(2, 4, 6, 8, 10, 15, 20),
                            credentials_per_domain=1000,
                            num_trials=5, use_chain=True):
    """
    实验3b: 参与域数对 GCL 全域聚合开销的影响

    自变量: 域数 m
    因变量: 域根收集验证时间, 排序时间, 全域 Merkle 建树时间, 快照构造时间,
           链上域根锚定时间, 链上全局快照锚定时间
    """
    print_header("实验3b: 域数量 vs GCL 聚合开销")
    if use_chain:
        print("  [链上模式] 域根+全局快照将锚定到 FISCO BCOS")
        fc = _get_chain_client()
    all_results = []

    chain_epoch_counter = int(time.time())

    for m in domain_counts:
        print(f"\n  域数 m={m}, 每域 {credentials_per_domain} 凭证")

        trial_results = {
            'domain_anchor_ms': [], 'verify_ms': [], 'sort_ms': [],
            'global_build_ms': [], 'snapshot_ms': [], 'total_ms': [],
            'chain_domain_anchor_ms': [], 'chain_global_anchor_ms': [],
            'chain_query_ms': [], 'total_with_chain_ms': [],
            'snapshot_bytes': [],
        }

        for _ in range(num_trials):
            chain_epoch_counter += 1
            epoch = chain_epoch_counter

            # 阶段1: 各域构建域内锚定 (并行, 取最慢)
            t0 = time.perf_counter()
            domain_roots = []
            for d in range(m):
                leaves = [hashlib.sha256(f"cred_{d}_{i}".encode()).digest()
                          for i in range(credentials_per_domain)]
                tree = MerkleTree()
                root = tree.build(leaves, sort=True)
                domain_roots.append({
                    'domain_id': f"DCL_{d}",
                    'root': root,
                    'epoch': epoch,
                })
            domain_anchor_ms = (time.perf_counter() - t0) * 1000

            # 阶段2: GCL 验证各域锚定记录签名 (模拟)
            t0 = time.perf_counter()
            for dr in domain_roots:
                _ = hashlib.sha256(dr['root']).digest()  # 模拟签名验证
            verify_ms = (time.perf_counter() - t0) * 1000

            # 阶段3: 域根排序
            t0 = time.perf_counter()
            sorted_roots = sorted(domain_roots, key=lambda x: x['domain_id'])
            root_bytes = [dr['root'] for dr in sorted_roots]
            sort_ms = (time.perf_counter() - t0) * 1000

            # 阶段4: 全域 Merkle 树构建
            t0 = time.perf_counter()
            global_tree = MerkleTree()
            global_root = global_tree.build(root_bytes, sort=False)
            global_build_ms = (time.perf_counter() - t0) * 1000

            # 阶段5: 快照元数据构造
            t0 = time.perf_counter()
            snapshot = {
                'epoch': epoch,
                'global_root': global_root.hex(),
                'participating_domains': [dr['domain_id'] for dr in sorted_roots],
                'domain_count': m,
                'timestamp': time.time(),
            }
            snapshot_bytes = len(json.dumps(snapshot).encode('utf-8'))
            snapshot_ms = (time.perf_counter() - t0) * 1000

            offchain_total = domain_anchor_ms + verify_ms + sort_ms + global_build_ms + snapshot_ms

            # 阶段6: 链上锚定 — 各域域根 + 全局快照
            chain_domain_anchor_ms = 0
            chain_global_anchor_ms = 0
            chain_query_ms = 0
            if use_chain:
                sig_placeholder = b"\x00" * 48

                # 6a: 锚定各域域根 (取最慢的一次作为并行耗时)
                domain_tx_times = []
                for dr in domain_roots:
                    _, tx_ms = fc.anchor_domain_root(
                        dr['domain_id'], epoch, dr['root'], sig_placeholder,
                        credentials_per_domain
                    )
                    domain_tx_times.append(tx_ms)
                chain_domain_anchor_ms = max(domain_tx_times)  # 并行取最慢

                # 6b: 锚定全局快照
                _, chain_global_anchor_ms = fc.anchor_global_snapshot(
                    epoch, global_root, sig_placeholder, m
                )

                # 6c: 链上查询验证
                _, chain_query_ms = fc.get_global_snapshot(epoch)

            trial_results['domain_anchor_ms'].append(domain_anchor_ms)
            trial_results['verify_ms'].append(verify_ms)
            trial_results['sort_ms'].append(sort_ms)
            trial_results['global_build_ms'].append(global_build_ms)
            trial_results['snapshot_ms'].append(snapshot_ms)
            trial_results['total_ms'].append(offchain_total)
            trial_results['chain_domain_anchor_ms'].append(chain_domain_anchor_ms)
            trial_results['chain_global_anchor_ms'].append(chain_global_anchor_ms)
            trial_results['chain_query_ms'].append(chain_query_ms)
            trial_results['total_with_chain_ms'].append(
                offchain_total + chain_domain_anchor_ms + chain_global_anchor_ms)
            trial_results['snapshot_bytes'].append(snapshot_bytes)

        row = {
            'm': m,
            'domain_anchor_ms': round(statistics.mean(trial_results['domain_anchor_ms']), 2),
            'verify_ms': round(statistics.mean(trial_results['verify_ms']), 3),
            'sort_ms': round(statistics.mean(trial_results['sort_ms']), 3),
            'global_build_ms': round(statistics.mean(trial_results['global_build_ms']), 3),
            'snapshot_ms': round(statistics.mean(trial_results['snapshot_ms']), 3),
            'offchain_total_ms': round(statistics.mean(trial_results['total_ms']), 2),
            'chain_domain_anchor_ms': round(statistics.mean(trial_results['chain_domain_anchor_ms']), 1),
            'chain_global_anchor_ms': round(statistics.mean(trial_results['chain_global_anchor_ms']), 1),
            'chain_query_ms': round(statistics.mean(trial_results['chain_query_ms']), 2),
            'total_with_chain_ms': round(statistics.mean(trial_results['total_with_chain_ms']), 1),
            'snapshot_bytes': trial_results['snapshot_bytes'][0],
        }
        all_results.append(row)
        if use_chain:
            print(f"    链下: {row['offchain_total_ms']} ms + 域根锚定: {row['chain_domain_anchor_ms']} ms"
                  f" + 全局快照: {row['chain_global_anchor_ms']} ms = 总计: {row['total_with_chain_ms']} ms")
        else:
            print(f"    总耗时: {row['offchain_total_ms']} ms, 快照大小: {row['snapshot_bytes']} B")

    print("\n  结果汇总:")
    if use_chain:
        print_result_table(all_results, ['m', 'domain_anchor_ms', 'global_build_ms',
                                          'chain_domain_anchor_ms', 'chain_global_anchor_ms',
                                          'total_with_chain_ms', 'snapshot_bytes'])
    else:
        print_result_table(all_results, ['m', 'domain_anchor_ms', 'global_build_ms',
                                          'offchain_total_ms', 'snapshot_bytes'])

    result = ExperimentResult(
        experiment_id='EXP3b',
        experiment_name='Domain Scale vs GCL Aggregation',
        params={'domain_counts': list(domain_counts), 'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp3c_rtl_endorsement(committee_sizes=(3, 5, 7, 9),
                               num_trials=3, use_chain=True):
    """
    实验3c: RTL 门限背书开销

    自变量: RTL 委员会规模
    因变量: 门限签名生成时间, 链上全局快照锚定时间, 背书记录大小
    """
    print_header("实验3c: RTL 门限背书开销")
    if use_chain:
        print("  [链上模式] 背书后的全局快照将锚定到 FISCO BCOS")
        fc = _get_chain_client()
    all_results = []

    chain_epoch_counter = int(time.time()) + 100000  # 避免与 exp3b 冲突

    for n in committee_sizes:
        t = max(2, int(n * 0.67) + 1)
        print(f"\n  RTL 委员会 n={n}, 门限 t={t}")

        sign_times = []
        chain_anchor_times = []
        for trial in range(num_trials):
            print(f"    试验 {trial+1}/{num_trials}...")
            chain_epoch_counter += 1
            epoch = chain_epoch_counter

            member_ids = list(range(1, n + 1))
            bls_ts = BLSThresholdSignature(t, n)
            bls_ts.keygen(member_ids)

            # 模拟全域快照根
            snapshot_root = hashlib.sha256(b"global_root_snapshot").digest()

            # 门限签名
            sig, timings = bls_ts.sign_and_time(snapshot_root, member_ids[:t])
            sign_times.append(timings['total_ms'])

            # 链上锚定: 将背书后的全局快照写入链
            chain_anchor_ms = 0
            if use_chain:
                sig_bytes = sig if isinstance(sig, bytes) else b"\x00" * 48
                _, chain_anchor_ms = fc.anchor_global_snapshot(
                    epoch, snapshot_root, sig_bytes, n
                )
                chain_anchor_times.append(chain_anchor_ms)

        row = {
            'n': n,
            't': t,
            'sign_avg_ms': round(statistics.mean(sign_times), 1),
            'sign_min_ms': round(min(sign_times), 1),
            'sign_max_ms': round(max(sign_times), 1),
        }
        if use_chain:
            row['chain_anchor_ms'] = round(statistics.mean(chain_anchor_times), 1)
            row['total_with_chain_ms'] = round(
                statistics.mean(sign_times) + statistics.mean(chain_anchor_times), 1)

        all_results.append(row)
        if use_chain:
            print(f"    平均签名: {row['sign_avg_ms']} ms + 链上锚定: {row['chain_anchor_ms']} ms"
                  f" = 总计: {row['total_with_chain_ms']} ms")
        else:
            print(f"    平均签名时间: {row['sign_avg_ms']} ms")

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP3c',
        experiment_name='RTL Threshold Endorsement',
        params={'committee_sizes': list(committee_sizes), 'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_all(use_chain=True):
    """运行实验3全部子实验"""
    print_header("实验3: 锚定与快照构建开销评估 (论文 5.3.4)")

    results_3a = run_exp3a_credential_scale(
        credential_counts=(100, 500, 1000, 5000, 10000),
        num_trials=5,
        use_chain=use_chain,
    )

    results_3b = run_exp3b_domain_scale(
        domain_counts=(2, 4, 6, 8, 10, 15, 20),
        credentials_per_domain=1000,
        num_trials=5,
        use_chain=use_chain,
    )

    results_3c = run_exp3c_rtl_endorsement(
        committee_sizes=(3, 5, 7),
        num_trials=3,
        use_chain=use_chain,
    )

    return {'exp3a': results_3a, 'exp3b': results_3b, 'exp3c': results_3c}


if __name__ == '__main__':
    run_all()
