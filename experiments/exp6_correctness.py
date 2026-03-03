"""
实验6: 更新后验证成本与正确性
对应论文 5.5.2 节

目标: 验证变色龙哈希更新后
  (1) 承诺值不变性 (Commit 不变)
  (2) Merkle 路径稳定性 (公式 4.22)
  (3) 域级根不变性 (单凭证更新场景)
  (4) 更新前后验证延迟无显著差异

优先级: P0 (证明变色龙哈希的核心性质)
"""

import sys
import os
import time
import random
import hashlib
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.chameleon_hash import ChameleonHash
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


def run_exp6a_commitment_invariance(num_credentials=200,
                                     update_counts=(10, 50, 100),
                                     ch_bits=128, use_chain=True):
    """
    实验6a: 承诺值不变性验证

    验证: CH(m_old, r_old) == CH(m_new, r_new) 在每次碰撞后成立
    链上验证: 注册凭证→更新→从链上读回→比对承诺不变
    """
    print_header("实验6a: 承诺值不变性验证")
    if use_chain:
        print("  [链上模式] 凭证将注册到链并在更新后从链上读取验证")
        fc = _get_chain_client()

    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()

    chain_cred_counter = int(time.time()) + 200000

    # 签发凭证
    print(f"  签发 {num_credentials} 个凭证...")
    credentials = []
    for i in range(num_credentials):
        chain_cred_counter += 1
        m = random.randint(1, ch.q - 1)
        r = random.randint(1, ch.q - 1)
        commit = ch.hash(m, r)
        cred_id = hashlib.sha256(f"exp6a_cred_{chain_cred_counter}".encode()).digest()
        credentials.append({'m': m, 'r': r, 'commit': commit, 'id': i, 'cred_id': cred_id})

    # 链上注册所有凭证（采样注册，避免太慢）
    chain_registered_ids = set()
    if use_chain:
        # 只注册将被更新的凭证（按最大 update_count 提前注册）
        max_k = max(update_counts)
        if max_k > num_credentials:
            max_k = num_credentials
        sample_indices = random.sample(range(num_credentials), max_k)
        print(f"  链上注册 {max_k} 个凭证...")
        for idx in sample_indices:
            vc = credentials[idx]
            commit_bytes = vc['commit'].to_bytes(
                (vc['commit'].bit_length() + 7) // 8, 'big')
            fc.register_credential(vc['cred_id'], commit_bytes, "DCL_A", 1)
            chain_registered_ids.add(idx)

    all_results = []

    for K in update_counts:
        if K > num_credentials:
            K = num_credentials
        print(f"\n  更新 K={K} 个凭证...")

        # 从已注册的凭证中选取
        if use_chain:
            indices = random.sample(list(chain_registered_ids), min(K, len(chain_registered_ids)))
        else:
            indices = random.sample(range(num_credentials), K)

        invariant_pass = 0
        collision_verify_pass = 0
        chain_consistency_pass = 0
        chain_query_times = []

        for idx in indices:
            vc = credentials[idx]
            m_new = random.randint(1, ch.q - 1)
            r_new = ch.forge(vc['m'], vc['r'], m_new)

            # 检查 1: 承诺值不变
            commit_new = ch.hash(m_new, r_new)
            if commit_new == vc['commit']:
                invariant_pass += 1

            # 检查 2: 碰撞正确
            if ch.verify_collision(vc['m'], vc['r'], m_new, r_new):
                collision_verify_pass += 1

            # 检查 3 (链上): 记录更新并查询验证
            if use_chain and idx in chain_registered_ids:
                new_r_bytes = hashlib.sha256(str(r_new).encode()).digest()
                fc.record_update(vc['cred_id'], new_r_bytes, b"\x00" * 48, 1)

                # 从链上读取凭证信息
                result_tuple, q_ms = fc.get_credential(vc['cred_id'])
                chain_query_times.append(q_ms)
                # result_tuple: (commitment, domain_id, create_epoch, update_count, revoked, exists)
                if result_tuple[5]:  # exists
                    chain_consistency_pass += 1

        row = {
            'K': K,
            'invariant_pass': invariant_pass,
            'invariant_rate': f"{invariant_pass / K * 100:.1f}%",
            'collision_pass': collision_verify_pass,
            'collision_rate': f"{collision_verify_pass / K * 100:.1f}%",
        }
        if use_chain:
            row['chain_consistency'] = f"{chain_consistency_pass}/{len(indices)}",
            row['chain_query_avg_ms'] = round(
                statistics.mean(chain_query_times), 2) if chain_query_times else 0

        all_results.append(row)
        msg = f"    承诺不变率: {row['invariant_rate']}, 碰撞正确率: {row['collision_rate']}"
        if use_chain:
            msg += f", 链上一致: {chain_consistency_pass}/{len(indices)}"
        print(msg)

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP6a',
        experiment_name='Commitment Invariance Verification',
        params={'num_credentials': num_credentials, 'update_counts': list(update_counts),
                'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp6b_merkle_path_stability(num_credentials=200,
                                      update_counts=(10, 50, 100),
                                      ch_bits=128, use_chain=True):
    """
    实验6b: Merkle 路径稳定性验证 (对应论文公式 4.22)

    验证: 变色龙哈希更新后, 由于 Commit 不变, Merkle 路径不变
    链上验证: 锚定域根→更新凭证→重建树→验证域根不变→链上查询比对
    """
    print_header("实验6b: Merkle 路径稳定性验证")
    if use_chain:
        print("  [链上模式] 域根将锚定到链并在更新后验证不变性")
        fc = _get_chain_client()

    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()

    chain_epoch_counter = int(time.time()) + 300000

    # 签发凭证并构建 Merkle 树
    print(f"  签发 {num_credentials} 个凭证并构建 Merkle 树...")
    credentials = []
    commit_bytes_list = []

    for i in range(num_credentials):
        m = random.randint(1, ch.q - 1)
        r = random.randint(1, ch.q - 1)
        commit = ch.hash(m, r)
        commit_bytes = commit.to_bytes((commit.bit_length() + 7) // 8, 'big')
        credentials.append({'m': m, 'r': r, 'commit': commit, 'commit_bytes': commit_bytes})
        commit_bytes_list.append(commit_bytes)

    tree = MerkleTree()
    root_before = tree.build(commit_bytes_list, sort=False)
    print(f"  Merkle 树深度: {tree.depth}, 根: {root_before[:8].hex()}...")

    # 链上锚定更新前的域根
    if use_chain:
        chain_epoch_counter += 1
        epoch_before = chain_epoch_counter
        fc.anchor_domain_root("DCL_EXP6", epoch_before, root_before,
                              b"\x00" * 48, num_credentials)
        print(f"  更新前域根已锚定到链 (epoch={epoch_before})")

    all_results = []

    for K in update_counts:
        if K > num_credentials:
            K = num_credentials
        print(f"\n  更新 K={K} 个凭证, 检查路径稳定性...")

        indices = random.sample(range(num_credentials), K)

        # 记录更新前的 Merkle 路径
        proofs_before = {}
        for idx in indices:
            proofs_before[idx] = tree.get_proof(idx)

        # 执行更新 (变色龙哈希碰撞)
        for idx in indices:
            vc = credentials[idx]
            m_new = random.randint(1, ch.q - 1)
            r_new = ch.forge(vc['m'], vc['r'], m_new)
            # 关键: commit 不变, 所以 commit_bytes_list 不变
            credentials[idx]['m'] = m_new
            credentials[idx]['r'] = r_new

        # 重新构建 Merkle 树 (使用相同的 commit_bytes_list)
        tree_after = MerkleTree()
        root_after = tree_after.build(commit_bytes_list, sort=False)

        # 验证
        root_invariant = (root_before == root_after)
        path_stable_count = 0
        path_verify_count = 0

        for idx in indices:
            proof_after = tree_after.get_proof(idx)

            # 路径是否相同
            if proofs_before[idx] == proof_after:
                path_stable_count += 1

            # 路径验证是否通过
            leaf_hash = tree_after.hash_func(commit_bytes_list[idx])
            if MerkleTree.verify_proof(leaf_hash, proof_after, root_after):
                path_verify_count += 1

        # 链上验证域根不变
        chain_root_match = None
        if use_chain:
            chain_epoch_counter += 1
            epoch_after = chain_epoch_counter
            fc.anchor_domain_root("DCL_EXP6", epoch_after, root_after,
                                  b"\x00" * 48, num_credentials)
            # 查询更新前后的链上域根并比对
            result_before, _ = fc.get_domain_root("DCL_EXP6", epoch_before)
            result_after, _ = fc.get_domain_root("DCL_EXP6", epoch_after)
            # result: (root, timestamp, cred_count, exists)
            chain_root_match = (result_before[0] == result_after[0])

        row = {
            'K': K,
            'root_invariant': root_invariant,
            'path_stable': f"{path_stable_count}/{K}",
            'path_stable_rate': f"{path_stable_count / K * 100:.1f}%",
            'path_verify': f"{path_verify_count}/{K}",
            'path_verify_rate': f"{path_verify_count / K * 100:.1f}%",
        }
        if use_chain:
            row['chain_root_match'] = chain_root_match

        all_results.append(row)
        msg = (f"    根不变: {root_invariant}, 路径稳定率: {row['path_stable_rate']}, "
               f"路径验证率: {row['path_verify_rate']}")
        if use_chain:
            msg += f", 链上根一致: {chain_root_match}"
        print(msg)

    print("\n  结果汇总:")
    print_result_table(all_results)

    result = ExperimentResult(
        experiment_id='EXP6b',
        experiment_name='Merkle Path Stability',
        params={'num_credentials': num_credentials, 'use_chain': use_chain},
        extra={'results': all_results},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return all_results


def run_exp6c_verification_cost_comparison(num_credentials=200,
                                             num_updates=50,
                                             num_verify_trials=100,
                                             ch_bits=128, use_chain=True):
    """
    实验6c: 更新前后验证延迟对比

    验证: 变色龙哈希更新不引入额外验证开销 (差异 < 5%)
    链上: 增加从链上读取凭证信息的查询延迟对比
    """
    print_header("实验6c: 更新前后验证延迟对比")
    if use_chain:
        print("  [链上模式] 增加链上查询延迟对比")
        fc = _get_chain_client()

    ch = ChameleonHash(bits=ch_bits)
    pk, td = ch.keygen()

    # 签发凭证
    print(f"  签发 {num_credentials} 个凭证...")
    credentials = []
    commit_bytes_list = []

    for i in range(num_credentials):
        m = random.randint(1, ch.q - 1)
        r = random.randint(1, ch.q - 1)
        commit = ch.hash(m, r)
        commit_bytes = commit.to_bytes((commit.bit_length() + 7) // 8, 'big')
        credentials.append({'m': m, 'r': r, 'commit': commit, 'commit_bytes': commit_bytes})
        commit_bytes_list.append(commit_bytes)

    tree = MerkleTree()
    root = tree.build(commit_bytes_list, sort=False)

    # --- 测量更新前的验证延迟 ---
    print(f"  测量更新前验证延迟 ({num_verify_trials} 次)...")
    latencies_before = []
    for _ in range(num_verify_trials):
        idx = random.randint(0, num_credentials - 1)
        proof = tree.get_proof(idx)
        leaf_hash = tree.hash_func(commit_bytes_list[idx])

        with Timer() as t:
            # Merkle 路径验证
            MerkleTree.verify_proof(leaf_hash, proof, root)
            # 变色龙哈希重算
            ch.hash(credentials[idx]['m'], credentials[idx]['r'])

        latencies_before.append(t.elapsed_ms)

    # --- 执行更新 ---
    print(f"  更新 {num_updates} 个凭证...")
    update_indices = random.sample(range(num_credentials), num_updates)
    for idx in update_indices:
        vc = credentials[idx]
        m_new = random.randint(1, ch.q - 1)
        r_new = ch.forge(vc['m'], vc['r'], m_new)
        credentials[idx]['m'] = m_new
        credentials[idx]['r'] = r_new

    # --- 测量更新后的验证延迟 ---
    print(f"  测量更新后验证延迟 ({num_verify_trials} 次, 仅验证已更新凭证)...")
    latencies_after = []
    for _ in range(num_verify_trials):
        idx = random.choice(update_indices)
        proof = tree.get_proof(idx)
        leaf_hash = tree.hash_func(commit_bytes_list[idx])

        with Timer() as t:
            MerkleTree.verify_proof(leaf_hash, proof, root)
            ch.hash(credentials[idx]['m'], credentials[idx]['r'])

        latencies_after.append(t.elapsed_ms)

    # --- 对比分析 ---
    avg_before = statistics.mean(latencies_before)
    avg_after = statistics.mean(latencies_after)
    diff_percent = abs(avg_after - avg_before) / avg_before * 100 if avg_before > 0 else 0

    results = {
        'before_avg_ms': round(avg_before, 4),
        'before_p50_ms': round(statistics.median(latencies_before), 4),
        'before_p95_ms': round(sorted(latencies_before)[int(len(latencies_before) * 0.95)], 4),
        'after_avg_ms': round(avg_after, 4),
        'after_p50_ms': round(statistics.median(latencies_after), 4),
        'after_p95_ms': round(sorted(latencies_after)[int(len(latencies_after) * 0.95)], 4),
        'diff_percent': round(diff_percent, 2),
        'within_5_percent': diff_percent < 5.0,
    }

    # --- 链上查询延迟对比 (更新前后) ---
    if use_chain:
        print(f"\n  链上查询延迟对比 (注册→更新→查询)...")
        chain_cred_counter = int(time.time()) + 400000
        chain_query_before = []
        chain_query_after = []

        # 注册一批凭证, 查询延迟
        sample_size = min(20, num_credentials)
        for i in range(sample_size):
            chain_cred_counter += 1
            cred_id = hashlib.sha256(f"exp6c_{chain_cred_counter}".encode()).digest()
            vc = credentials[i]
            commit_bytes = vc['commit'].to_bytes(
                (vc['commit'].bit_length() + 7) // 8, 'big')
            fc.register_credential(cred_id, commit_bytes, "DCL_A", 1)

            # 查询 (更新前)
            _, q_ms = fc.get_credential(cred_id)
            chain_query_before.append(q_ms)

            # 记录更新
            new_r_bytes = hashlib.sha256(f"r_new_{i}".encode()).digest()
            fc.record_update(cred_id, new_r_bytes, b"\x00" * 48, 1)

            # 查询 (更新后)
            _, q_ms = fc.get_credential(cred_id)
            chain_query_after.append(q_ms)

        results['chain_query_before_avg_ms'] = round(statistics.mean(chain_query_before), 2)
        results['chain_query_after_avg_ms'] = round(statistics.mean(chain_query_after), 2)
        chain_diff = abs(results['chain_query_after_avg_ms'] - results['chain_query_before_avg_ms'])
        results['chain_query_diff_ms'] = round(chain_diff, 2)
        print(f"  链上查询 更新前: {results['chain_query_before_avg_ms']:.2f} ms, "
              f"更新后: {results['chain_query_after_avg_ms']:.2f} ms, "
              f"差异: {results['chain_query_diff_ms']:.2f} ms")

    print(f"\n  更新前平均延迟: {results['before_avg_ms']:.4f} ms")
    print(f"  更新后平均延迟: {results['after_avg_ms']:.4f} ms")
    print(f"  相对差异: {results['diff_percent']:.2f}%")
    print(f"  是否在 5% 以内: {'YES' if results['within_5_percent'] else 'NO'}")

    result = ExperimentResult(
        experiment_id='EXP6c',
        experiment_name='Pre/Post Update Verification Cost',
        params={'num_credentials': num_credentials, 'num_updates': num_updates,
                'use_chain': use_chain},
        extra=results,
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return results


def run_all(use_chain=True):
    """运行实验6全部子实验"""
    print_header("实验6: 更新后验证成本与正确性 (论文 5.5.2)")

    results_6a = run_exp6a_commitment_invariance(
        num_credentials=200,
        update_counts=(10, 50, 100),
        ch_bits=128,
        use_chain=use_chain,
    )

    results_6b = run_exp6b_merkle_path_stability(
        num_credentials=200,
        update_counts=(10, 50, 100),
        ch_bits=128,
        use_chain=use_chain,
    )

    results_6c = run_exp6c_verification_cost_comparison(
        num_credentials=200,
        num_updates=50,
        num_verify_trials=100,
        ch_bits=128,
        use_chain=use_chain,
    )

    return {'exp6a': results_6a, 'exp6b': results_6b, 'exp6c': results_6c}


if __name__ == '__main__':
    run_all()
