"""
实验2 修正版: 跨域验证完整流程对比
包含BLS验签、Merkle验证、链上查询、网络延迟

HFA-DID验证流程:
  1. 查询GCL全域快照 (1次链上查询 + 网络延迟)
  2. 全域Merkle路径验证
  3. 域内Merkle路径验证
  4. BLS门限签名验证
  5. (可选) RCP治理状态验证

Cross-Chain验证流程:
  1. 中继路由发现 (固定开销)
  2. 逐域SPV查询 (m次链上查询 + 每跳网络延迟)
  3. SPV区块头验证 (每域)
  4. 域内Merkle路径验证
  5. BLS门限签名验证
"""
import sys, os, json, time, random, statistics, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.crypto.bls_threshold import BLSThresholdSignature
from src.crypto.merkle import MerkleTree
from src.chain.fisco_client import FISCOClient
from src.utils import print_header


# 网络延迟参数 (ms)
NET_VERIFIER_TO_GCL = 5.0       # 验证者到GCL的网络延迟
NET_RELAY_PER_HOP = 10.0        # 跨链中继每跳延迟
NET_RELAY_DISCOVERY = 15.0      # 中继路由发现固定开销
SPV_HEADER_VERIFY_MS = 2.0      # SPV区块头哈希验证 (每域)


def run_exp2_full(domain_counts=None, credentials_per_domain=1000,
                  committee_size=6, num_trials=10):
    if domain_counts is None:
        domain_counts = [2, 5, 10, 15, 20, 30]

    print_header("Exp2: Full Cross-Domain Verification Comparison")

    # Init BLS for signature verification measurement
    t_val = max(2, int(committee_size * 0.6) + 1)
    member_ids = list(range(1, committee_size + 1))
    bls = BLSThresholdSignature(threshold=t_val, num_members=committee_size)
    bls.keygen(member_ids)

    # Pre-sign a credential for verification benchmarks
    test_msg = b"benchmark_credential_content"
    test_sig, _ = bls.sign_and_time(test_msg, member_ids[:t_val])

    # Measure BLS verify cost (one-time benchmark)
    bls_verify_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        bls.verify(test_msg, test_sig)
        bls_verify_times.append((time.perf_counter() - t0) * 1000)
    bls_verify_ms = statistics.mean(bls_verify_times)
    print("  BLS verify benchmark: %.1f ms" % bls_verify_ms)

    # Init chain
    fc = FISCOClient()
    fc.init()
    epoch_base = int(time.time()) + 200000

    # Measure chain query cost (one-time benchmark)
    fc.anchor_domain_root("bench", epoch_base, hashlib.sha256(b"x").digest(),
                          b"\x00" * 48, 1)
    chain_query_times = []
    for _ in range(10):
        t0 = time.perf_counter()
        fc.get_domain_root("bench", epoch_base)
        chain_query_times.append((time.perf_counter() - t0) * 1000)
    chain_query_ms = statistics.mean(chain_query_times)
    print("  Chain query benchmark: %.1f ms" % chain_query_ms)

    results = []

    for m in domain_counts:
        print("\n  m=%d domains, %d trials..." % (m, num_trials))

        # Pre-build domain trees and anchor
        domain_roots = []
        domain_trees = []
        for d in range(m):
            leaves = [hashlib.sha256(("vc_%d_%d" % (d, i)).encode()).digest()
                      for i in range(credentials_per_domain)]
            tree = MerkleTree()
            root = tree.build(leaves, sort=False)
            domain_roots.append(root)
            domain_trees.append(tree)
            fc.anchor_domain_root("D%d" % d, epoch_base + m, root,
                                  b"\x00" * 48, credentials_per_domain)

        global_tree = MerkleTree()
        global_root = global_tree.build(domain_roots, sort=False)
        fc.anchor_global_snapshot(epoch_base + m, global_root, b"\x00" * 48, m)

        hfa_details = []
        cross_details = []

        for trial in range(num_trials):
            target_d = random.randint(0, m - 1)
            target_vc = random.randint(0, credentials_per_domain - 1)

            # ============================================
            # HFA-DID complete verification
            # ============================================
            hfa_breakdown = {}

            # Step 1: Query GCL snapshot (chain query + network)
            t0 = time.perf_counter()
            fc.get_global_snapshot(epoch_base + m)
            hfa_breakdown['chain_query'] = (time.perf_counter() - t0) * 1000
            hfa_breakdown['network'] = NET_VERIFIER_TO_GCL

            # Step 2: Global Merkle proof
            t0 = time.perf_counter()
            gproof = global_tree.get_proof(target_d)
            gleaf = global_tree.hash_func(domain_roots[target_d])
            MerkleTree.verify_proof(gleaf, gproof, global_root)
            hfa_breakdown['global_merkle'] = (time.perf_counter() - t0) * 1000

            # Step 3: Domain Merkle proof
            t0 = time.perf_counter()
            dproof = domain_trees[target_d].get_proof(target_vc)
            dleaf = domain_trees[target_d].hash_func(
                hashlib.sha256(("vc_%d_%d" % (target_d, target_vc)).encode()).digest())
            MerkleTree.verify_proof(dleaf, dproof, domain_trees[target_d].root)
            hfa_breakdown['domain_merkle'] = (time.perf_counter() - t0) * 1000

            # Step 4: BLS signature verification
            t0 = time.perf_counter()
            bls.verify(test_msg, test_sig)
            hfa_breakdown['bls_verify'] = (time.perf_counter() - t0) * 1000

            hfa_breakdown['total'] = sum(hfa_breakdown.values())
            hfa_details.append(hfa_breakdown)

            # ============================================
            # Cross-Chain relay verification
            # ============================================
            cross_breakdown = {}

            # Step 1: Relay route discovery (fixed)
            cross_breakdown['relay_discovery'] = NET_RELAY_DISCOVERY

            # Step 2: Query each domain via relay (m chain queries + network per hop)
            t0 = time.perf_counter()
            for d in range(m):
                fc.get_domain_root("D%d" % d, epoch_base + m)
            cross_breakdown['chain_queries'] = (time.perf_counter() - t0) * 1000
            cross_breakdown['network'] = m * NET_RELAY_PER_HOP

            # Step 3: SPV header verification per domain
            cross_breakdown['spv_verify'] = m * SPV_HEADER_VERIFY_MS

            # Step 4: Domain Merkle proof (same as HFA-DID)
            t0 = time.perf_counter()
            dproof2 = domain_trees[target_d].get_proof(target_vc)
            dleaf2 = domain_trees[target_d].hash_func(
                hashlib.sha256(("vc_%d_%d" % (target_d, target_vc)).encode()).digest())
            MerkleTree.verify_proof(dleaf2, dproof2, domain_trees[target_d].root)
            cross_breakdown['domain_merkle'] = (time.perf_counter() - t0) * 1000

            # Step 5: BLS verification (same cost)
            t0 = time.perf_counter()
            bls.verify(test_msg, test_sig)
            cross_breakdown['bls_verify'] = (time.perf_counter() - t0) * 1000

            cross_breakdown['total'] = sum(cross_breakdown.values())
            cross_details.append(cross_breakdown)

        # Aggregate
        hfa_avg = statistics.mean(d['total'] for d in hfa_details)
        cross_avg = statistics.mean(d['total'] for d in cross_details)
        speedup = cross_avg / hfa_avg if hfa_avg > 0 else 0

        # Breakdown averages
        hfa_bk = {}
        for key in hfa_details[0]:
            hfa_bk[key] = round(statistics.mean(d[key] for d in hfa_details), 2)
        cross_bk = {}
        for key in cross_details[0]:
            cross_bk[key] = round(statistics.mean(d[key] for d in cross_details), 2)

        result = {
            'm': m,
            'hfa_total_ms': round(hfa_avg, 1),
            'cross_total_ms': round(cross_avg, 1),
            'speedup': round(speedup, 2),
            'hfa_breakdown': hfa_bk,
            'cross_breakdown': cross_bk,
        }
        results.append(result)

        print("    HFA-DID: %.1fms (query=%.1f, net=%.1f, merkle=%.1f, bls=%.1f)" % (
            hfa_avg, hfa_bk['chain_query'], hfa_bk['network'],
            hfa_bk['global_merkle'] + hfa_bk['domain_merkle'], hfa_bk['bls_verify']))
        print("    Cross:   %.1fms (relay=%.1f, queries=%.1f, net=%.1f, spv=%.1f, bls=%.1f)" % (
            cross_avg, cross_bk['relay_discovery'], cross_bk['chain_queries'],
            cross_bk['network'], cross_bk['spv_verify'], cross_bk['bls_verify']))
        print("    Speedup: %.1fx" % speedup)

    fc.close()
    return results


def run_all(save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)

    results = run_exp2_full(num_trials=10)

    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, 'EXP2_cross_full_' + ts + '.json')
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)
    print("\nResults saved: " + filepath)
    return results


if __name__ == '__main__':
    run_all()
