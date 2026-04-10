"""
实验1+2 (链上版): 核心性能 + 跨域验证
包含真实FISCO BCOS链上锚定与查询操作
"""
import sys, os, json, time, random, statistics, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.crypto.bls_threshold import BLSThresholdSignature
from src.crypto.merkle import MerkleTree
from src.chain.fisco_client import FISCOClient
from src.utils import print_header


def run_exp1(committee_sizes=None, num_trials=3):
    """
    实验1: 核心操作性能 (含链上锚定)
    阶段: DKG初始化 -> 公钥聚合 -> 凭证签发 -> 链上锚定
    """
    if committee_sizes is None:
        committee_sizes = [4, 8, 12, 16, 20]

    print_header("Exp1: Core Performance (with on-chain anchoring)")

    fc = FISCOClient()
    fc.init()
    epoch_counter = int(time.time())

    results = []
    for n in committee_sizes:
        t = max(2, int(n * 0.6) + 1)
        member_ids = list(range(1, n + 1))
        print("\n  n=%d, t=%d, trials=%d" % (n, t, num_trials))

        init_times, issue_times, anchor_times, query_times = [], [], [], []

        for trial in range(num_trials):
            # DKG init
            bls = BLSThresholdSignature(threshold=t, num_members=n)
            t0 = time.perf_counter()
            bls.keygen(member_ids)
            init_times.append((time.perf_counter() - t0) * 1000)

            # Credential issuance (BLS threshold sign)
            msg = ("vc_n%d_trial%d" % (n, trial)).encode()
            signer_ids = member_ids[:t]
            _, timings = bls.sign_and_time(msg, signer_ids)
            issue_times.append(timings['total_ms'])

            # On-chain anchoring
            cred_hash = hashlib.sha256(msg).digest()
            tree = MerkleTree()
            leaves = [hashlib.sha256(("vc_%d" % i).encode()).digest() for i in range(100)]
            root = tree.build(leaves, sort=False)
            sig_bytes = b"\x00" * 48

            epoch_counter += 1
            domain_id = "DCL_exp1_n%d" % n

            t0 = time.perf_counter()
            fc.anchor_domain_root(domain_id, epoch_counter, root, sig_bytes, 100)
            anchor_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            fc.get_domain_root(domain_id, epoch_counter)
            query_times.append((time.perf_counter() - t0) * 1000)

        result = {
            'n': n, 't': t,
            'init_ms': round(statistics.mean(init_times), 1),
            'issue_ms': round(statistics.mean(issue_times), 1),
            'anchor_ms': round(statistics.mean(anchor_times), 1),
            'query_ms': round(statistics.mean(query_times), 1),
        }
        results.append(result)
        print("    Init=%.1fms, Issue=%.1fms, Anchor=%.1fms, Query=%.1fms" % (
            result['init_ms'], result['issue_ms'], result['anchor_ms'], result['query_ms']))

    fc.close()
    return results


def run_exp2(domain_counts=None, credentials_per_domain=1000, num_trials=30):
    """
    实验2: 跨域验证 (含链上操作)
    HFA-DID: 链上查询全域快照 + Merkle验证
    Cross-Chain: 逐域链上查询 + SPV验证
    """
    if domain_counts is None:
        domain_counts = [2, 5, 10, 15, 20, 30]

    print_header("Exp2: Cross-Domain Verification (with on-chain ops)")

    fc = FISCOClient()
    fc.init()
    epoch_base = int(time.time()) + 100000

    results = []

    for m in domain_counts:
        print("\n  m=%d domains, %d trials..." % (m, num_trials))

        # Pre-build: anchor all domain roots and global snapshot
        domain_roots = []
        domain_trees = []
        for d in range(m):
            leaves = [hashlib.sha256(("vc_%d_%d" % (d, i)).encode()).digest()
                      for i in range(credentials_per_domain)]
            tree = MerkleTree()
            root = tree.build(leaves, sort=False)
            domain_roots.append(root)
            domain_trees.append(tree)
            # Anchor each domain root
            fc.anchor_domain_root("DCL_d%d" % d, epoch_base + m, root, b"\x00" * 48,
                                  credentials_per_domain)

        # Build and anchor global snapshot
        global_tree = MerkleTree()
        global_root = global_tree.build(domain_roots, sort=False)
        fc.anchor_global_snapshot(epoch_base + m, global_root, b"\x00" * 48, m)

        hfa_lats, cross_lats = [], []

        for trial in range(num_trials):
            target_domain = random.randint(0, m - 1)
            target_vc = random.randint(0, credentials_per_domain - 1)

            # === HFA-DID: query GCL snapshot + dual Merkle ===
            t0 = time.perf_counter()
            # 1. Chain query: global snapshot
            fc.get_global_snapshot(epoch_base + m)
            # 2. Global Merkle proof
            gproof = global_tree.get_proof(target_domain)
            gleaf = global_tree.hash_func(domain_roots[target_domain])
            MerkleTree.verify_proof(gleaf, gproof, global_root)
            # 3. Domain Merkle proof
            dproof = domain_trees[target_domain].get_proof(target_vc)
            dleaf = domain_trees[target_domain].hash_func(
                hashlib.sha256(("vc_%d_%d" % (target_domain, target_vc)).encode()).digest())
            MerkleTree.verify_proof(dleaf, dproof, domain_trees[target_domain].root)
            hfa_ms = (time.perf_counter() - t0) * 1000
            hfa_lats.append(hfa_ms)

            # === Cross-Chain: query each domain ===
            t0 = time.perf_counter()
            # Query each domain's root from chain (simulates relay per domain)
            for d in range(m):
                fc.get_domain_root("DCL_d%d" % d, epoch_base + m)
            # Verify target credential
            dproof2 = domain_trees[target_domain].get_proof(target_vc)
            dleaf2 = domain_trees[target_domain].hash_func(
                hashlib.sha256(("vc_%d_%d" % (target_domain, target_vc)).encode()).digest())
            MerkleTree.verify_proof(dleaf2, dproof2, domain_trees[target_domain].root)
            cross_ms = (time.perf_counter() - t0) * 1000
            cross_lats.append(cross_ms)

        hfa_avg = statistics.mean(hfa_lats)
        cross_avg = statistics.mean(cross_lats)
        speedup = cross_avg / hfa_avg if hfa_avg > 0 else 0

        result = {
            'm': m,
            'hfa_avg_ms': round(hfa_avg, 2),
            'cross_avg_ms': round(cross_avg, 2),
            'speedup': round(speedup, 2),
        }
        results.append(result)
        print("    HFA-DID: %.2fms, Cross-Chain: %.2fms, speedup: %.1fx" % (
            hfa_avg, cross_avg, speedup))

    fc.close()
    return results


def run_all(save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)

    exp1 = run_exp1(num_trials=3)
    exp2 = run_exp2(num_trials=30)

    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, 'EXP_chain_' + ts + '.json')
    with open(filepath, 'w') as f:
        json.dump({'exp1': exp1, 'exp2': exp2}, f, indent=2)
    print("\nResults saved: " + filepath)

    return {'exp1': exp1, 'exp2': exp2}


if __name__ == '__main__':
    run_all()
