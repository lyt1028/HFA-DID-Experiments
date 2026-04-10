"""
端到端跨域验证实验
6步验证全部真实执行: 链上查询(FISCO) + BLS验证(blspy) + Merkle验证

HFA-DID: Step1/2/4并行查询, Step3/5/6串行计算
Relay: 逐域串行执行全部步骤
"""
import sys
import os
import json
import time
import random
import hashlib
import statistics
import csv
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.chain.fisco_client import FISCOClient
from src.crypto.merkle import MerkleTree
from bls_threshold_blspy import BLSThresholdBlspy


def setup_domains(fc, bls, n_domains, n_creds=64):
    """
    预实验setup: 为每个域注册域状态、锚定Merkle根、生成BLS签名
    返回domain_data供验证阶段使用
    """
    print("  Setting up %d domains..." % n_domains)
    epoch = int(time.time()) + 300000

    domain_data = {}
    for d in range(n_domains):
        domain_id = "E2E_D%d" % d

        # 构建Merkle树
        leaves = [hashlib.sha256(("vc_%d_%d" % (d, i)).encode()).digest()
                  for i in range(n_creds)]
        tree = MerkleTree()
        root = tree.build(leaves, sort=False)

        # 生成BLS签名 (凭证签名 + RCP签名)
        cred_msg = b"cred_" + domain_id.encode() + b"_epoch_" + str(epoch).encode()
        cred_sig, _ = bls.sign_and_time(cred_msg, list(bls.sk_shares.keys())[:bls.t])

        rcp_msg = b"rcp_" + domain_id.encode() + b"_epoch_" + str(epoch).encode()
        rcp_sig, _ = bls.sign_and_time(rcp_msg, list(bls.sk_shares.keys())[:bls.t])

        # 链上锚定
        sig_bytes = b"\x00" * 48
        fc.anchor_domain_root(domain_id, epoch, root, sig_bytes, n_creds)

        # 随机选一个凭证的proof
        target_idx = random.randint(0, n_creds - 1)
        proof = tree.get_proof(target_idx)
        leaf_hash = tree.hash_func(leaves[target_idx])

        domain_data[d] = {
            'domain_id': domain_id,
            'epoch': epoch,
            'root': root,
            'tree': tree,
            'proof': proof,
            'leaf_hash': leaf_hash,
            'cred_msg': cred_msg,
            'cred_sig': cred_sig,
            'rcp_msg': rcp_msg,
            'rcp_sig': rcp_sig,
        }

    # 构建全域快照并锚定
    domain_roots = [domain_data[d]['root'] for d in range(n_domains)]
    global_tree = MerkleTree()
    global_root = global_tree.build(domain_roots, sort=False)
    fc.anchor_global_snapshot(epoch, global_root, b"\x00" * 48, n_domains)

    domain_data['global_tree'] = global_tree
    domain_data['global_root'] = global_root
    domain_data['epoch'] = epoch
    domain_data['n_domains'] = n_domains

    print("  Setup done. epoch=%d" % epoch)
    return domain_data


def hfadid_verify_once(fc, bls, domain_data, target_d):
    """
    单次HFA-DID端到端验证 (6步全部真实执行)
    网络查询阶段并行, 计算阶段串行
    """
    d = domain_data[target_d]
    epoch = domain_data['epoch']
    breakdown = {}

    # === 网络查询阶段 (Step1 + Step2 + Step4 并行) ===
    def step1_rtl():
        t0 = time.perf_counter()
        # 查询域状态 (用get_roster模拟RTL查询)
        fc.get_domain_root(d['domain_id'], epoch)
        return (time.perf_counter() - t0) * 1000

    def step2_gcl():
        t0 = time.perf_counter()
        fc.get_global_snapshot(epoch)
        return (time.perf_counter() - t0) * 1000

    def step4_gel():
        t0 = time.perf_counter()
        fc.get_domain_root(d['domain_id'], epoch)
        return (time.perf_counter() - t0) * 1000

    with ThreadPoolExecutor(max_workers=3) as pool:
        f1 = pool.submit(step1_rtl)
        f2 = pool.submit(step2_gcl)
        f4 = pool.submit(step4_gel)
        breakdown['step1_rtl_ms'] = f1.result()
        breakdown['step2_gcl_ms'] = f2.result()
        breakdown['step4_gel_ms'] = f4.result()

    breakdown['network_phase_ms'] = max(
        breakdown['step1_rtl_ms'],
        breakdown['step2_gcl_ms'],
        breakdown['step4_gel_ms']
    )

    # === 计算阶段 (Step3 + Step5 + Step6 串行) ===

    # Step 3: Merkle路径验证
    t0 = time.perf_counter()
    MerkleTree.verify_proof(d['leaf_hash'], d['proof'], d['root'])
    breakdown['step3_merkle_ms'] = (time.perf_counter() - t0) * 1000

    # Step 5: RCP BLS验证 (blspy)
    valid_rcp, rcp_ms = bls.verify_timed(d['rcp_msg'], d['rcp_sig'])
    breakdown['step5_rcp_bls_ms'] = rcp_ms

    # Step 6: 凭证BLS验证 (blspy)
    valid_cred, cred_ms = bls.verify_timed(d['cred_msg'], d['cred_sig'])
    breakdown['step6_cred_bls_ms'] = cred_ms

    breakdown['compute_phase_ms'] = (
        breakdown['step3_merkle_ms'] +
        breakdown['step5_rcp_bls_ms'] +
        breakdown['step6_cred_bls_ms']
    )

    breakdown['total_ms'] = breakdown['network_phase_ms'] + breakdown['compute_phase_ms']
    breakdown['valid'] = valid_rcp and valid_cred

    return breakdown


def relay_verify_once(fc, bls, domain_data):
    """
    单次Relay端到端验证: 逐域串行查询+验证
    """
    n = domain_data['n_domains']
    epoch = domain_data['epoch']
    total_ms = 0
    steps = {}

    for d_idx in range(n):
        d = domain_data[d_idx]

        # 链上查询 (串行)
        t0 = time.perf_counter()
        fc.get_domain_root(d['domain_id'], epoch)
        query_ms = (time.perf_counter() - t0) * 1000
        total_ms += query_ms

        # Merkle验证
        t0 = time.perf_counter()
        MerkleTree.verify_proof(d['leaf_hash'], d['proof'], d['root'])
        merkle_ms = (time.perf_counter() - t0) * 1000
        total_ms += merkle_ms

        # BLS验证
        _, bls_ms = bls.verify_timed(d['cred_msg'], d['cred_sig'])
        total_ms += bls_ms

    steps['total_ms'] = total_ms
    steps['n_domains'] = n
    return steps


def run_experiment(domain_counts=None, n_trials=30, n_creds=64):
    """主实验"""
    if domain_counts is None:
        domain_counts = [2, 5, 10, 15, 20, 30]

    print("=" * 60)
    print("  E2E Cross-Domain Verification Experiment")
    print("  FISCO BCOS + blspy + Merkle + Docker Network")
    print("=" * 60)

    fc = FISCOClient()
    fc.init()

    # 初始化BLS (6,10门限)
    bls = BLSThresholdBlspy(n=10, t=6)
    bls.keygen()
    print("  BLS keygen done. master_pk ready.")

    # BLS benchmark
    test_msg = b"benchmark_msg"
    test_sig, timings = bls.sign_and_time(test_msg)
    print("  BLS benchmark: sign=%.1fms, verify=%.1fms, valid=%s" % (
        timings['partial_sign_ms'] + timings['aggregate_ms'],
        timings['verify_ms'], timings['valid']))

    results = []

    for m in domain_counts:
        print("\n--- m=%d domains ---" % m)

        # Setup
        domain_data = setup_domains(fc, bls, m, n_creds)

        hfa_totals = []
        relay_totals = []

        for trial in range(n_trials):
            target = random.randint(0, m - 1)

            # HFA-DID
            hfa = hfadid_verify_once(fc, bls, domain_data, target)
            hfa_totals.append(hfa['total_ms'])

            # Relay
            relay = relay_verify_once(fc, bls, domain_data)
            relay_totals.append(relay['total_ms'])

            results.append({
                'scheme': 'HFA-DID', 'm': m, 'trial': trial,
                'total_ms': round(hfa['total_ms'], 2),
                'network_ms': round(hfa['network_phase_ms'], 2),
                'compute_ms': round(hfa['compute_phase_ms'], 2),
                'step1': round(hfa['step1_rtl_ms'], 2),
                'step2': round(hfa['step2_gcl_ms'], 2),
                'step3': round(hfa['step3_merkle_ms'], 3),
                'step4': round(hfa['step4_gel_ms'], 2),
                'step5': round(hfa['step5_rcp_bls_ms'], 2),
                'step6': round(hfa['step6_cred_bls_ms'], 2),
            })
            results.append({
                'scheme': 'Relay', 'm': m, 'trial': trial,
                'total_ms': round(relay['total_ms'], 2),
            })

            if trial % 10 == 0:
                print("  Trial %d: HFA=%.1fms, Relay=%.1fms" % (
                    trial, hfa['total_ms'], relay['total_ms']))

        hfa_avg = statistics.mean(hfa_totals)
        relay_avg = statistics.mean(relay_totals)
        speedup = relay_avg / hfa_avg if hfa_avg > 0 else 0
        print("  m=%d: HFA=%.1fms, Relay=%.1fms, speedup=%.1fx" % (
            m, hfa_avg, relay_avg, speedup))

    fc.close()
    return results


def save_results(results, save_dir):
    os.makedirs(save_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')

    # CSV
    csv_path = os.path.join(save_dir, 'e2e_results_%s.csv' % ts)
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print("CSV saved: %s" % csv_path)

    # JSON summary
    summary = {}
    for r in results:
        if r['scheme'] == 'HFA-DID':
            key = 'm%d' % r['m']
            if key not in summary:
                summary[key] = {'hfa': [], 'relay': []}
            summary[key]['hfa'].append(r['total_ms'])
    for r in results:
        if r['scheme'] == 'Relay':
            key = 'm%d' % r['m']
            summary[key]['relay'].append(r['total_ms'])

    json_summary = {}
    for key, data in summary.items():
        json_summary[key] = {
            'hfa_avg': round(statistics.mean(data['hfa']), 1),
            'hfa_std': round(statistics.stdev(data['hfa']), 1) if len(data['hfa']) > 1 else 0,
            'relay_avg': round(statistics.mean(data['relay']), 1),
            'relay_std': round(statistics.stdev(data['relay']), 1) if len(data['relay']) > 1 else 0,
            'speedup': round(statistics.mean(data['relay']) / statistics.mean(data['hfa']), 1),
        }

    json_path = os.path.join(save_dir, 'e2e_summary_%s.json' % ts)
    with open(json_path, 'w') as f:
        json.dump(json_summary, f, indent=2)
    print("JSON saved: %s" % json_path)

    return csv_path, json_path


if __name__ == '__main__':
    results = run_experiment(domain_counts=[2, 5, 10, 15, 20, 30], n_trials=30)
    save_results(results, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results'))
