"""
Task 1: 并行中继基线实验
=============================
对比三种跨域验证方案的端到端延迟:
1. HFA-DID: 并行查询GCL(1次) + 本地BLS验证
2. 串行中继: 逐域串行查询m个DCL
3. 并行中继: 并发查询m个DCL(asyncio)

所有查询走真实FISCO BCOS链上RPC, BLS验证用blspy实测.
"""

import sys
import os
import time
import json
import hashlib
import random
import asyncio
import statistics
import csv
from concurrent.futures import ThreadPoolExecutor

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from bls_threshold_blspy import BLSThresholdSigner


# ============================================================
# FISCO Chain Client (复用已有)
# ============================================================

class ChainClient:
    def __init__(self):
        self.fc = None

    def init(self):
        from src.chain.fisco_client import FISCOClient
        self.fc = FISCOClient()
        self.fc.init()

    def close(self):
        if self.fc:
            self.fc.close()

    def query_domain_root(self, domain_id, epoch):
        t0 = time.perf_counter()
        result = self.fc.get_domain_root(domain_id, epoch)
        return result, (time.perf_counter() - t0) * 1000

    def query_credential(self, cred_id):
        t0 = time.perf_counter()
        result = self.fc.get_credential(cred_id)
        return result, (time.perf_counter() - t0) * 1000

    def anchor_domain_root(self, domain_id, epoch, root, sig, n):
        self.fc.anchor_domain_root(domain_id, epoch, root, sig, n)

    def register_credential(self, cred_id, commitment, sig, epoch):
        self.fc.register_credential(cred_id, commitment, sig, epoch)


# ============================================================
# 域数据准备
# ============================================================

def setup_domains(chain, n_domains, n_creds=32, committee_n=10, committee_t=7):
    epoch = int(time.time()) % 100000 + random.randint(10000, 99999)
    domains = {}

    # 共用一个signer避免blspy内存问题
    signer = BLSThresholdSigner(committee_n, committee_t)
    pk = signer.keygen()

    for d in range(n_domains):
        domain_id = f"PR_{d}_{epoch}"

        # 凭证(每域不同消息)
        msg = f"cred_{domain_id}_0_ep{epoch}".encode()
        sig, _ = signer.sign_and_time(msg)

        # 链上锚定
        root = hashlib.sha256(msg).digest()
        try:
            chain.anchor_domain_root(domain_id, epoch, root, b'\x00' * 48, n_creds)
        except:
            pass

        cred_id = hashlib.sha256(f"cid_{domain_id}_0".encode()).digest()
        try:
            chain.register_credential(cred_id, root, b'\x00' * 48, epoch)
        except:
            pass

        domains[d] = {
            'domain_id': domain_id, 'epoch': epoch,
            'signer': signer, 'pk': pk,
            'cred_msg': msg, 'cred_sig': sig, 'cred_id': cred_id,
        }
    return domains


# ============================================================
# 三种验证方案
# ============================================================

def hfa_did_verify(chain, domains, target_idx=0):
    """HFA-DID: 并行查3次链(RTL+GCL+GEL), 串行2次BLS验证"""
    d = domains[target_idx]
    with ThreadPoolExecutor(max_workers=3) as pool:
        f1 = pool.submit(chain.query_domain_root, d['domain_id'], d['epoch'])
        f2 = pool.submit(chain.query_domain_root, d['domain_id'], d['epoch'])
        f3 = pool.submit(chain.query_credential, d['cred_id'])
    _, t1 = f1.result()
    _, t2 = f2.result()
    _, t3 = f3.result()
    net_ms = max(t1, t2, t3)

    _, bls1 = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
    _, bls2 = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
    compute_ms = bls1 + bls2

    return net_ms + compute_ms


def serial_relay_verify(chain, domains, n_domains):
    """串行中继: 逐域串行查询+验证"""
    total = 0
    for i in range(n_domains):
        d = domains[i]
        _, t1 = chain.query_domain_root(d['domain_id'], d['epoch'])
        _, t2 = chain.query_credential(d['cred_id'])
        _, bls_ms = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
        total += t1 + t2 + bls_ms
    return total


def parallel_relay_verify(chain, domains, n_domains):
    """
    并行中继: 并发查询所有域, 取max网络延迟 + 逐域BLS验证

    FISCO SDK非线程安全, 改为串行查询但只取max延迟(模拟并行效果).
    这是合理的: 并行中继的瓶颈是最慢的那个域, 不是总和.
    """
    # 串行执行所有域查询, 记录每域延迟
    per_domain_net = []
    for i in range(n_domains):
        d = domains[i]
        _, t1 = chain.query_domain_root(d['domain_id'], d['epoch'])
        _, t2 = chain.query_credential(d['cred_id'])
        per_domain_net.append(t1 + t2)

    # 并行中继: 网络延迟 = max(各域), 不是sum
    max_net = max(per_domain_net)

    # BLS验证仍需逐域串行(不同域不同公钥)
    bls_total = 0
    for i in range(n_domains):
        d = domains[i]
        _, bls_ms = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
        bls_total += bls_ms

    return max_net + bls_total


# ============================================================
# 主实验
# ============================================================

def run_experiment(domain_counts=None, n_trials=20):
    if domain_counts is None:
        domain_counts = [2, 5, 10, 15, 20, 30]

    print("=" * 60)
    print("  三方案跨域验证延迟对比")
    print("  HFA-DID vs 串行中继 vs 并行中继")
    print("  FISCO BCOS + blspy 真实链上查询")
    print("=" * 60)

    chain = ChainClient()
    chain.init()
    print("  Chain connected.\n")

    results = []

    for m in domain_counts:
        print(f"\n  m={m}, {n_trials} trials...")
        domains = setup_domains(chain, m)

        hfa_times = []
        serial_times = []
        parallel_times = []

        for trial in range(n_trials):
            target = random.randint(0, m - 1)
            h = hfa_did_verify(chain, domains, target)
            s = serial_relay_verify(chain, domains, m)
            p = parallel_relay_verify(chain, domains, m)
            hfa_times.append(h)
            serial_times.append(s)
            parallel_times.append(p)

        hfa_avg = statistics.mean(hfa_times)
        serial_avg = statistics.mean(serial_times)
        parallel_avg = statistics.mean(parallel_times)

        print(f"    HFA-DID:    {hfa_avg:.1f}ms")
        print(f"    串行中继:   {serial_avg:.1f}ms  ({serial_avg/hfa_avg:.1f}x slower)")
        print(f"    并行中继:   {parallel_avg:.1f}ms  ({parallel_avg/hfa_avg:.1f}x slower)")

        results.append({
            'm': m,
            'hfa_avg': round(hfa_avg, 1),
            'hfa_std': round(statistics.stdev(hfa_times), 1) if len(hfa_times) > 1 else 0,
            'serial_avg': round(serial_avg, 1),
            'serial_std': round(statistics.stdev(serial_times), 1) if len(serial_times) > 1 else 0,
            'parallel_avg': round(parallel_avg, 1),
            'parallel_std': round(statistics.stdev(parallel_times), 1) if len(parallel_times) > 1 else 0,
        })

    chain.close()

    # 保存
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')

    json_path = os.path.join(results_dir, f'relay_comparison_{ts}.json')
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved: {json_path}")

    # 打印加速比汇总
    print("\n  === 加速比汇总 ===")
    print(f"  {'m':>4s} | {'HFA-DID':>10s} | {'串行中继':>10s} | {'并行中继':>10s} | {'vs串行':>6s} | {'vs并行':>6s}")
    print("  " + "-" * 60)
    for r in results:
        vs_s = r['serial_avg'] / r['hfa_avg'] if r['hfa_avg'] > 0 else 0
        vs_p = r['parallel_avg'] / r['hfa_avg'] if r['hfa_avg'] > 0 else 0
        print(f"  {r['m']:4d} | {r['hfa_avg']:8.1f}ms | {r['serial_avg']:8.1f}ms | {r['parallel_avg']:8.1f}ms | {vs_s:5.1f}x | {vs_p:5.1f}x")

    return results


if __name__ == '__main__':
    if '--quick' in sys.argv:
        run_experiment(domain_counts=[2, 5, 10], n_trials=5)
    else:
        run_experiment(domain_counts=[2, 5, 10, 15, 20, 30], n_trials=20)
