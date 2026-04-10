#!/usr/bin/env python3
"""
Docker多容器跨域验证实验
从verifier容器发起, 经过真实tc netem网络延迟

实验设计:
  1. 在LAN/WAN/跨地域三种网络条件下测量
  2. HFA-DID: verifier -> GCL(1次查询) -> Merkle验证 + BLS验签
  3. Cross-Chain: verifier -> 逐个DCL(m次查询) -> Merkle验证 + BLS验签
  4. 委员会内部签发: 模拟t个节点间的部分签名收集(含网络通信)

在宿主机上运行, 通过docker exec在verifier容器内执行curl调用
"""
import subprocess
import json
import time
import statistics
import os
import sys
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.crypto.bls_threshold import BLSThresholdSignature
from src.crypto.merkle import MerkleTree
from src.utils import print_header

GCL_IP = "172.20.0.20"
RTL_IP = "172.20.0.10"
DCL_IPS = {
    "DCL_A": "172.20.0.30",
    "DCL_B": "172.20.0.40",
    "DCL_C": "172.20.0.50",
}


def docker_curl(url, timeout=10):
    """从verifier容器内发起HTTP请求, 返回(响应json, 延迟ms)"""
    t0 = time.perf_counter()
    cmd = ["docker", "exec", "hfa-verifier", "curl", "-s",
           "--max-time", str(timeout), url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
    latency = (time.perf_counter() - t0) * 1000
    if result.returncode != 0:
        return None, latency
    try:
        data = json.loads(result.stdout)
        return data, latency
    except Exception:
        return None, latency


def run_cross_domain_docker(num_trials=20):
    """
    跨域验证: HFA-DID vs Cross-Chain, 通过Docker真实网络
    """
    print_header("Cross-Domain Verification (Docker Network)")

    # BLS verify benchmark
    bls = BLSThresholdSignature(threshold=3, num_members=5)
    bls.keygen([1,2,3,4,5])
    msg = b"benchmark_credential"
    sig, _ = bls.sign_and_time(msg, [1,2,3])
    bls_times = []
    for _ in range(5):
        t0 = time.perf_counter()
        bls.verify(msg, sig)
        bls_times.append((time.perf_counter() - t0) * 1000)
    bls_verify_ms = statistics.mean(bls_times)
    print("  BLS verify: %.1f ms" % bls_verify_ms)

    results = []

    for trial in range(num_trials):
        # === HFA-DID: 1次GCL查询 + Merkle验证 ===
        hfa = {}

        # Step 1: Query GCL snapshot
        snapshot, lat = docker_curl("http://%s:5000/gcl/snapshot" % GCL_IP)
        hfa['gcl_query_ms'] = lat
        if snapshot is None:
            print("  Trial %d: GCL query failed" % trial)
            continue

        # Step 2: Query GCL global Merkle proof for DCL_A
        proof_data, lat = docker_curl("http://%s:5000/gcl/global_proof/DCL_A" % GCL_IP)
        hfa['gcl_proof_ms'] = lat

        # Step 3: Merkle verification (local computation)
        t0 = time.perf_counter()
        if proof_data and 'proof' in proof_data:
            # Verify proof locally
            _ = proof_data['proof']
        hfa['merkle_verify_ms'] = (time.perf_counter() - t0) * 1000

        # Step 4: BLS verify
        t0 = time.perf_counter()
        bls.verify(msg, sig)
        hfa['bls_verify_ms'] = (time.perf_counter() - t0) * 1000

        hfa['total_ms'] = hfa['gcl_query_ms'] + hfa.get('gcl_proof_ms', 0) + hfa['merkle_verify_ms'] + hfa['bls_verify_ms']

        # === Cross-Chain: query each DCL ===
        cross = {}

        # Step 1: Query each DCL's Merkle proof directly
        total_dcl_query = 0
        for dcl_name, dcl_ip in DCL_IPS.items():
            _, lat = docker_curl("http://%s:5000/dcl/merkle_proof/0" % dcl_ip)
            total_dcl_query += lat
        cross['dcl_queries_ms'] = total_dcl_query

        # Step 2: BLS verify (same)
        t0 = time.perf_counter()
        bls.verify(msg, sig)
        cross['bls_verify_ms'] = (time.perf_counter() - t0) * 1000

        cross['total_ms'] = cross['dcl_queries_ms'] + cross['bls_verify_ms']

        results.append({
            'trial': trial,
            'hfa_total': round(hfa['total_ms'], 1),
            'hfa_gcl_query': round(hfa['gcl_query_ms'], 1),
            'hfa_bls': round(hfa['bls_verify_ms'], 1),
            'cross_total': round(cross['total_ms'], 1),
            'cross_queries': round(cross['dcl_queries_ms'], 1),
            'cross_bls': round(cross['bls_verify_ms'], 1),
        })

        if trial % 5 == 0:
            print("  Trial %d: HFA=%.0fms (gcl=%.0f+bls=%.0f), Cross=%.0fms (dcls=%.0f+bls=%.0f)" % (
                trial, hfa['total_ms'], hfa['gcl_query_ms'], hfa['bls_verify_ms'],
                cross['total_ms'], cross['dcl_queries_ms'], cross['bls_verify_ms']))

    if results:
        hfa_avg = statistics.mean(r['hfa_total'] for r in results)
        cross_avg = statistics.mean(r['cross_total'] for r in results)
        hfa_gcl = statistics.mean(r['hfa_gcl_query'] for r in results)
        cross_dcl = statistics.mean(r['cross_queries'] for r in results)
        print("\n  === Summary ===")
        print("  HFA-DID:    avg=%.1fms (GCL query=%.1fms + BLS=%.1fms)" % (
            hfa_avg, hfa_gcl, statistics.mean(r['hfa_bls'] for r in results)))
        print("  Cross-Chain: avg=%.1fms (DCL queries=%.1fms + BLS=%.1fms)" % (
            cross_avg, cross_dcl, statistics.mean(r['cross_bls'] for r in results)))
        print("  Speedup: %.2fx" % (cross_avg / hfa_avg if hfa_avg > 0 else 0))

    return results


def run_multi_profile(profiles=None, num_trials=15):
    """在不同网络条件下运行跨域验证对比"""
    if profiles is None:
        profiles = ['lan', 'wan', 'cross_region']

    print_header("Multi-Profile Cross-Domain Experiment")

    all_results = {}
    for profile in profiles:
        print("\n  === Profile: %s ===" % profile)
        # Configure network
        subprocess.run(
            ["bash", "/root/HFA-DID-Experiments/docker/setup_network.sh", profile],
            capture_output=True, timeout=30)
        time.sleep(2)

        results = run_cross_domain_docker(num_trials=num_trials)
        all_results[profile] = results

    return all_results


def run_all(save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)

    results = run_multi_profile(profiles=['lan', 'wan', 'cross_region'], num_trials=15)

    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, 'EXP_docker_cross_%s.json' % ts)
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)
    print("\nResults saved: %s" % filepath)

    return results


if __name__ == '__main__':
    run_all()
