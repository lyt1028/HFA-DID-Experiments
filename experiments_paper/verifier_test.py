#!/usr/bin/env python3
"""
在verifier容器内部运行的跨域验证测量脚本
直接用requests发HTTP, 避免docker exec开销
"""
import requests
import time
import statistics
import json
import sys
import os

GCL_URL = "http://172.20.0.20:5000"
NUM_TRIALS = 20


def measure_hfa(m):
    """HFA-DID: 1次GCL快照查询"""
    latencies = []
    for _ in range(NUM_TRIALS):
        t0 = time.perf_counter()
        r = requests.get(GCL_URL + "/gcl/snapshot", timeout=5)
        latencies.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(latencies), statistics.stdev(latencies)


def measure_cross(m):
    """Cross-Chain: 逐个查询m个DCL (重复查询已有DCL模拟m域)"""
    # 原始DCL IPs
    dcl_ips = ["172.20.0.30", "172.20.0.40", "172.20.0.50"]
    latencies = []
    for _ in range(NUM_TRIALS):
        total = 0
        for i in range(m):
            ip = dcl_ips[i % len(dcl_ips)]
            t0 = time.perf_counter()
            r = requests.get("http://%s:5000/dcl/merkle_proof/0" % ip, timeout=5)
            total += (time.perf_counter() - t0) * 1000
        latencies.append(total)
    return statistics.mean(latencies), statistics.stdev(latencies)


def main():
    m = int(sys.argv[1]) if len(sys.argv) > 1 else 3

    hfa_avg, hfa_std = measure_hfa(m)
    cross_avg, cross_std = measure_cross(m)
    speedup = cross_avg / hfa_avg if hfa_avg > 0 else 0

    result = {
        "m": m,
        "hfa_query_ms": round(hfa_avg, 1),
        "hfa_std_ms": round(hfa_std, 1),
        "cross_query_ms": round(cross_avg, 1),
        "cross_std_ms": round(cross_std, 1),
        "query_speedup": round(speedup, 1),
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
