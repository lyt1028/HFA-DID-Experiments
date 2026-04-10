#!/usr/bin/env python3
"""
Docker多域跨域验证实验
动态创建m个DCL容器, 在LAN/WAN/跨地域三种网络下测量

实验流程:
  1. 生成docker-compose-scale.yml (m个DCL)
  2. 启动容器
  3. 配置tc netem网络延迟
  4. 从verifier发起HFA-DID(1次GCL查询) vs Cross-Chain(m次DCL查询)
  5. 停止容器
"""
import subprocess
import json
import time
import statistics
import os
import sys
import yaml
import random

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.crypto.bls_threshold import BLSThresholdSignature
from src.utils import print_header

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKER_DIR = os.path.join(PROJECT_DIR, 'docker')
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def generate_compose(m):
    """生成含m个DCL的docker-compose文件"""
    services = {
        'rtl': {
            'image': 'hfa-did-node',
            'container_name': 'hfa-rtl',
            'hostname': 'rtl',
            'networks': {'hfa-net': {'ipv4_address': '172.20.0.10'}},
            'volumes': ['../:/app'],
            'working_dir': '/app',
            'cap_add': ['NET_ADMIN'],
            'command': ['python', '-m', 'docker.node_service', '--role', 'rtl', '--port', '5000'],
        },
        'gcl': {
            'image': 'hfa-did-node',
            'container_name': 'hfa-gcl',
            'hostname': 'gcl',
            'networks': {'hfa-net': {'ipv4_address': '172.20.0.20'}},
            'volumes': ['../:/app'],
            'working_dir': '/app',
            'cap_add': ['NET_ADMIN'],
            'command': ['python', '-m', 'docker.node_service', '--role', 'gcl', '--port', '5000',
                        '--domains', ','.join(['DCL_%d' % i for i in range(m)])],
        },
        'verifier': {
            'image': 'hfa-did-node',
            'container_name': 'hfa-verifier',
            'hostname': 'verifier',
            'networks': {'hfa-net': {'ipv4_address': '172.20.0.100'}},
            'volumes': ['../:/app'],
            'working_dir': '/app',
            'cap_add': ['NET_ADMIN'],
            'command': ['sleep', 'infinity'],
        },
    }

    for i in range(m):
        ip = '172.20.0.%d' % (30 + i)
        services['dcl-%d' % i] = {
            'image': 'hfa-did-node',
            'container_name': 'hfa-dcl-%d' % i,
            'hostname': 'dcl-%d' % i,
            'networks': {'hfa-net': {'ipv4_address': ip}},
            'volumes': ['../:/app'],
            'working_dir': '/app',
            'cap_add': ['NET_ADMIN'],
            'command': ['python', '-m', 'docker.node_service', '--role', 'dcl',
                        '--domain', 'DCL_%d' % i, '--port', '5000'],
        }

    compose = {
        'services': services,
        'networks': {
            'hfa-net': {
                'driver': 'bridge',
                'ipam': {
                    'config': [{'subnet': '172.20.0.0/16'}]
                }
            }
        }
    }

    path = os.path.join(DOCKER_DIR, 'docker-compose-scale.yml')
    with open(path, 'w') as f:
        yaml.dump(compose, f, default_flow_style=False)
    return path


def setup_network(m, profile):
    """配置tc netem网络延迟"""
    # 先清除所有规则
    containers = ['hfa-rtl', 'hfa-gcl', 'hfa-verifier'] + ['hfa-dcl-%d' % i for i in range(m)]
    for c in containers:
        subprocess.run(['docker', 'exec', c, 'tc', 'qdisc', 'del', 'dev', 'eth0', 'root'],
                      capture_output=True, timeout=5)

    if profile == 'lan':
        # verifier->any: 1ms, dcl->gcl: 0.5ms
        subprocess.run(['docker', 'exec', 'hfa-verifier', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '1ms'], capture_output=True, timeout=5)
        subprocess.run(['docker', 'exec', 'hfa-gcl', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '0.5ms'], capture_output=True, timeout=5)
        for i in range(m):
            subprocess.run(['docker', 'exec', 'hfa-dcl-%d' % i, 'tc', 'qdisc', 'add', 'dev', 'eth0',
                           'root', 'netem', 'delay', '0.5ms'], capture_output=True, timeout=5)

    elif profile == 'wan':
        subprocess.run(['docker', 'exec', 'hfa-verifier', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '25ms', '5ms', 'distribution', 'normal', 'loss', '0.5%'],
                      capture_output=True, timeout=5)
        subprocess.run(['docker', 'exec', 'hfa-gcl', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '15ms', '3ms', 'distribution', 'normal', 'loss', '0.3%'],
                      capture_output=True, timeout=5)
        for i in range(m):
            delay = '%dms' % random.randint(10, 30)
            subprocess.run(['docker', 'exec', 'hfa-dcl-%d' % i, 'tc', 'qdisc', 'add', 'dev', 'eth0',
                           'root', 'netem', 'delay', delay, '3ms', 'distribution', 'normal', 'loss', '0.3%'],
                          capture_output=True, timeout=5)

    elif profile == 'cross_region':
        subprocess.run(['docker', 'exec', 'hfa-verifier', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '75ms', '15ms', 'distribution', 'normal', 'loss', '1%'],
                      capture_output=True, timeout=5)
        subprocess.run(['docker', 'exec', 'hfa-gcl', 'tc', 'qdisc', 'add', 'dev', 'eth0',
                       'root', 'netem', 'delay', '40ms', '8ms', 'distribution', 'normal', 'loss', '0.5%'],
                      capture_output=True, timeout=5)
        for i in range(m):
            delay = '%dms' % random.randint(30, 80)
            subprocess.run(['docker', 'exec', 'hfa-dcl-%d' % i, 'tc', 'qdisc', 'add', 'dev', 'eth0',
                           'root', 'netem', 'delay', delay, '10ms', 'distribution', 'normal', 'loss', '0.5%'],
                          capture_output=True, timeout=5)


def docker_curl(url, timeout=15):
    t0 = time.perf_counter()
    cmd = ['docker', 'exec', 'hfa-verifier', 'curl', '-s', '--max-time', str(timeout), url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
    latency = (time.perf_counter() - t0) * 1000
    return latency


def run_single(m, profile, num_trials=10):
    """单次实验: m个域, 指定网络条件"""
    random.seed(42)
    setup_network(m, profile)
    time.sleep(2)

    # BLS benchmark
    bls = BLSThresholdSignature(threshold=3, num_members=5)
    bls.keygen([1,2,3,4,5])
    msg = b"benchmark"
    sig, _ = bls.sign_and_time(msg, [1,2,3])
    bls_ms = statistics.mean([(time.perf_counter(), bls.verify(msg, sig),
                               (time.perf_counter() - _t) * 1000)[2]
                              for _t in [time.perf_counter()] * 3])
    # Simpler BLS benchmark
    bls_times = []
    for _ in range(3):
        t0 = time.perf_counter()
        bls.verify(msg, sig)
        bls_times.append((time.perf_counter() - t0) * 1000)
    bls_verify = statistics.mean(bls_times)

    hfa_queries = []
    cross_queries = []

    for trial in range(num_trials):
        # HFA-DID: 1 GCL query
        lat = docker_curl('http://172.20.0.20:5000/gcl/snapshot')
        hfa_queries.append(lat)

        # Cross-Chain: m DCL queries (sequential)
        total = 0
        for i in range(m):
            ip = '172.20.0.%d' % (30 + i)
            lat = docker_curl('http://%s:5000/dcl/merkle_proof/0' % ip)
            total += lat
        cross_queries.append(total)

    hfa_q_avg = statistics.mean(hfa_queries)
    cross_q_avg = statistics.mean(cross_queries)

    return {
        'm': m,
        'profile': profile,
        'hfa_query_ms': round(hfa_q_avg, 1),
        'hfa_total_ms': round(hfa_q_avg + bls_verify, 1),
        'cross_query_ms': round(cross_q_avg, 1),
        'cross_total_ms': round(cross_q_avg + bls_verify, 1),
        'bls_verify_ms': round(bls_verify, 1),
        'query_speedup': round(cross_q_avg / hfa_q_avg, 1) if hfa_q_avg > 0 else 0,
    }


def run_all():
    print_header("Docker Scale Cross-Domain Experiment")

    domain_counts = [2, 5, 10, 15, 20]
    profiles = ['lan', 'wan', 'cross_region']

    all_results = {}

    for m in domain_counts:
        print("\n\n========== m=%d domains ==========" % m)

        # Generate and start containers
        compose_path = generate_compose(m)
        print("  Stopping old containers...")
        subprocess.run(['docker', 'compose', '-f', compose_path, 'down'],
                      capture_output=True, timeout=60)
        print("  Starting %d DCL + GCL + RTL + verifier..." % m)
        subprocess.run(['docker', 'compose', '-f', compose_path, 'up', '-d'],
                      capture_output=True, timeout=120)
        time.sleep(8)  # Wait for Flask services to start

        for profile in profiles:
            print("\n  m=%d, profile=%s" % (m, profile))
            result = run_single(m, profile, num_trials=10)
            key = "%s_m%d" % (profile, m)
            all_results[key] = result
            print("    HFA: %.0fms (query=%.0f), Cross: %.0fms (query=%.0f), speedup=%.1fx" % (
                result['hfa_total_ms'], result['hfa_query_ms'],
                result['cross_total_ms'], result['cross_query_ms'],
                result['query_speedup']))

        # Stop containers to free resources
        print("  Stopping containers...")
        subprocess.run(['docker', 'compose', '-f', compose_path, 'down'],
                      capture_output=True, timeout=60)

    # Save
    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(RESULTS_DIR, 'EXP_docker_scale_%s.json' % ts)
    with open(filepath, 'w') as f:
        json.dump(all_results, f, indent=2)
    print("\n\nResults saved: %s" % filepath)

    # Summary table
    print("\n=== Summary ===")
    print("%6s" % "m", end="")
    for p in profiles:
        print(" | %s HFA/Cross (query speedup)" % p, end="")
    print()
    for m in domain_counts:
        print("%6d" % m, end="")
        for p in profiles:
            key = "%s_m%d" % (p, m)
            r = all_results[key]
            print(" | %4.0f/%4.0fms (%4.1fx)" % (r['hfa_query_ms'], r['cross_query_ms'], r['query_speedup']), end="")
        print()

    return all_results


if __name__ == '__main__':
    run_all()
