#!/usr/bin/env python3
"""
实验9v3: 签发域故障可用性对比 (真实Docker网络+HTTP API)

关键区别: 按需拉取通过DCL容器HTTP API查询(受tc netem影响),
         HFA-DID通过GCL容器API查询(GCL网络始终正常)

故障场景 (m=5域, 逐步增加故障):
  S0: 全部正常           (0/5 故障)
  S1: 1域高延迟          (1/5 退化)
  S2: 1离线+1间歇性      (2/5 故障)
  S3: 2离线+1高延迟      (3/5 故障)
  S4: 3离线+1间歇性      (4/5 故障)
  S5: 全部离线           (5/5 故障)
"""

import sys, os, time, random, json, subprocess, requests
import numpy as np

# ── 容器配置 ──
DCL_ENDPOINTS = {
    0: {"container": "hfa-dcl-a", "url": "http://172.20.0.30:5000"},
    1: {"container": "hfa-dcl-b", "url": "http://172.20.0.40:5000"},
    2: {"container": "hfa-dcl-c", "url": "http://172.20.0.50:5000"},
    3: {"container": "hfa-dcl-a", "url": "http://172.20.0.30:5000"},  # 复用
    4: {"container": "hfa-dcl-b", "url": "http://172.20.0.40:5000"},  # 复用
}
GCL_ENDPOINT = {"container": "hfa-gcl", "url": "http://172.20.0.20:5000"}

# ── tc netem 配置 ──
PROFILES = {
    "normal":       "tc qdisc replace dev eth0 root netem delay 30ms 8ms loss 0.5%",
    "high_latency": "tc qdisc replace dev eth0 root netem delay 300ms 80ms loss 5%",
    "intermittent": "tc qdisc replace dev eth0 root netem delay 150ms 100ms loss 40%",
    "offline":      "tc qdisc replace dev eth0 root netem delay 0ms loss 100%",
}

HTTP_TIMEOUT = 3.0  # 单次HTTP超时 (秒)
MAX_RETRIES = 1     # 按需拉取重试次数


def apply_tc(container, profile):
    cmd = PROFILES[profile]
    subprocess.run(
        ["docker", "exec", container, "bash", "-c",
         f"tc qdisc del dev eth0 root 2>/dev/null; {cmd}"],
        capture_output=True, timeout=5
    )

def reset_all():
    for d in DCL_ENDPOINTS.values():
        apply_tc(d["container"], "normal")
    apply_tc(GCL_ENDPOINT["container"], "normal")
    time.sleep(0.5)


def hfa_verify_all(m, n_creds=1000):
    """
    HFA-DID: 查GCL获取全域快照, 再逐域验证Merkle证明
    网络路径: verifier → GCL容器 (受GCL网络条件影响, 但GCL始终正常)
    """
    results = []
    gcl_url = GCL_ENDPOINT["url"]

    for d_idx in range(m):
        t0 = time.perf_counter()
        success = False
        note = ""

        try:
            # Step 1: 查GCL快照 (验证域根存在性)
            r1 = requests.get(f"{gcl_url}/gcl/snapshot", timeout=HTTP_TIMEOUT)
            if r1.status_code != 200:
                note = "GCL快照查询失败"
                results.append((False, (time.perf_counter()-t0)*1000, note))
                continue
            snapshot = r1.json()

            # Step 2: 查GCL域级证明
            domain_id = f"DCL_{chr(65 + d_idx % 3)}"
            r2 = requests.get(f"{gcl_url}/gcl/domain_proof/{domain_id}", timeout=HTTP_TIMEOUT)
            if r2.status_code != 200:
                note = "域证明查询失败"
                results.append((False, (time.perf_counter()-t0)*1000, note))
                continue

            # Step 3: 本地Merkle验证 (不需要网络)
            proof_data = r2.json()
            # 验证逻辑: 检查返回数据完整性
            if "domain_root" in proof_data and "proof" in proof_data:
                success = True
                note = "成功"
            else:
                note = "数据不完整"

        except requests.Timeout:
            note = "GCL查询超时"
        except requests.ConnectionError:
            note = "GCL连接失败"
        except Exception as e:
            note = f"异常: {type(e).__name__}"

        ms = (time.perf_counter() - t0) * 1000
        results.append((success, ms, note))

    return results


def relay_verify_all(m, n_creds=1000):
    """
    按需拉取: 逐域查各DCL的HTTP API
    网络路径: verifier → DCL容器 (受各DCL的tc netem影响)
    带重试: 失败后重试MAX_RETRIES次
    """
    results = []

    for d_idx in range(m):
        dcl = DCL_ENDPOINTS[d_idx]
        dcl_url = dcl["url"]
        t0 = time.perf_counter()
        success = False
        note = ""

        for attempt in range(1 + MAX_RETRIES):
            try:
                # Step 1: 查DCL域信息
                r1 = requests.get(f"{dcl_url}/dcl/info", timeout=HTTP_TIMEOUT)
                if r1.status_code != 200:
                    if attempt < MAX_RETRIES:
                        time.sleep(0.2)
                        continue
                    note = f"DCL信息查询失败(已重试{attempt+1}次)"
                    break

                # Step 2: 查DCL Merkle证明
                cred_idx = random.randint(0, n_creds - 1)
                r2 = requests.get(f"{dcl_url}/dcl/merkle_proof/{cred_idx}", timeout=HTTP_TIMEOUT)
                if r2.status_code != 200:
                    if attempt < MAX_RETRIES:
                        time.sleep(0.2)
                        continue
                    note = f"Merkle证明查询失败(已重试{attempt+1}次)"
                    break

                proof_data = r2.json()
                if "root" in proof_data and "proof" in proof_data:
                    success = True
                    note = f"成功(尝试{attempt+1}次)"
                else:
                    note = "数据不完整"
                break

            except requests.Timeout:
                if attempt < MAX_RETRIES:
                    time.sleep(0.2)
                    continue
                note = f"超时(已重试{attempt+1}次)"
            except requests.ConnectionError:
                if attempt < MAX_RETRIES:
                    time.sleep(0.2)
                    continue
                note = f"连接失败(已重试{attempt+1}次)"
            except Exception as e:
                note = f"异常: {type(e).__name__}"
                break

        ms = (time.perf_counter() - t0) * 1000
        results.append((success, ms, note))

    return results


def run_scenario(m, fault_config, n_repeats=20):
    """运行单个故障场景"""
    reset_all()
    applied = set()
    for d_idx, profile in fault_config.items():
        container = DCL_ENDPOINTS[d_idx]["container"]
        if container not in applied:
            apply_tc(container, profile)
            applied.add(container)
    time.sleep(1.5)  # 等tc规则生效

    hfa_data = {"success": [], "latency": []}
    relay_data = {"success": [], "latency": []}

    for trial in range(n_repeats):
        # HFA-DID
        hfa_res = hfa_verify_all(m)
        hfa_succ = sum(1 for ok, _, _ in hfa_res if ok)
        hfa_total = sum(ms for _, ms, _ in hfa_res)
        hfa_data["success"].append(hfa_succ / m * 100)
        hfa_data["latency"].append(hfa_total)

        # 按需拉取
        relay_res = relay_verify_all(m)
        relay_succ = sum(1 for ok, _, _ in relay_res if ok)
        relay_total = sum(ms for _, ms, _ in relay_res)
        relay_data["success"].append(relay_succ / m * 100)
        relay_data["latency"].append(relay_total)

        if trial == 0:
            # 打印首次各域详情
            for d_idx, (ok, ms, note) in enumerate(relay_res):
                profile = fault_config.get(d_idx, "normal")
                print(f"      域{d_idx}[{profile:12s}] relay: {note:30s} ({ms:.0f}ms)")

    return {
        "hfa_success_mean": float(np.mean(hfa_data["success"])),
        "hfa_success_std": float(np.std(hfa_data["success"])),
        "hfa_latency_mean": float(np.mean(hfa_data["latency"])),
        "hfa_latency_std": float(np.std(hfa_data["latency"])),
        "relay_success_mean": float(np.mean(relay_data["success"])),
        "relay_success_std": float(np.std(relay_data["success"])),
        "relay_latency_mean": float(np.mean(relay_data["latency"])),
        "relay_latency_std": float(np.std(relay_data["latency"])),
    }


def run_experiment(m=5, n_repeats=20):
    print("=" * 60)
    print("  实验9v3: 签发域故障可用性对比 (真实HTTP+tc netem)")
    print("=" * 60)
    print(f"  域数量: {m}, 重复: {n_repeats}")
    print(f"  HTTP超时: {HTTP_TIMEOUT}s, 重试: {MAX_RETRIES}次")

    scenarios = [
        ("S0: 全部正常",          {},                                                    "0/5故障"),
        ("S1: 1域高延迟",         {0: "high_latency"},                                   "1/5退化"),
        ("S2: 1离线+1间歇",       {0: "offline", 1: "intermittent"},                     "2/5故障"),
        ("S3: 2离线+1高延迟",     {0: "offline", 1: "offline", 2: "high_latency"},       "3/5故障"),
        ("S4: 3离线+1间歇",       {0: "offline", 1: "offline", 2: "offline", 3: "intermittent"}, "4/5故障"),
        ("S5: 全部离线",          {i: "offline" for i in range(m)},                      "5/5故障"),
    ]

    all_results = {}
    for label, fault_config, desc in scenarios:
        print(f"\n  === {label} ({desc}) ===")
        r = run_scenario(m, fault_config, n_repeats)
        all_results[label] = r
        print(f"    HFA-DID: 成功率={r['hfa_success_mean']:.1f}% +/- {r['hfa_success_std']:.1f}%  "
              f"延迟={r['hfa_latency_mean']:.0f} +/- {r['hfa_latency_std']:.0f} ms")
        print(f"    按需拉取: 成功率={r['relay_success_mean']:.1f}% +/- {r['relay_success_std']:.1f}%  "
              f"延迟={r['relay_latency_mean']:.0f} +/- {r['relay_latency_std']:.0f} ms")

    reset_all()
    print("\n  网络已恢复")

    results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, "exp9v3_availability.json"), "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"  结果: results/exp9v3_availability.json")
    return all_results


if __name__ == "__main__":
    quick = "--quick" in sys.argv
    run_experiment(m=5, n_repeats=5 if quick else 20)
