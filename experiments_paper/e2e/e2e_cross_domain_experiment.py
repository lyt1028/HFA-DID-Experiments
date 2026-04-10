"""
真实端到端跨域验证延迟实验
============================

所有延迟来自:
- 真实 FISCO BCOS 智能合约 RPC 查询
- 真实 BLS12-381 配对验证 (blspy C++ 库)
- 真实 Merkle 路径哈希计算 (SHA-256)
- Docker + tc netem 注入的 WAN 网络延迟

实验覆盖论文 6 步跨域验证流程:
Step 1: RTL 域状态查询 (链上)
Step 2: GCL 快照查询 (链上)
Step 3: Merkle 路径验证 (本地)
Step 4: GEL/RCP 检索 (链上)
Step 5: RCP BLS 验证 (本地 blspy)
Step 6: 凭证 BLS 验证 (本地 blspy)

HFA-DID: Step 1/2/4 并行, Step 3/5/6 串行
Relay: 逐域串行执行全部步骤
"""

import sys
import os
import time
import json
import hashlib
import random
import csv
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

# 项目根目录
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, PROJECT_ROOT)

from bls_threshold_blspy import BLSThresholdSigner


# ============================================================
# Merkle 树 (SHA-256)
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_merkle_tree(leaves: list) -> list:
    """构建 Merkle 树, 返回所有层级"""
    if not leaves:
        return [[sha256(b"empty")]]
    current = [sha256(l) if isinstance(l, bytes) else l for l in leaves]
    levels = [current[:]]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        next_level = []
        for i in range(0, len(current), 2):
            combined = current[i] + current[i + 1]
            next_level.append(sha256(combined))
        current = next_level
        levels.append(current[:])
    return levels


def get_merkle_root(levels: list) -> bytes:
    return levels[-1][0]


def get_merkle_proof(levels: list, index: int) -> list:
    """生成指定叶子的 Merkle 证明路径"""
    proof = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx
            proof.append(('right', level[sibling_idx]))
        else:
            proof.append(('left', level[idx - 1]))
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: bytes, proof: list, root: bytes) -> bool:
    """验证 Merkle 证明"""
    current = leaf_hash
    for direction, sibling in proof:
        if direction == 'right':
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)
    return current == root


# ============================================================
# FISCO BCOS 链交互封装
# ============================================================

class ChainClient:
    """FISCO BCOS 链交互客户端"""

    def __init__(self):
        self.fc = None
        self._initialized = False

    def init(self):
        if self._initialized:
            return
        from src.chain.fisco_client import FISCOClient
        self.fc = FISCOClient()
        self.fc.init()
        self._initialized = True

    def close(self):
        if self.fc:
            self.fc.close()

    # ---- 写入操作 (setup 阶段) ----

    def anchor_domain_root(self, domain_id, epoch, root, sig, n_creds):
        """锚定域根到链上"""
        t0 = time.perf_counter()
        self.fc.anchor_domain_root(domain_id, epoch, root, sig, n_creds)
        return (time.perf_counter() - t0) * 1000

    def publish_roster(self, domain_id, epoch, member_ids, pk_hash):
        """发布委员会名册 (模拟 RTL 域状态)"""
        t0 = time.perf_counter()
        self.fc.publish_roster(domain_id, epoch, member_ids, pk_hash)
        return (time.perf_counter() - t0) * 1000

    def record_rotation(self, domain_id, from_epoch, to_epoch, old_pk_hash, new_pk_hash):
        """记录轮转 (模拟 GEL/RCP)"""
        t0 = time.perf_counter()
        self.fc.record_rotation(domain_id, from_epoch, to_epoch, old_pk_hash, new_pk_hash)
        return (time.perf_counter() - t0) * 1000

    # ---- 查询操作 (验证阶段, 返回 (data, latency_ms)) ----

    def query_roster(self, domain_id, epoch):
        """Step 1: RTL 查询域委员会"""
        t0 = time.perf_counter()
        result = self.fc.get_roster(domain_id, epoch)
        ms = (time.perf_counter() - t0) * 1000
        return result, ms

    def query_domain_root(self, domain_id, epoch):
        """Step 2: GCL 快照查询"""
        t0 = time.perf_counter()
        result = self.fc.get_domain_root(domain_id, epoch)
        ms = (time.perf_counter() - t0) * 1000
        return result, ms

    def query_credential(self, cred_id):
        """Step 4: GEL 凭证记录查询"""
        t0 = time.perf_counter()
        result = self.fc.get_credential(cred_id)
        ms = (time.perf_counter() - t0) * 1000
        return result, ms


# ============================================================
# 域数据准备
# ============================================================

def setup_domains(chain: ChainClient, n_domains: int, n_creds: int = 64,
                  committee_n: int = 10, committee_t: int = 7):
    """
    为 n_domains 个域准备实验数据:
    - BLS 门限密钥
    - 凭证 Merkle 树
    - 链上锚定
    - 链上 RCP 记录
    """
    print(f"  Setup: {n_domains} domains, {n_creds} creds/domain, ({committee_t},{committee_n}) threshold")

    domains = {}
    epoch = int(time.time()) % 100000 + random.randint(10000, 99999)

    for d in range(n_domains):
        domain_id = f"E2E_DOM_{d}_{epoch}"

        # 1. BLS 门限密钥
        signer = BLSThresholdSigner(committee_n, committee_t)
        pk = signer.keygen()

        # 2. 签发凭证
        cred_leaves = []
        cred_msgs = []
        cred_sigs = []
        for c in range(n_creds):
            msg = f"cred_{domain_id}_{c}_epoch{epoch}".encode()
            sig, _ = signer.sign_and_time(msg)
            cred_leaves.append(msg)
            cred_msgs.append(msg)
            cred_sigs.append(sig)

        # 3. Merkle 树
        tree_levels = build_merkle_tree(cred_leaves)
        root = get_merkle_root(tree_levels)

        # 4. 选一个凭证的证明路径
        target_idx = random.randint(0, n_creds - 1)
        leaf_hash = sha256(cred_leaves[target_idx])
        proof = get_merkle_proof(tree_levels, target_idx)

        # 5. RCP 签名
        rcp_msg = f"rcp_{domain_id}_epoch{epoch}_rotation".encode()
        rcp_sig, _ = signer.sign_and_time(rcp_msg)

        # 6. 链上锚定
        pk_bytes = bytes(pk)
        sig_placeholder = b'\x00' * 48
        try:
            chain.anchor_domain_root(domain_id, epoch, root, sig_placeholder, n_creds)
            chain.publish_roster(domain_id, epoch, list(range(1, committee_n + 1)),
                                 hashlib.sha256(pk_bytes).digest())
        except Exception as e:
            print(f"    [WARN] Chain anchor failed for {domain_id}: {e}")

        # 7. 注册凭证到链上 (用于 Step 4 查询)
        cred_id = hashlib.sha256(f"cred_id_{domain_id}_{target_idx}".encode()).digest()
        commitment = sha256(cred_msgs[target_idx])
        try:
            chain.fc.register_credential(cred_id, commitment, sig_placeholder, epoch)
        except Exception as e:
            pass  # 可能已存在

        domains[d] = {
            'domain_id': domain_id,
            'epoch': epoch,
            'signer': signer,
            'pk': pk,
            'tree_levels': tree_levels,
            'root': root,
            'target_idx': target_idx,
            'leaf_hash': leaf_hash,
            'proof': proof,
            'cred_msg': cred_msgs[target_idx],
            'cred_sig': cred_sigs[target_idx],
            'rcp_msg': rcp_msg,
            'rcp_sig': rcp_sig,
            'cred_id': cred_id,
        }

    return domains


# ============================================================
# HFA-DID 端到端验证
# ============================================================

def hfadid_verify_once(chain: ChainClient, domains: dict, domain_idx: int) -> dict:
    """
    单次 HFA-DID 端到端验证 (6 步全部真实执行)

    网络查询阶段: Step 1/2/4 并行, 取 max
    本地计算阶段: Step 3/5/6 串行
    """
    d = domains[domain_idx]
    result = {}

    # === 网络查询阶段 (并行) ===
    with ThreadPoolExecutor(max_workers=3) as pool:
        f1 = pool.submit(chain.query_roster, d['domain_id'], d['epoch'])
        f2 = pool.submit(chain.query_domain_root, d['domain_id'], d['epoch'])
        f4 = pool.submit(chain.query_credential, d['cred_id'])

    _, step1_ms = f1.result()
    _, step2_ms = f2.result()
    _, step4_ms = f4.result()

    result['step1_rtl_ms'] = step1_ms
    result['step2_gcl_ms'] = step2_ms
    result['step4_gel_ms'] = step4_ms
    result['network_phase_ms'] = max(step1_ms, step2_ms, step4_ms)

    # === 本地计算阶段 (串行) ===

    # Step 3: Merkle 路径验证
    t0 = time.perf_counter()
    merkle_valid = verify_merkle_proof(d['leaf_hash'], d['proof'], d['root'])
    step3_ms = (time.perf_counter() - t0) * 1000
    result['step3_merkle_ms'] = step3_ms

    # Step 5: RCP BLS 验证
    rcp_valid, step5_ms = d['signer'].verify_timed(d['rcp_msg'], d['rcp_sig'])
    result['step5_rcp_bls_ms'] = step5_ms

    # Step 6: 凭证 BLS 验证
    cred_valid, step6_ms = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
    result['step6_cred_bls_ms'] = step6_ms

    result['compute_phase_ms'] = step3_ms + step5_ms + step6_ms
    result['total_ms'] = result['network_phase_ms'] + result['compute_phase_ms']
    result['all_valid'] = merkle_valid and rcp_valid and cred_valid

    return result


# ============================================================
# Relay (跨链中继) 端到端验证
# ============================================================

def relay_verify_once(chain: ChainClient, domains: dict, n_domains: int) -> dict:
    """
    单次 Relay 端到端验证: 逐域串行执行全部步骤
    """
    total_ms = 0
    step_totals = {
        'step1_rtl_ms': 0, 'step2_gcl_ms': 0, 'step3_merkle_ms': 0,
        'step4_gel_ms': 0, 'step5_rcp_bls_ms': 0, 'step6_cred_bls_ms': 0,
    }

    for idx in range(n_domains):
        d = domains[idx]

        # Step 1: RTL 查询
        _, s1 = chain.query_roster(d['domain_id'], d['epoch'])
        step_totals['step1_rtl_ms'] += s1

        # Step 2: GCL 查询
        _, s2 = chain.query_domain_root(d['domain_id'], d['epoch'])
        step_totals['step2_gcl_ms'] += s2

        # Step 3: Merkle 验证
        t0 = time.perf_counter()
        verify_merkle_proof(d['leaf_hash'], d['proof'], d['root'])
        s3 = (time.perf_counter() - t0) * 1000
        step_totals['step3_merkle_ms'] += s3

        # Step 4: GEL 查询
        _, s4 = chain.query_credential(d['cred_id'])
        step_totals['step4_gel_ms'] += s4

        # Step 5: RCP BLS 验证
        _, s5 = d['signer'].verify_timed(d['rcp_msg'], d['rcp_sig'])
        step_totals['step5_rcp_bls_ms'] += s5

        # Step 6: 凭证 BLS 验证
        _, s6 = d['signer'].verify_timed(d['cred_msg'], d['cred_sig'])
        step_totals['step6_cred_bls_ms'] += s6

    result = dict(step_totals)
    result['network_phase_ms'] = (step_totals['step1_rtl_ms'] +
                                   step_totals['step2_gcl_ms'] +
                                   step_totals['step4_gel_ms'])
    result['compute_phase_ms'] = (step_totals['step3_merkle_ms'] +
                                   step_totals['step5_rcp_bls_ms'] +
                                   step_totals['step6_cred_bls_ms'])
    result['total_ms'] = result['network_phase_ms'] + result['compute_phase_ms']
    return result


# ============================================================
# 主实验循环
# ============================================================

def run_experiment(domain_counts=None, n_trials=20, n_creds=64):
    if domain_counts is None:
        domain_counts = [2, 5, 10, 15, 20, 30]

    print("=" * 60)
    print("  HFA-DID 端到端跨域验证延迟实验")
    print("  FISCO BCOS + blspy + SHA-256 Merkle")
    print("=" * 60)

    # 初始化链客户端
    chain = ChainClient()
    chain.init()
    print("  Chain connected.\n")

    all_results = []
    summary = []

    for m in domain_counts:
        print(f"\n{'='*50}")
        print(f"  域数量 m={m}, 试验 {n_trials} 次")
        print(f"{'='*50}")

        # Setup
        domains = setup_domains(chain, m, n_creds=n_creds)
        print(f"  Setup complete. Running trials...")

        hfa_totals = []
        relay_totals = []
        hfa_details = []

        for trial in range(n_trials):
            # HFA-DID: 随机选一个域验证
            target_domain = random.randint(0, m - 1)
            hfa = hfadid_verify_once(chain, domains, target_domain)
            hfa_totals.append(hfa['total_ms'])
            hfa_details.append(hfa)

            # Relay: 串行查询所有域
            relay = relay_verify_once(chain, domains, m)
            relay_totals.append(relay['total_ms'])

            all_results.append({
                'scheme': 'HFA-DID', 'num_domains': m, 'trial': trial,
                **{k: round(v, 3) for k, v in hfa.items() if isinstance(v, float)},
                'all_valid': hfa['all_valid'],
            })
            all_results.append({
                'scheme': 'Relay', 'num_domains': m, 'trial': trial,
                **{k: round(v, 3) for k, v in relay.items() if isinstance(v, float)},
            })

            if trial < 3:
                print(f"    Trial {trial}: HFA={hfa['total_ms']:.1f}ms "
                      f"(net={hfa['network_phase_ms']:.1f}, "
                      f"compute={hfa['compute_phase_ms']:.1f}), "
                      f"Relay={relay['total_ms']:.1f}ms, "
                      f"valid={hfa['all_valid']}")

        # 汇总
        hfa_avg = statistics.mean(hfa_totals)
        hfa_p50 = statistics.median(hfa_totals)
        relay_avg = statistics.mean(relay_totals)
        speedup = relay_avg / hfa_avg if hfa_avg > 0 else 0

        # HFA-DID 平均分解
        avg_net = statistics.mean(d['network_phase_ms'] for d in hfa_details)
        avg_merkle = statistics.mean(d['step3_merkle_ms'] for d in hfa_details)
        avg_rcp_bls = statistics.mean(d['step5_rcp_bls_ms'] for d in hfa_details)
        avg_cred_bls = statistics.mean(d['step6_cred_bls_ms'] for d in hfa_details)

        print(f"\n  --- m={m} 汇总 ---")
        print(f"  HFA-DID: avg={hfa_avg:.1f}ms, p50={hfa_p50:.1f}ms")
        print(f"    网络阶段(并行): {avg_net:.1f}ms")
        print(f"    Merkle验证:     {avg_merkle:.3f}ms")
        print(f"    RCP BLS验证:    {avg_rcp_bls:.2f}ms")
        print(f"    凭证BLS验证:    {avg_cred_bls:.2f}ms")
        print(f"  Relay:   avg={relay_avg:.1f}ms")
        print(f"  加速比:  {speedup:.1f}x")

        summary.append({
            'm': m,
            'hfa_avg_ms': round(hfa_avg, 1),
            'hfa_p50_ms': round(hfa_p50, 1),
            'hfa_net_ms': round(avg_net, 1),
            'hfa_merkle_ms': round(avg_merkle, 3),
            'hfa_rcp_bls_ms': round(avg_rcp_bls, 2),
            'hfa_cred_bls_ms': round(avg_cred_bls, 2),
            'relay_avg_ms': round(relay_avg, 1),
            'speedup': round(speedup, 1),
        })

    chain.close()

    # 保存结果
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)

    ts = time.strftime('%Y%m%d_%H%M%S')

    # CSV
    csv_path = os.path.join(results_dir, f'e2e_results_{ts}.csv')
    if all_results:
        keys = all_results[0].keys()
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n  CSV saved: {csv_path}")

    # JSON summary
    json_path = os.path.join(results_dir, f'e2e_summary_{ts}.json')
    with open(json_path, 'w') as f:
        json.dump({'summary': summary, 'params': {
            'n_trials': n_trials, 'n_creds': n_creds,
            'committee_n': 10, 'committee_t': 7,
        }}, f, indent=2)
    print(f"  JSON saved: {json_path}")

    return summary


if __name__ == '__main__':
    # 小规模快速测试
    if '--quick' in sys.argv:
        run_experiment(domain_counts=[2, 5], n_trials=5, n_creds=32)
    else:
        run_experiment(domain_counts=[2, 5, 10, 15, 20, 30], n_trials=20, n_creds=64)
