"""
扩展Re-DKG: 增加乐观路径实现
在原redkg.py基础上新增optimistic_rotate方法
"""
import time
from typing import List, Dict, Tuple
from .shamir import ShamirSecretSharing


class ReDKG:
    """Re-DKG 轮转协议 (含乐观路径与完整路径)"""

    def __init__(self, prime: int, threshold: int):
        self.q = prime
        self.threshold = threshold
        self.sss = ShamirSecretSharing(prime)

    def rotate_full(self, old_committee, new_committee, old_shares):
        """
        完整路径: 所有旧成员向所有新成员分发份额
        每个旧成员i发送合并值 m_{i->j} = lambda_i * sk_i + f_i(j)
        其中f_i为零常数项随机多项式
        通信复杂度: O(|C_old| * |C_new|) = O(n^2)
        """
        timings = {}

        # Lagrange系数 (在旧委员会上)
        lambdas = {}
        for xi in old_committee:
            lam = 1
            for xj in old_committee:
                if xi != xj:
                    lam = (lam * xj * pow(xj - xi, -1, self.q)) % self.q
            lambdas[xi] = lam

        # 阶段1: 每个旧成员生成零秘密多项式, 计算合并值发给所有新成员
        t0 = time.perf_counter()
        merged_values = {}  # merged_values[(from_id, to_id)]
        comm_messages = 0
        for from_id in old_committee:
            zero_shares, _ = self.sss.split_zero(
                self.threshold, len(new_committee), new_committee
            )
            for to_id in new_committee:
                # m_{i->j} = lambda_i * sk_i + f_i(j)
                m = (lambdas[from_id] * old_shares[from_id] + zero_shares[to_id]) % self.q
                merged_values[(from_id, to_id)] = m
                comm_messages += 1
        timings['phase1_redistribute_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段2: 新份额聚合 sk_j_new = sum(m_{i->j})
        t0 = time.perf_counter()
        new_shares = {}
        for to_id in new_committee:
            new_shares[to_id] = sum(
                merged_values[(from_id, to_id)] for from_id in old_committee
            ) % self.q
        timings['phase2_aggregate_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段3: 验证
        t0 = time.perf_counter()
        old_secret = self.sss.reconstruct(
            {mid: old_shares[mid] for mid in old_committee}, self.threshold
        )
        new_secret = self.sss.reconstruct(new_shares, self.threshold)
        invariance_ok = (old_secret == new_secret)
        timings['phase3_verify_ms'] = (time.perf_counter() - t0) * 1000

        timings['total_ms'] = sum(v for k, v in timings.items() if k.endswith('_ms'))
        timings['comm_messages'] = comm_messages
        timings['path'] = 'full'

        if not invariance_ok:
            raise RuntimeError("Re-DKG full path: secret invariance check failed")

        return new_shares, timings

    def rotate_optimistic(self, old_committee, new_committee, old_shares):
        """
        乐观路径: 仅留任节点生成扰动多项式
        - 留任节点: 增量更新 sk_k_new = sk_k_old + sum(delta_l(k))
        - 新节点: 合并值 m_{k->j} = lambda_k * sk_k_old + delta_k(j)
        通信复杂度: O(|C_stay| * |C_join|) + O(|C_stay|^2)
        当留存率高时远小于O(n^2)
        """
        timings = {}

        old_set = set(old_committee)
        new_set = set(new_committee)
        stay = sorted(old_set & new_set)
        join = sorted(new_set - old_set)

        if len(stay) < self.threshold:
            raise ValueError(f"Optimistic path requires |C_stay|={len(stay)} >= t={self.threshold}")

        # 阶段1: 留任节点生成零常数项扰动多项式 delta_k(x), delta_k(0)=0
        t0 = time.perf_counter()
        delta_shares = {}  # delta_shares[(from_k, to_id)] = delta_k(to_id)
        comm_messages = 0
        all_new_ids = stay + join

        for k in stay:
            # 生成 delta_k 对所有新成员的值
            zero_shares, _ = self.sss.split_zero(
                self.threshold, len(all_new_ids), all_new_ids
            )
            for to_id in all_new_ids:
                delta_shares[(k, to_id)] = zero_shares[to_id]

            # 通信: 留任节点间互发 + 留任节点向新节点发合并值
            comm_messages += len(stay) - 1  # 给其他留任节点发delta值
            comm_messages += len(join)      # 给新节点发合并值

        timings['phase1_perturb_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段2a: 留任节点增量更新
        t0 = time.perf_counter()
        new_shares = {}
        for k in stay:
            # sk_k_new = sk_k_old + sum_{l in C_stay} delta_l(k)  (包括l=k自己)
            delta_sum = sum(
                delta_shares[(l, k)] for l in stay
            ) % self.q
            new_shares[k] = (old_shares[k] + delta_sum) % self.q

        # 阶段2b: 新节点通过合并值获取份额
        # Lagrange系数 (在stay集合上)
        lambdas = {}
        for xi in stay:
            lam = 1
            for xj in stay:
                if xi != xj:
                    lam = (lam * xj * pow(xj - xi, -1, self.q)) % self.q
            lambdas[xi] = lam

        for j in join:
            merged_sum = 0
            for k in stay:
                # m_{k->j} = lambda_k * sk_k_old + delta_k(j)
                m = (lambdas[k] * old_shares[k] + delta_shares[(k, j)]) % self.q
                merged_sum = (merged_sum + m) % self.q
            new_shares[j] = merged_sum

        timings['phase2_aggregate_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段3: 验证秘密不变性
        t0 = time.perf_counter()
        old_secret = self.sss.reconstruct(
            {mid: old_shares[mid] for mid in old_committee}, self.threshold
        )
        new_secret = self.sss.reconstruct(new_shares, self.threshold)
        invariance_ok = (old_secret == new_secret)
        timings['phase3_verify_ms'] = (time.perf_counter() - t0) * 1000

        timings['total_ms'] = sum(v for k, v in timings.items() if k.endswith('_ms'))
        timings['comm_messages'] = comm_messages
        timings['path'] = 'optimistic'
        timings['retention_rate'] = len(stay) / len(new_committee)
        timings['stay_count'] = len(stay)
        timings['join_count'] = len(join)

        if not invariance_ok:
            raise RuntimeError("Re-DKG optimistic path: secret invariance check failed")

        return new_shares, timings

    def rotate(self, old_committee, new_committee, old_shares, rho_th=0.7):
        """
        自动选择路径: rho >= rho_th 走乐观路径, 否则走完整路径
        """
        old_set = set(old_committee)
        new_set = set(new_committee)
        stay = old_set & new_set
        rho = len(stay) / len(new_set) if new_set else 0

        if rho >= rho_th and len(stay) >= self.threshold:
            return self.rotate_optimistic(old_committee, new_committee, old_shares)
        else:
            return self.rotate_full(old_committee, new_committee, old_shares)

    def verify_secret_invariance(self, old_shares, new_shares, old_committee, new_committee):
        old_secret = self.sss.reconstruct(
            {mid: old_shares[mid] for mid in old_committee}, self.threshold
        )
        new_secret = self.sss.reconstruct(new_shares, self.threshold)
        return old_secret == new_secret
