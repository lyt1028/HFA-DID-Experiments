"""
Re-DKG: 公钥不变的密钥份额轮转协议
用于委员会轮换时的密钥安全继承

对应论文:
  - 公式 (4.5):  份额重分配 s_{i->j} = f_i(id_j) mod q
  - 公式 (4.6):  多项式承诺 C_{i,k} = g^{a_{i,k}}
  - 公式 (4.7):  新成员份额 s_j' = sum(s_{i->j})
  - 公式 (4.8):  留任成员份额 s_j' = s_j + sum(s_{i->j})
  - 公式 (4.11): 总私钥不变性 sum(s_j') = sum(s_j) = x
  - 算法 4.2:   Re-DKG 完整流程
"""

import time
from typing import List, Dict, Tuple
from .shamir import ShamirSecretSharing


class ReDKG:
    """Re-DKG 轮转协议"""

    def __init__(self, prime: int, threshold: int):
        """
        Args:
            prime:     有限域模数 (与 BLS 曲线阶或变色龙哈希群阶一致)
            threshold: 门限值 t
        """
        self.q = prime
        self.threshold = threshold
        self.sss = ShamirSecretSharing(prime)

    def rotate(self, old_committee: List[int], new_committee: List[int],
               old_shares: Dict[int, int]) -> Tuple[Dict[int, int], Dict[str, float]]:
        """
        执行完整的 Re-DKG 轮转

        Args:
            old_committee: 旧委员会成员 ID 列表
            new_committee: 新委员会成员 ID 列表
            old_shares:    {member_id: share_value} 旧份额

        Returns:
            (new_shares, stage_timings_ms)
        """
        timings = {}

        # ========== 阶段1: 份额重分配 ==========
        t0 = time.perf_counter()

        # 每个旧成员生成零秘密多项式并计算子份额
        sub_shares: Dict[Tuple[int, int], int] = {}
        poly_coeffs: Dict[int, List[int]] = {}

        for from_id in old_committee:
            zero_shares, coeffs = self.sss.split_zero(
                self.threshold, len(new_committee), new_committee
            )
            poly_coeffs[from_id] = coeffs
            for to_id in new_committee:
                sub_shares[(from_id, to_id)] = zero_shares[to_id]

        timings['phase1_redistribute_ms'] = (time.perf_counter() - t0) * 1000

        # ========== 阶段2: 新份额聚合 ==========
        t0 = time.perf_counter()

        new_shares: Dict[int, int] = {}
        old_set = set(old_committee)

        for to_id in new_committee:
            received_sum = sum(
                sub_shares[(from_id, to_id)] for from_id in old_committee
            ) % self.q

            if to_id in old_set and to_id in old_shares:
                # 留任成员: s_j' = s_j + sum(s_{i->j})  [公式 4.8]
                new_shares[to_id] = (old_shares[to_id] + received_sum) % self.q
            else:
                # 新成员: s_j' = sum(s_{i->j})  [公式 4.7]
                new_shares[to_id] = received_sum % self.q

        timings['phase2_aggregate_ms'] = (time.perf_counter() - t0) * 1000

        # ========== 阶段3: 一致性验证 ==========
        # Shamir 方案中秘密通过拉格朗日插值 f(0) 重构, 而非直接求和
        t0 = time.perf_counter()

        old_secret = self.sss.reconstruct(
            {mid: old_shares[mid] for mid in old_committee}, self.threshold
        )
        new_secret = self.sss.reconstruct(new_shares, self.threshold)
        invariance_ok = (old_secret == new_secret)

        timings['phase3_verify_ms'] = (time.perf_counter() - t0) * 1000
        timings['total_ms'] = sum(v for k, v in timings.items() if k.endswith('_ms'))
        timings['invariance_check'] = invariance_ok

        if not invariance_ok:
            raise RuntimeError("Re-DKG 一致性验证失败: 重构秘密值发生变化")

        return new_shares, timings

    def verify_secret_invariance(self, old_shares: Dict[int, int],
                                  new_shares: Dict[int, int],
                                  old_committee: List[int],
                                  new_committee: List[int]) -> bool:
        """
        验证轮转前后秘密不变 (公式 4.11)
        通过拉格朗日插值重构 f(0) 进行验证
        """
        old_secret = self.sss.reconstruct(
            {mid: old_shares[mid] for mid in old_committee}, self.threshold
        )
        new_secret = self.sss.reconstruct(new_shares, self.threshold)
        return old_secret == new_secret

    def verify_reconstructed_secret(self, shares: Dict[int, int],
                                     expected_secret: int) -> bool:
        """验证份额可正确重构出原始秘密"""
        reconstructed = self.sss.reconstruct(shares, self.threshold)
        return reconstructed == expected_secret

    def simulate_multi_epoch_rotation(self, initial_secret: int,
                                       num_epochs: int,
                                       committee_size: int,
                                       rotation_fraction: float = 0.3
                                       ) -> List[Dict]:
        """
        模拟多周期连续轮转

        Args:
            initial_secret:    初始秘密 (主密钥或陷门)
            num_epochs:        轮转周期数
            committee_size:    委员会规模
            rotation_fraction: 每次轮换的成员比例

        Returns:
            每个周期的轮转记录列表
        """
        import random
        records = []

        # 初始分发
        current_ids = list(range(1, committee_size + 1))
        current_shares = self.sss.split(
            initial_secret, self.threshold, committee_size, current_ids
        )
        next_id_counter = committee_size + 1

        for epoch in range(num_epochs):
            # 确定新委员会 (部分轮换)
            num_rotate = max(1, int(committee_size * rotation_fraction))
            staying = current_ids[:-num_rotate]
            new_members = list(range(next_id_counter, next_id_counter + num_rotate))
            next_id_counter += num_rotate
            new_ids = staying + new_members

            # 执行轮转
            new_shares, timings = self.rotate(current_ids, new_ids, current_shares)

            # 验证秘密可重构
            reconstructed = self.sss.reconstruct(new_shares, self.threshold)
            secret_valid = (reconstructed == initial_secret)

            records.append({
                'epoch': epoch + 1,
                'old_committee': current_ids[:],
                'new_committee': new_ids[:],
                'rotated_out': current_ids[-num_rotate:],
                'rotated_in': new_members,
                'timings': timings,
                'secret_reconstructable': secret_valid,
            })

            current_ids = new_ids
            current_shares = new_shares

        return records
