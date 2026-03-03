"""
Shamir 秘密共享方案
用于门限签名、变色龙哈希陷门分发、Re-DKG 等模块的基础组件

对应论文:
  - 公式 (4.5): 份额重分配 s_{i->j} = f_i(id_j) mod q
  - 公式 (4.9)/(4.10): 新份额聚合
"""

import random
from typing import List, Tuple, Dict


class ShamirSecretSharing:
    """Shamir (t, n) 秘密共享"""

    def __init__(self, prime: int):
        """
        Args:
            prime: 有限域的模数 (大素数)
        """
        self.p = prime

    def _mod_inverse(self, a: int, m: int) -> int:
        """扩展欧几里得算法求模逆"""
        return pow(a, -1, m)

    def _eval_poly(self, coeffs: List[int], x: int) -> int:
        """在 x 处求多项式值: f(x) = c0 + c1*x + c2*x^2 + ..."""
        result = 0
        for i, c in enumerate(coeffs):
            result = (result + c * pow(x, i, self.p)) % self.p
        return result

    def split(self, secret: int, threshold: int,
              num_shares: int, ids: List[int] = None) -> Dict[int, int]:
        """
        将秘密分成 num_shares 个份额, 需要 threshold 个才能重构

        Args:
            secret:    秘密值
            threshold: 门限值 t
            num_shares: 总份额数 n
            ids:       各份额的标识 (默认 1..n)

        Returns:
            {id: share_value} 字典
        """
        if ids is None:
            ids = list(range(1, num_shares + 1))
        assert len(ids) == num_shares
        assert threshold <= num_shares

        # 生成 t-1 阶随机多项式, 常数项为 secret
        coeffs = [secret % self.p]
        for _ in range(threshold - 1):
            coeffs.append(random.randint(0, self.p - 1))

        shares = {}
        for node_id in ids:
            shares[node_id] = self._eval_poly(coeffs, node_id)

        return shares

    def split_zero(self, threshold: int, num_shares: int,
                   ids: List[int] = None) -> Tuple[Dict[int, int], List[int]]:
        """
        生成常数项为零的秘密共享 (用于 Re-DKG)
        对应论文: f_i(0) = 0

        Returns:
            (shares_dict, coefficients)
        """
        if ids is None:
            ids = list(range(1, num_shares + 1))

        # 常数项 = 0, 其余随机
        coeffs = [0]
        for _ in range(threshold - 1):
            coeffs.append(random.randint(1, self.p - 1))

        shares = {}
        for node_id in ids:
            shares[node_id] = self._eval_poly(coeffs, node_id)

        return shares, coeffs

    def reconstruct(self, shares: Dict[int, int], threshold: int) -> int:
        """
        拉格朗日插值重构秘密

        Args:
            shares:    {id: share_value}, 需 >= threshold 个
            threshold: 门限值

        Returns:
            重构的秘密值
        """
        items = list(shares.items())[:threshold]
        if len(items) < threshold:
            raise ValueError(f"份额不足: 需要 {threshold}, 仅有 {len(items)}")

        secret = 0
        for i, (xi, yi) in enumerate(items):
            # 拉格朗日基多项式在 x=0 处的值
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(items):
                if i != j:
                    numerator = (numerator * (-xj)) % self.p
                    denominator = (denominator * (xi - xj)) % self.p

            lagrange = (yi * numerator * self._mod_inverse(denominator, self.p)) % self.p
            secret = (secret + lagrange) % self.p

        return secret

    def verify_share(self, share_id: int, share_value: int,
                     commitments: List[int], g: int) -> bool:
        """
        Feldman VSS: 验证份额是否与公开承诺一致
        检查 g^{share_value} == prod(C_k^{id^k})

        Args:
            share_id:    份额持有者ID
            share_value: 份额值
            commitments: [g^{a_0}, g^{a_1}, ..., g^{a_{t-1}}]
            g:           生成元

        Returns:
            验证是否通过
        """
        lhs = pow(g, share_value, self.p)
        rhs = 1
        for k, ck in enumerate(commitments):
            rhs = (rhs * pow(ck, pow(share_id, k), self.p)) % self.p
        return lhs == rhs
