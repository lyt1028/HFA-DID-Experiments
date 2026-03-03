"""
变色龙哈希实现 (基于离散对数的构造)
用于凭证可验证更新与撤销

对应论文:
  - 公式 (4.15): Commit_i = CH(m_i, r_i)
  - 公式 (4.16): CH(m_old, r_old) = CH(m_new, r_new)  碰撞/更新
  - 公式 (4.22): 承诺不变 => Merkle路径不变
  - 公式 (4.25): 陷门份额轮转不变性

方案:
  基于 Schnorr 群上的变色龙哈希:
    KeyGen:  选大素数 p, q (q | p-1), 生成元 g
             陷门 td <- Z_q, 公钥 pk = g^td mod p
    Hash:    CH(m, r) = g^m * pk^r mod p
    Forge:   已知 td, 给定 (m, r) 和 m', 计算:
             r' = r + (m - m') * td^{-1} mod q
             使得 CH(m, r) = CH(m', r')
"""

import random
import hashlib
import time
from typing import Tuple, Dict, List

from Crypto.Util.number import getPrime, isPrime


def _find_safe_prime_group(bits: int = 256) -> Tuple[int, int, int]:
    """
    生成安全素数群参数 (p, q, g)
    q 是素数, p = 2q + 1 也是素数, g 是 Z_p* 中 q 阶子群的生成元
    """
    while True:
        q = getPrime(bits)
        p = 2 * q + 1
        if isPrime(p):
            # 寻找 q 阶子群的生成元
            for h in range(2, 100):
                g = pow(h, 2, p)
                if g != 1 and pow(g, q, p) == 1:
                    return p, q, g
    # 不会到达这里


class ChameleonHash:
    """变色龙哈希 (单密钥版本)"""

    def __init__(self, bits: int = 256):
        self.p, self.q, self.g = _find_safe_prime_group(bits)
        self.td: int = 0   # 陷门 (私钥)
        self.pk: int = 0   # 公钥

    def keygen(self) -> Tuple[int, int]:
        """
        生成变色龙哈希密钥对
        Returns: (pk, td)
        """
        self.td = random.randint(2, self.q - 1)
        self.pk = pow(self.g, self.td, self.p)
        return self.pk, self.td

    def hash(self, m: int, r: int) -> int:
        """
        计算变色龙哈希: CH(m, r) = g^m * pk^r mod p
        """
        return (pow(self.g, m % self.q, self.p) *
                pow(self.pk, r % self.q, self.p)) % self.p

    def forge(self, m_old: int, r_old: int, m_new: int) -> int:
        """
        利用陷门 td 计算碰撞: 找 r_new 使 CH(m_old, r_old) = CH(m_new, r_new)

        r_new = r_old + (m_old - m_new) * td^{-1} mod q
        """
        if self.td == 0:
            raise ValueError("陷门未设置, 请先调用 keygen()")
        td_inv = pow(self.td, -1, self.q)
        r_new = (r_old + (m_old - m_new) * td_inv) % self.q
        return r_new

    def verify_collision(self, m_old: int, r_old: int,
                         m_new: int, r_new: int) -> bool:
        """验证碰撞: CH(m_old, r_old) == CH(m_new, r_new)"""
        return self.hash(m_old, r_old) == self.hash(m_new, r_new)

    @staticmethod
    def message_to_int(message: str, q: int) -> int:
        """将字符串消息转为 Z_q 中的整数"""
        h = hashlib.sha256(message.encode('utf-8')).digest()
        return int.from_bytes(h, 'big') % q

    def random_r(self) -> int:
        """生成随机因子 r"""
        return random.randint(1, self.q - 1)


class ThresholdChameleonHash:
    """
    门限变色龙哈希: 陷门以 Shamir 秘密共享形式分布于委员会成员间

    对应论文公式 (4.25):
      sum(td_i^{(e)}) = sum(td_j^{(e+1)}) = td  (mod q)
    """

    def __init__(self, ch: ChameleonHash, threshold: int, committee_size: int):
        self.ch = ch
        self.threshold = threshold
        self.committee_size = committee_size
        self.shares: Dict[int, int] = {}

    def distribute_trapdoor(self, td: int, member_ids: List[int]) -> Dict[int, int]:
        """
        将陷门通过 Shamir 秘密共享分发给委员会成员

        Args:
            td:         陷门秘密
            member_ids: 成员ID列表

        Returns:
            {member_id: share} 份额字典
        """
        from .shamir import ShamirSecretSharing
        sss = ShamirSecretSharing(self.ch.q)
        self.shares = sss.split(td, self.threshold, len(member_ids), member_ids)
        return self.shares

    def threshold_forge(self, share_subset: Dict[int, int],
                        m_old: int, r_old: int, m_new: int) -> int:
        """
        门限碰撞计算: 收集 >= t 个份额, 重构陷门后计算碰撞

        Args:
            share_subset: {member_id: share_value}, 需 >= threshold 个
            m_old:  原凭证内容哈希值
            r_old:  原随机因子
            m_new:  新凭证内容哈希值

        Returns:
            r_new 使 CH(m_old, r_old) = CH(m_new, r_new)
        """
        from .shamir import ShamirSecretSharing
        sss = ShamirSecretSharing(self.ch.q)
        td = sss.reconstruct(share_subset, self.threshold)

        td_inv = pow(td, -1, self.ch.q)
        r_new = (r_old + (m_old - m_new) * td_inv) % self.ch.q
        return r_new

    def threshold_forge_timed(self, share_subset: Dict[int, int],
                              m_old: int, r_old: int, m_new: int) -> Tuple[int, Dict[str, float]]:
        """
        带分阶段计时的门限碰撞计算

        Returns:
            (r_new, stage_timings_ms)
        """
        from .shamir import ShamirSecretSharing
        timings = {}

        # 阶段1: 陷门重构
        t0 = time.perf_counter()
        sss = ShamirSecretSharing(self.ch.q)
        td = sss.reconstruct(share_subset, self.threshold)
        timings['trapdoor_reconstruct_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段2: 碰撞计算
        t0 = time.perf_counter()
        td_inv = pow(td, -1, self.ch.q)
        r_new = (r_old + (m_old - m_new) * td_inv) % self.ch.q
        timings['collision_compute_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段3: 碰撞验证
        t0 = time.perf_counter()
        assert self.ch.hash(m_old, r_old) == self.ch.hash(m_new, r_new)
        timings['collision_verify_ms'] = (time.perf_counter() - t0) * 1000

        timings['total_ms'] = sum(timings.values())
        return r_new, timings
