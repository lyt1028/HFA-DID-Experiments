"""
BLS 门限签名实现 (基于 py_ecc 的 BLS12-381 曲线)
用于凭证签发、锚定背书、更新记录签名

对应论文:
  - 公式 (3.1): 门限签名 sigma = prod(H(msg)^{s_i})
  - 公式 (3.9): BLS 配对验证 e(sigma, g) = e(H(msg), PK_CC)
  - 算法 3.1:  凭证委员会联合签发算法

说明:
  py_ecc 是纯 Python 实现, 性能适合学术实验但不适合生产环境
  实际测量的绝对延迟值偏高, 但各方案间的相对比值是有效的
"""

import time
import hashlib
from typing import List, Dict, Tuple

from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    pubkey_to_G1,
    signature_to_G2,
    G2_to_signature,
)
from py_ecc.optimized_bls12_381 import (
    G1,
    G2,
    Z1,
    Z2,
    multiply,
    add,
    neg,
    curve_order,
)


class BLSThresholdSignature:
    """
    (t, n) BLS 门限签名

    - 使用 BLS12-381 曲线
    - 签名在 G2 上, 公钥在 G1 上
    - 支持签名聚合与门限重构
    """

    def __init__(self, threshold: int, num_members: int):
        self.threshold = threshold
        self.num_members = num_members
        self.curve_order = curve_order

        # 密钥材料 (DKG 后填充)
        self.master_sk: int = 0
        self.master_pk = Z1  # G1 点
        self.shares: Dict[int, int] = {}      # {member_id: sk_share}
        self.public_shares: Dict[int, any] = {}  # {member_id: pk_share (G1 point)}

    def keygen(self, member_ids: List[int] = None):
        """
        模拟 DKG: 生成主密钥并分发份额

        实际系统中应通过分布式密钥生成协议完成,
        这里为实验简化为中心化生成 + Shamir 分发
        """
        from .shamir import ShamirSecretSharing
        import random

        if member_ids is None:
            member_ids = list(range(1, self.num_members + 1))

        # 生成主密钥
        self.master_sk = random.randint(1, self.curve_order - 1)
        self.master_pk = multiply(G1, self.master_sk)

        # Shamir 分发份额
        sss = ShamirSecretSharing(self.curve_order)
        self.shares = sss.split(self.master_sk, self.threshold,
                                len(member_ids), member_ids)

        # 计算各成员公钥份额
        self.public_shares = {}
        for mid, sk_share in self.shares.items():
            self.public_shares[mid] = multiply(G1, sk_share)

        return self.master_pk

    def partial_sign(self, member_id: int, message: bytes) -> Tuple:
        """
        成员生成部分签名

        Args:
            member_id: 成员ID
            message:   待签名消息

        Returns:
            G2 上的部分签名点
        """
        sk_share = self.shares[member_id]
        msg_point = self._hash_to_g2(message)
        return multiply(msg_point, sk_share)

    def aggregate_partial_sigs(self, partial_sigs: Dict[int, Tuple]) -> Tuple:
        """
        聚合部分签名 (拉格朗日插值)

        Args:
            partial_sigs: {member_id: partial_sig_point}

        Returns:
            聚合签名 (G2 点)
        """
        if len(partial_sigs) < self.threshold:
            raise ValueError(f"部分签名不足: 需要 {self.threshold}, 仅有 {len(partial_sigs)}")

        ids = list(partial_sigs.keys())[:self.threshold]
        result = Z2  # 无穷远点

        for i, xi in enumerate(ids):
            # 拉格朗日系数 lambda_i = prod(xj / (xj - xi)) for j != i
            lam = 1
            for j, xj in enumerate(ids):
                if i != j:
                    lam = (lam * xj * pow(xj - xi, -1, self.curve_order)) % self.curve_order

            weighted = multiply(partial_sigs[xi], lam)
            result = add(result, weighted)

        return result

    def verify(self, message: bytes, signature, public_key=None) -> bool:
        """
        验证 BLS 签名: e(PK, H(m)) == e(G1, sigma)

        Args:
            message:    原始消息
            signature:  聚合签名 (G2 点)
            public_key: 聚合公钥 (G1 点), 默认使用 master_pk
        """
        from py_ecc.optimized_bls12_381 import pairing
        pk = public_key or self.master_pk
        msg_point = self._hash_to_g2(message)

        lhs = pairing(msg_point, pk)
        rhs = pairing(signature, G1)
        return lhs == rhs

    def sign_and_time(self, message: bytes,
                      signer_ids: List[int] = None) -> Tuple[any, Dict[str, float]]:
        """
        带分阶段计时的完整签发流程

        Returns:
            (signature, timings_ms)
        """
        timings = {}
        if signer_ids is None:
            signer_ids = list(self.shares.keys())[:self.threshold]

        # 阶段1: 各成员生成部分签名
        t0 = time.perf_counter()
        partial_sigs = {}
        for mid in signer_ids:
            partial_sigs[mid] = self.partial_sign(mid, message)
        timings['partial_sign_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段2: 聚合
        t0 = time.perf_counter()
        agg_sig = self.aggregate_partial_sigs(partial_sigs)
        timings['aggregate_ms'] = (time.perf_counter() - t0) * 1000

        # 阶段3: 验证
        t0 = time.perf_counter()
        valid = self.verify(message, agg_sig)
        timings['verify_ms'] = (time.perf_counter() - t0) * 1000

        timings['total_ms'] = sum(timings.values())
        return agg_sig, timings

    def verify_and_time(self, message: bytes, signature) -> Tuple[bool, float]:
        """
        带计时的验证

        Returns:
            (is_valid, latency_ms)
        """
        t0 = time.perf_counter()
        result = self.verify(message, signature)
        latency = (time.perf_counter() - t0) * 1000
        return result, latency

    @staticmethod
    def _hash_to_g2(message: bytes):
        """将消息哈希到 G2 曲线上的点 (简化实现)"""
        # 使用消息哈希作为标量乘以 G2 生成元
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % curve_order
        if h == 0:
            h = 1
        return multiply(G2, h)
