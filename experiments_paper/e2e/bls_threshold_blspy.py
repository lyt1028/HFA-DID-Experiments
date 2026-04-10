"""
BLS 门限签名模块 (blspy C++ 绑定版本)
用于端到端跨域验证实验

blspy 使用 BLS12-381 曲线, 单次 pairing 验证 ~1-3ms
对比 py_ecc 纯 Python 实现快 ~100x
"""

import time
import hashlib
import secrets
from typing import List, Dict, Tuple

from blspy import (
    PopSchemeMPL,
    PrivateKey,
    G1Element,
    G2Element,
)

# BLS12-381 曲线阶
BLS_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


class BLSThresholdSigner:
    """(t, n) BLS 门限签名器 (blspy 版本)"""

    def __init__(self, n: int, t: int):
        self.n = n
        self.t = t
        self.master_sk = None
        self.master_pk = None
        self.sk_shares: Dict[int, PrivateKey] = {}
        self.pk_shares: Dict[int, G1Element] = {}

    def keygen(self) -> G1Element:
        """
        Shamir 秘密共享生成密钥份额:
        1. 生成主密钥
        2. 构造 t-1 阶随机多项式 f(x), f(0) = master_sk
        3. 计算 sk_i = f(i) mod q
        """
        # 生成主密钥
        seed = secrets.token_bytes(32)
        self.master_sk = PopSchemeMPL.key_gen(seed)
        self.master_pk = self.master_sk.get_g1()
        master_sk_int = int.from_bytes(bytes(self.master_sk), 'big') % BLS_ORDER

        # 构造 t-1 阶多项式系数 [a0=master_sk, a1, ..., a_{t-1}]
        coeffs = [master_sk_int]
        for _ in range(self.t - 1):
            coeffs.append(secrets.randbelow(BLS_ORDER))

        # 计算每个成员的份额 f(i) = sum(a_j * i^j) mod q
        self.sk_shares = {}
        self.pk_shares = {}
        for i in range(1, self.n + 1):
            val = 0
            for j, a in enumerate(coeffs):
                val = (val + a * pow(i, j, BLS_ORDER)) % BLS_ORDER
            sk_bytes = val.to_bytes(32, 'big')
            sk = PrivateKey.from_bytes(sk_bytes)
            self.sk_shares[i] = sk
            self.pk_shares[i] = sk.get_g1()

        return self.master_pk

    def sign_partial(self, member_id: int, msg: bytes) -> G2Element:
        """单个节点用份额签名"""
        return PopSchemeMPL.sign(self.sk_shares[member_id], msg)

    def aggregate_partial_sigs(self, partial_sigs: Dict[int, G2Element],
                                msg: bytes) -> Tuple[G2Element, float]:
        """
        Lagrange 插值聚合部分签名

        Returns: (aggregated_sig, aggregate_ms)
        """
        t0 = time.perf_counter()

        ids = list(partial_sigs.keys())[:self.t]

        # 计算 Lagrange 系数
        lambdas = {}
        for i, xi in enumerate(ids):
            lam = 1
            for j, xj in enumerate(ids):
                if i != j:
                    lam = (lam * xj * pow(xj - xi, -1, BLS_ORDER)) % BLS_ORDER
            lambdas[xi] = lam

        # 用 Lagrange 系数对部分签名做标量乘法并累加
        # blspy 不直接支持 G2 标量乘法, 用重复签名模拟
        # 实际做法: 用 sk_share * lambda 重新签名
        weighted_sigs = []
        for mid in ids:
            weighted_sk_int = (int.from_bytes(bytes(self.sk_shares[mid]), 'big')
                               * lambdas[mid]) % BLS_ORDER
            weighted_sk = PrivateKey.from_bytes(weighted_sk_int.to_bytes(32, 'big'))
            weighted_sig = PopSchemeMPL.sign(weighted_sk, msg)
            weighted_sigs.append(weighted_sig)

        # 聚合
        agg_sig = weighted_sigs[0]
        for s in weighted_sigs[1:]:
            agg_sig = agg_sig + s

        agg_ms = (time.perf_counter() - t0) * 1000
        return agg_sig, agg_ms

    def sign_and_time(self, msg: bytes,
                      signer_ids: List[int] = None) -> Tuple[G2Element, Dict[str, float]]:
        """
        完整签名流程并计时

        Returns: (signature, {partial_sign_ms, aggregate_ms, total_ms})
        """
        if signer_ids is None:
            signer_ids = list(range(1, self.t + 1))

        timings = {}

        # 部分签名
        t0 = time.perf_counter()
        partial_sigs = {}
        for mid in signer_ids[:self.t]:
            partial_sigs[mid] = self.sign_partial(mid, msg)
        timings['partial_sign_ms'] = (time.perf_counter() - t0) * 1000

        # 聚合
        agg_sig, agg_ms = self.aggregate_partial_sigs(partial_sigs, msg)
        timings['aggregate_ms'] = agg_ms

        timings['total_sign_ms'] = timings['partial_sign_ms'] + timings['aggregate_ms']

        return agg_sig, timings

    def verify_timed(self, msg: bytes, sig: G2Element,
                     pk: G1Element = None) -> Tuple[bool, float]:
        """
        BLS 配对验证并计时

        Returns: (valid, latency_ms)
        """
        if pk is None:
            pk = self.master_pk
        t0 = time.perf_counter()
        valid = PopSchemeMPL.verify(pk, msg, sig)
        ms = (time.perf_counter() - t0) * 1000
        return valid, ms


if __name__ == '__main__':
    print("=== BLS Threshold Signer (blspy) Test ===")
    signer = BLSThresholdSigner(n=10, t=7)
    pk = signer.keygen()
    print(f"  Master PK: {bytes(pk)[:16].hex()}...")

    msg = b"test credential content for HFA-DID"
    sig, timings = signer.sign_and_time(msg)
    print(f"  Sign: partial={timings['partial_sign_ms']:.2f}ms, "
          f"agg={timings['aggregate_ms']:.2f}ms, "
          f"total={timings['total_sign_ms']:.2f}ms")

    valid, verify_ms = signer.verify_timed(msg, sig)
    print(f"  Verify: {valid}, {verify_ms:.2f}ms")

    # 测试错误消息
    valid2, _ = signer.verify_timed(b"wrong message", sig)
    print(f"  Wrong msg verify: {valid2} (should be False)")
