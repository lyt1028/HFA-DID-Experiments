"""
blspy BLS 门限签名模块
使用C++绑定的blspy库, 单次pairing约2-5ms
"""
import time
import hashlib
import secrets
from typing import List, Dict, Tuple

from blspy import (
    PrivateKey, G1Element, G2Element,
    AugSchemeMPL, BasicSchemeMPL
)


class BLSThresholdBlspy:
    """(t, n) BLS 门限签名 (blspy C++实现)"""

    def __init__(self, n: int, t: int):
        self.n = n
        self.t = t
        self.master_sk = None
        self.master_pk = None
        self.sk_shares = {}   # {id: PrivateKey}
        self.pk_shares = {}   # {id: G1Element}
        # BLS curve order
        self.order = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    def keygen(self, member_ids=None):
        """Shamir秘密共享生成密钥份额"""
        if member_ids is None:
            member_ids = list(range(1, self.n + 1))

        # 生成主密钥
        seed = secrets.token_bytes(32)
        self.master_sk = AugSchemeMPL.key_gen(seed)
        self.master_pk = self.master_sk.get_g1()

        # 构造t-1阶随机多项式 f(x), f(0) = master_sk_int
        master_int = int.from_bytes(bytes(self.master_sk), 'big') % self.order
        coeffs = [master_int]
        for _ in range(self.t - 1):
            coeffs.append(secrets.randbelow(self.order))

        # 计算每个成员的份额 f(id)
        for mid in member_ids:
            val = 0
            for j, c in enumerate(coeffs):
                val = (val + c * pow(mid, j, self.order)) % self.order
            sk_bytes = val.to_bytes(32, 'big')
            self.sk_shares[mid] = PrivateKey.from_bytes(sk_bytes)
            self.pk_shares[mid] = self.sk_shares[mid].get_g1()

        return self.master_pk

    def sign_partial(self, member_id, msg):
        """单个成员生成部分签名"""
        return AugSchemeMPL.sign(self.sk_shares[member_id], msg)

    def _lagrange_coeff(self, indices, i):
        """计算Lagrange系数 lambda_i"""
        num = 1
        den = 1
        for j in indices:
            if j != i:
                num = (num * j) % self.order
                den = (den * (j - i)) % self.order
        return (num * pow(den, -1, self.order)) % self.order

    def aggregate_partial(self, partial_sigs, indices):
        """Lagrange插值聚合部分签名"""
        # 对每个部分签名乘以Lagrange系数后累加
        result = None
        for i, idx in enumerate(indices):
            coeff = self._lagrange_coeff(indices, idx)
            # 标量乘: sig^coeff
            weighted = partial_sigs[i] * coeff  # blspy G2Element supports scalar mul
            if result is None:
                result = weighted
            else:
                result = result + weighted  # G2 point addition
        return result

    def sign_and_time(self, msg, signer_ids=None):
        """完整签发流程并计时"""
        if signer_ids is None:
            signer_ids = list(self.sk_shares.keys())[:self.t]

        timings = {}

        # 部分签名
        t0 = time.perf_counter()
        partial_sigs = []
        for mid in signer_ids:
            partial_sigs.append(self.sign_partial(mid, msg))
        timings['partial_sign_ms'] = (time.perf_counter() - t0) * 1000

        # 聚合
        t0 = time.perf_counter()
        agg_sig = self.aggregate_partial(partial_sigs, signer_ids)
        timings['aggregate_ms'] = (time.perf_counter() - t0) * 1000

        # 验证
        t0 = time.perf_counter()
        valid = AugSchemeMPL.verify(self.master_pk, msg, agg_sig)
        timings['verify_ms'] = (time.perf_counter() - t0) * 1000

        timings['total_ms'] = sum(timings.values())
        timings['valid'] = valid

        return agg_sig, timings

    def verify_timed(self, msg, sig, pk=None):
        """单次验证并计时"""
        if pk is None:
            pk = self.master_pk
        t0 = time.perf_counter()
        valid = AugSchemeMPL.verify(pk, msg, sig)
        latency = (time.perf_counter() - t0) * 1000
        return valid, latency
