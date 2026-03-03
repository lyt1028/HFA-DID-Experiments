"""
Merkle 树实现
用于域内凭证状态锚定与跨域全域快照

对应论文:
  - 公式 (3.4): 叶子摘要 L_i = H(DomainID || e || DID_u || delta || H(Commit))
  - 公式 (3.5): 域级状态根 Root_VC_j = H(MerkleTree(Order({L_i})))
  - 公式 (3.8): 全域状态根 Root_Global
  - 算法 3.1:  域级 Merkle 建树
"""

import hashlib
from typing import List, Tuple, Optional


class MerkleTree:
    """排序 Merkle 树 (与论文一致的确定性排序构建)"""

    def __init__(self, hash_func=None):
        """
        Args:
            hash_func: 哈希函数, 默认 SHA-256
        """
        self.hash_func = hash_func or self._sha256
        self.root: bytes = b''
        self.leaves: List[bytes] = []
        self.layers: List[List[bytes]] = []

    @staticmethod
    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        return self.hash_func(left + right)

    def build(self, data_items: List[bytes], sort: bool = True) -> bytes:
        """
        构建 Merkle 树

        Args:
            data_items: 叶子节点数据列表 (已经过哈希或原始数据)
            sort:       是否对叶子排序 (论文要求确定性排序)

        Returns:
            Merkle 根哈希
        """
        if not data_items:
            self.root = self.hash_func(b'')
            self.leaves = []
            self.layers = [[self.root]]
            return self.root

        # 计算叶子哈希
        self.leaves = [self.hash_func(item) if len(item) != 32 else item
                       for item in data_items]

        # 确定性排序 (论文 Order 函数)
        if sort:
            self.leaves = sorted(self.leaves)

        # 自底向上构建
        current = self.leaves[:]
        self.layers = [current[:]]

        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])  # 奇数补齐
            next_layer = []
            for i in range(0, len(current), 2):
                parent = self._hash_pair(current[i], current[i + 1])
                next_layer.append(parent)
            self.layers.append(next_layer)
            current = next_layer

        self.root = current[0]
        return self.root

    def get_proof(self, leaf_index: int) -> List[Tuple[bytes, str]]:
        """
        获取指定叶子的 Merkle 包含性证明路径

        Args:
            leaf_index: 叶子在排序后列表中的索引

        Returns:
            [(sibling_hash, direction), ...] 从叶子到根的路径
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"叶子索引越界: {leaf_index}")

        proof = []
        idx = leaf_index
        for layer in self.layers[:-1]:
            # 补齐层
            padded = layer[:]
            if len(padded) % 2 == 1:
                padded.append(padded[-1])

            if idx % 2 == 0:
                sibling_idx = idx + 1
                direction = 'right'
            else:
                sibling_idx = idx - 1
                direction = 'left'

            if sibling_idx < len(padded):
                proof.append((padded[sibling_idx], direction))

            idx = idx // 2

        return proof

    @classmethod
    def verify_proof(cls, leaf_hash: bytes, proof: List[Tuple[bytes, str]],
                     expected_root: bytes, hash_func=None) -> bool:
        """
        验证 Merkle 包含性证明

        Args:
            leaf_hash:     叶子哈希
            proof:         证明路径
            expected_root: 期望的根哈希

        Returns:
            验证是否通过
        """
        hf = hash_func or cls._sha256
        current = leaf_hash
        for sibling, direction in proof:
            if direction == 'right':
                current = hf(current + sibling)
            else:
                current = hf(sibling + current)
        return current == expected_root

    @property
    def depth(self) -> int:
        return len(self.layers) - 1

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)


def build_credential_leaf(domain_id: str, epoch: int, did_u: str,
                          status: str, commit_hash: bytes) -> bytes:
    """
    构造凭证状态叶子 (对应论文公式 3.4)

    L_i = H(DomainID || e || DID_u || delta || H(Commit))
    """
    data = (
        domain_id.encode('utf-8') +
        epoch.to_bytes(4, 'big') +
        did_u.encode('utf-8') +
        status.encode('utf-8') +
        commit_hash
    )
    return hashlib.sha256(data).digest()
