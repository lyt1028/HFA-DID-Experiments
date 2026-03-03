#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HFA-DID FISCO BCOS 链交互封装层
封装所有与区块链的交互操作，为实验提供统一接口
"""

import sys
import os
import json
import time
import hashlib

# python-sdk 路径
PYTHON_SDK_PATH = "/root/python-sdk"

# 延迟导入：SDK 在 import 时依赖相对路径，需要先切换工作目录
BcosClient = None
DatatypeParser = None


def _ensure_sdk_imported():
    """延迟导入 FISCO BCOS SDK（需要在 python-sdk 目录下才能正确初始化）"""
    global BcosClient, DatatypeParser
    if BcosClient is not None:
        return

    old_cwd = os.getcwd()
    os.chdir(PYTHON_SDK_PATH)
    try:
        if PYTHON_SDK_PATH not in sys.path:
            sys.path.insert(0, PYTHON_SDK_PATH)
        # FISCO SDK 自带 eth_utils (含 set_crypto_type), 需要确保优先于系统包
        # 若系统 eth_utils 已被缓存, 需要移除后重新导入
        if 'eth_utils' in sys.modules:
            # 检查是否是系统版本（不含 set_crypto_type）
            cached = sys.modules['eth_utils']
            if not hasattr(cached, '__file__') or PYTHON_SDK_PATH not in (cached.__file__ or ''):
                # 移除系统版本及其子模块缓存
                to_remove = [k for k in sys.modules if k == 'eth_utils' or k.startswith('eth_utils.')]
                for k in to_remove:
                    del sys.modules[k]
        from client.bcosclient import BcosClient as _BC
        from client.datatype_parser import DatatypeParser as _DP
        BcosClient = _BC
        DatatypeParser = _DP
    finally:
        os.chdir(old_cwd)


class FISCOClient:
    """FISCO BCOS 链交互客户端"""

    def __init__(self, config_path=None):
        self.client = None
        self.credential_registry_addr = None
        self.committee_governance_addr = None
        self.credential_registry_abi = None
        self.committee_governance_abi = None
        self._initialized = False

        # 加载合约地址
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "contract_addresses.json"
            )

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                addresses = json.load(f)
            self.credential_registry_addr = addresses.get("CredentialRegistry")
            self.committee_governance_addr = addresses.get("CommitteeGovernance")

    def init(self):
        """建立连接"""
        if self._initialized:
            return

        _ensure_sdk_imported()

        old_cwd = os.getcwd()
        os.chdir(PYTHON_SDK_PATH)

        try:
            self.client = BcosClient()
            self.client.init()

            # 加载 ABI
            abi_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "contracts"
            )

            parser1 = DatatypeParser()
            parser1.load_abi_file(os.path.join(abi_dir, "CredentialRegistry.abi"))
            self.credential_registry_abi = parser1.contract_abi

            parser2 = DatatypeParser()
            parser2.load_abi_file(os.path.join(abi_dir, "CommitteeGovernance.abi"))
            self.committee_governance_abi = parser2.contract_abi

            self._initialized = True
        finally:
            os.chdir(old_cwd)

    def close(self):
        """关闭连接"""
        if self.client:
            old_cwd = os.getcwd()
            os.chdir(PYTHON_SDK_PATH)
            try:
                self.client.finish()
            finally:
                os.chdir(old_cwd)
            self._initialized = False

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, *args):
        self.close()

    # ==================== 辅助方法 ====================

    def _to_bytes32(self, data):
        """将数据转换为 bytes32 格式"""
        if isinstance(data, str):
            if data.startswith("0x"):
                return bytes.fromhex(data[2:]).ljust(32, b"\x00")
            return hashlib.sha256(data.encode()).digest()
        elif isinstance(data, int):
            return data.to_bytes(32, "big")
        elif isinstance(data, bytes):
            return data[:32].ljust(32, b"\x00")
        return data

    def _send_tx(self, address, abi, fn_name, args):
        """发送交易并计时，返回 (receipt, latency_ms)"""
        old_cwd = os.getcwd()
        os.chdir(PYTHON_SDK_PATH)
        try:
            start = time.perf_counter()
            receipt = self.client.sendRawTransactionGetReceipt(
                address, abi, fn_name, args
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            return receipt, elapsed_ms
        finally:
            os.chdir(old_cwd)

    def _call(self, address, abi, fn_name, args=None):
        """调用只读方法并计时，返回 (result, latency_ms)"""
        old_cwd = os.getcwd()
        os.chdir(PYTHON_SDK_PATH)
        try:
            start = time.perf_counter()
            result = self.client.call(address, abi, fn_name, args)
            elapsed_ms = (time.perf_counter() - start) * 1000
            return result, elapsed_ms
        finally:
            os.chdir(old_cwd)

    # ==================== 域级锚定操作 ====================

    def anchor_domain_root(self, domain_id: str, epoch: int, root: bytes,
                           signature: bytes, cred_count: int):
        """锚定域级 Merkle 根到链上

        Returns:
            (receipt, latency_ms)
        """
        root_hex = self._to_bytes32(root)
        return self._send_tx(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "anchorDomainRoot",
            [domain_id, epoch, root_hex, signature, cred_count]
        )

    def get_domain_root(self, domain_id: str, epoch: int):
        """查询链上域级 Merkle 根

        Returns:
            ((root, timestamp, cred_count, exists), latency_ms)
        """
        return self._call(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "getDomainRoot",
            [domain_id, epoch]
        )

    # ==================== 全局快照操作 ====================

    def anchor_global_snapshot(self, epoch: int, global_root: bytes,
                               rtl_signature: bytes, domain_count: int):
        """锚定全局快照

        Returns:
            (receipt, latency_ms)
        """
        root_hex = self._to_bytes32(global_root)
        return self._send_tx(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "anchorGlobalSnapshot",
            [epoch, root_hex, rtl_signature, domain_count]
        )

    def get_global_snapshot(self, epoch: int):
        """查询全局快照

        Returns:
            ((global_root, domain_count, timestamp, exists), latency_ms)
        """
        return self._call(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "getGlobalSnapshot",
            [epoch]
        )

    # ==================== 凭证管理操作 ====================

    def register_credential(self, cred_id: bytes, commitment: bytes,
                            domain_id: str, epoch: int):
        """注册新凭证

        Returns:
            (receipt, latency_ms)
        """
        cid = self._to_bytes32(cred_id)
        com = self._to_bytes32(commitment)
        return self._send_tx(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "registerCredential",
            [cid, com, domain_id, epoch]
        )

    def record_update(self, cred_id: bytes, new_randomness: bytes,
                      signature: bytes, epoch: int):
        """记录凭证更新（变色龙哈希碰撞）

        Returns:
            (receipt, latency_ms)
        """
        cid = self._to_bytes32(cred_id)
        nr = self._to_bytes32(new_randomness)
        return self._send_tx(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "recordUpdate",
            [cid, nr, signature, epoch]
        )

    def record_revocation(self, cred_id: bytes, signature: bytes, epoch: int):
        """记录凭证撤销

        Returns:
            (receipt, latency_ms)
        """
        cid = self._to_bytes32(cred_id)
        return self._send_tx(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "recordRevocation",
            [cid, signature, epoch]
        )

    def get_credential(self, cred_id: bytes):
        """查询凭证信息

        Returns:
            ((commitment, domain_id, create_epoch, update_count, revoked, exists), latency_ms)
        """
        cid = self._to_bytes32(cred_id)
        return self._call(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "getCredential",
            [cid]
        )

    def get_update_log_count(self, cred_id: bytes):
        """查询凭证更新日志数量"""
        cid = self._to_bytes32(cred_id)
        return self._call(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "getUpdateLogCount",
            [cid]
        )

    def get_stats(self):
        """查询链上统计信息

        Returns:
            ((total_creds, total_updates, total_anchors, latest_global_epoch), latency_ms)
        """
        return self._call(
            self.credential_registry_addr,
            self.credential_registry_abi,
            "getStats"
        )

    # ==================== 委员会治理操作 ====================

    def publish_roster(self, domain_id: str, epoch: int,
                       members: list, threshold: int):
        """发布委员会名单

        Returns:
            (receipt, latency_ms)
        """
        return self._send_tx(
            self.committee_governance_addr,
            self.committee_governance_abi,
            "publishRoster",
            [domain_id, epoch, members, threshold]
        )

    def get_roster(self, domain_id: str, epoch: int):
        """查询委员会名单

        Returns:
            ((members, threshold, timestamp, exists), latency_ms)
        """
        return self._call(
            self.committee_governance_addr,
            self.committee_governance_abi,
            "getRoster",
            [domain_id, epoch]
        )

    def record_rotation(self, domain_id: str, from_epoch: int, to_epoch: int,
                        stay_count: int, join_count: int, exit_count: int,
                        rotation_time: int):
        """记录 Re-DKG 轮换完成

        Returns:
            (receipt, latency_ms)
        """
        return self._send_tx(
            self.committee_governance_addr,
            self.committee_governance_abi,
            "recordRotation",
            [domain_id, from_epoch, to_epoch,
             stay_count, join_count, exit_count, rotation_time]
        )


# ==================== 快速测试 ====================
if __name__ == "__main__":
    print("=== FISCOClient 集成测试 ===\n")

    with FISCOClient() as fc:
        # 1. 初始状态
        stats, t = fc.get_stats()
        print(f"1. 链上统计: creds={stats[0]}, updates={stats[1]}, "
              f"anchors={stats[2]}, epoch={stats[3]}  ({t:.1f}ms)")

        # 2. 锚定域根
        test_root = hashlib.sha256(b"test_domain_root").digest()
        test_sig = b"\x00" * 48
        receipt, t = fc.anchor_domain_root("domain_A", 1, test_root, test_sig, 100)
        print(f"2. 锚定域根: block={receipt['blockNumber']}  ({t:.1f}ms)")

        # 3. 查询域根
        result, t = fc.get_domain_root("domain_A", 1)
        print(f"3. 查询域根: exists={result[3]}  ({t:.1f}ms)")

        # 4. 注册凭证
        cred_id = hashlib.sha256(b"cred_001").digest()
        commitment = hashlib.sha256(b"CH(m,r)").digest()
        receipt, t = fc.register_credential(cred_id, commitment, "domain_A", 1)
        print(f"4. 注册凭证: block={receipt['blockNumber']}  ({t:.1f}ms)")

        # 5. 更新凭证
        new_r = hashlib.sha256(b"new_randomness").digest()
        receipt, t = fc.record_update(cred_id, new_r, b"\x00" * 48, 1)
        print(f"5. 更新凭证: block={receipt['blockNumber']}  ({t:.1f}ms)")

        # 6. 查询凭证
        result, t = fc.get_credential(cred_id)
        print(f"6. 查询凭证: updateCount={result[3]}, revoked={result[4]}  ({t:.1f}ms)")

        # 7. 发布委员会名单
        members = ["node_1", "node_2", "node_3", "node_4", "node_5"]
        receipt, t = fc.publish_roster("domain_A", 1, members, 3)
        print(f"7. 发布名单: block={receipt['blockNumber']}  ({t:.1f}ms)")

        # 8. 最终统计
        stats, t = fc.get_stats()
        print(f"\n8. 最终统计: creds={stats[0]}, updates={stats[1]}, "
              f"anchors={stats[2]}, epoch={stats[3]}  ({t:.1f}ms)")

    print("\n=== 全部测试通过! ===")
