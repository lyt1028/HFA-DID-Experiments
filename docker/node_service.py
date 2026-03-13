"""
HFA-DID 节点服务 —— 每个 Docker 容器运行一个实例
提供 REST API 供跨容器验证调用, 网络延迟由 tc netem 真实注入

角色:
  rtl  - 基础信任层: 提供全域快照背书签名验证
  gcl  - 全域协调层: 提供全域快照、域级根索引、状态位图
  dcl  - 业务凭证层: 提供域内 Merkle 证明、凭证数据
"""

import argparse
import hashlib
import json
import os
import sys
import time

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.merkle import MerkleTree, build_credential_leaf

app = Flask(__name__)

# ---- 全局状态 (启动时初始化) ----
STATE = {
    'role': None,
    'domain_id': None,
    'epoch': 1,
    'merkle_tree': None,
    'domain_roots': {},       # gcl 维护: {domain_id: root_hex}
    'global_tree': None,      # gcl 维护
    'global_root': None,      # gcl 维护
    'snapshot_sig': None,     # rtl 维护
    'status_bitmaps': {},     # gcl 维护: {domain_id: bitmap_hex}
    'credentials_per_domain': 1000,
}


def _init_dcl(domain_id, n_creds=1000):
    """初始化业务凭证层: 构建域内 Merkle 树"""
    items = [
        build_credential_leaf(domain_id, STATE['epoch'],
                              f"did:example:{domain_id}_{i}", "Active",
                              hashlib.sha256(f"commit_{domain_id}_{i}".encode()).digest())
        for i in range(n_creds)
    ]
    tree = MerkleTree()
    tree.build(items, sort=False)
    STATE['merkle_tree'] = tree
    STATE['domain_id'] = domain_id
    STATE['credentials_per_domain'] = n_creds
    print(f"[DCL:{domain_id}] 初始化完成, {n_creds} 凭证, root={tree.root[:16].hex()}...")


def _init_gcl(domain_ids, n_creds=1000):
    """初始化全域协调层: 收集各域根, 构建全域 Merkle 树"""
    domain_roots = []
    for did in domain_ids:
        items = [
            build_credential_leaf(did, STATE['epoch'],
                                  f"did:example:{did}_{i}", "Active",
                                  hashlib.sha256(f"commit_{did}_{i}".encode()).digest())
            for i in range(n_creds)
        ]
        tree = MerkleTree()
        tree.build(items, sort=False)
        STATE['domain_roots'][did] = tree.root.hex()
        domain_roots.append(tree.root)
        # 构造状态位图 (全0 = 无撤销)
        bitmap = b'\x00' * (n_creds // 8 + 1)
        STATE['status_bitmaps'][did] = bitmap.hex()

    global_tree = MerkleTree()
    global_root = global_tree.build(domain_roots, sort=False)
    STATE['global_tree'] = global_tree
    STATE['global_root'] = global_root.hex()
    print(f"[GCL] 初始化完成, {len(domain_ids)} 域, global_root={global_root[:16].hex()}...")


def _init_rtl():
    """初始化基础信任层: 生成快照背书签名 (模拟)"""
    sig = hashlib.sha256(b"rtl_endorsement_signature").digest()
    STATE['snapshot_sig'] = sig.hex()
    print(f"[RTL] 初始化完成, 背书签名就绪")


# ============================================================
# DCL API: 域内凭证服务
# ============================================================

@app.route('/dcl/merkle_proof/<int:cred_idx>')
def dcl_merkle_proof(cred_idx):
    """返回指定凭证的 Merkle 包含性证明"""
    tree = STATE['merkle_tree']
    if tree is None or cred_idx >= len(tree.leaves):
        return jsonify({'error': 'invalid index'}), 400
    proof = tree.get_proof(cred_idx)
    return jsonify({
        'leaf': tree.leaves[cred_idx].hex(),
        'proof': [p.hex() for p in proof],
        'root': tree.root.hex(),
        'domain_id': STATE['domain_id'],
        'epoch': STATE['epoch'],
    })


@app.route('/dcl/info')
def dcl_info():
    tree = STATE['merkle_tree']
    return jsonify({
        'domain_id': STATE['domain_id'],
        'root': tree.root.hex() if tree else None,
        'n_credentials': len(tree.leaves) if tree else 0,
        'epoch': STATE['epoch'],
    })


# ============================================================
# GCL API: 全域协调服务
# ============================================================

@app.route('/gcl/snapshot')
def gcl_snapshot():
    """返回全域快照 (全域根 + 各域根列表)"""
    return jsonify({
        'epoch': STATE['epoch'],
        'global_root': STATE['global_root'],
        'domain_roots': STATE['domain_roots'],
        'domain_count': len(STATE['domain_roots']),
    })


@app.route('/gcl/domain_proof/<domain_id>')
def gcl_domain_proof(domain_id):
    """返回指定域根在全域 Merkle 树中的包含性证明"""
    global_tree = STATE['global_tree']
    if global_tree is None:
        return jsonify({'error': 'gcl not initialized'}), 500
    domain_ids = list(STATE['domain_roots'].keys())
    if domain_id not in domain_ids:
        return jsonify({'error': f'domain {domain_id} not found'}), 404
    idx = domain_ids.index(domain_id)
    proof = global_tree.get_proof(idx)
    return jsonify({
        'domain_id': domain_id,
        'domain_root': STATE['domain_roots'][domain_id],
        'proof': [p.hex() for p in proof],
        'global_root': STATE['global_root'],
        'epoch': STATE['epoch'],
    })


@app.route('/gcl/bitmap/<domain_id>')
def gcl_bitmap(domain_id):
    """返回指定域的凭证状态位图"""
    if domain_id not in STATE['status_bitmaps']:
        return jsonify({'error': 'domain not found'}), 404
    return jsonify({
        'domain_id': domain_id,
        'bitmap_hex': STATE['status_bitmaps'][domain_id],
        'epoch': STATE['epoch'],
    })


# ============================================================
# RTL API: 信任根服务
# ============================================================

@app.route('/rtl/endorse')
def rtl_endorse():
    """返回当前全域快照的 RTL 背书签名"""
    return jsonify({
        'epoch': STATE['epoch'],
        'signature': STATE['snapshot_sig'],
    })


@app.route('/rtl/verify_endorse', methods=['POST'])
def rtl_verify_endorse():
    """验证 RTL 背书签名 (模拟配对运算延迟)"""
    t0 = time.perf_counter()
    # 模拟 BLS 配对验证: 两次大整数幂运算
    _ = pow(2, (1 << 20), (1 << 127) - 1)
    _ = pow(3, (1 << 20), (1 << 127) - 1)
    elapsed = (time.perf_counter() - t0) * 1000
    return jsonify({
        'valid': True,
        'verify_ms': round(elapsed, 3),
    })


# ============================================================
# 通用
# ============================================================

@app.route('/ping')
def ping():
    return jsonify({'role': STATE['role'], 'ts': time.time()})


# ============================================================
# 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', required=True, choices=['rtl', 'gcl', 'dcl'])
    parser.add_argument('--domain', default='DCL_A', help='DCL 域标识')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--n-creds', type=int, default=1000)
    args = parser.parse_args()

    STATE['role'] = args.role
    domain_ids = ['DCL_A', 'DCL_B', 'DCL_C']

    if args.role == 'dcl':
        _init_dcl(args.domain, args.n_creds)
    elif args.role == 'gcl':
        _init_gcl(domain_ids, args.n_creds)
    elif args.role == 'rtl':
        _init_rtl()

    app.run(host='0.0.0.0', port=args.port, threaded=True)


if __name__ == '__main__':
    main()
