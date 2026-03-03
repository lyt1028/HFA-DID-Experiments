"""
HFA-DID 实验入口
=============================

使用方法:
  python run_experiments.py           # 快速验证 (链下)
  python run_experiments.py quick     # 快速验证 (小参数, 链下)
  python run_experiments.py exp1      # 实验1: 域内验证性能 (含链上)
  python run_experiments.py exp2      # 实验2: 跨域验证性能 (含链上)
  python run_experiments.py exp3      # 实验3: 锚定与快照开销 (含链上)
  python run_experiments.py exp4      # 实验4: 服务可用性与恢复 (含链上)
  python run_experiments.py exp5      # 实验5: 更新/撤销开销 (含链上)
  python run_experiments.py exp6      # 实验6: 更新后验证正确性 (含链上)
  python run_experiments.py exp7      # 实验7: 陷门继承安全性 (含链上)
  python run_experiments.py all       # 运行全部实验 (含链上)
  python run_experiments.py p0        # 仅运行 P0 实验 (5, 6)
  python run_experiments.py p1        # 仅运行 P1 实验 (2, 3, 7)
  python run_experiments.py --no-chain exp3  # 仅链下模式运行
"""

import sys
import os
import time

# 确保项目根目录在 Python 路径中
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                 HFA-DID 实验系统                         ║
║   面向跨域的分布式数字身份关键技术研究                      ║
║   Hierarchical Federated Architecture for DID            ║
╚══════════════════════════════════════════════════════════╝
    """)


def check_dependencies():
    """检查关键依赖是否已安装"""
    print("[环境检查]")
    deps = {
        'py_ecc': 'BLS12-381 曲线运算',
        'Crypto': 'pycryptodome 密码学原语',
        'numpy': '数值计算',
        'matplotlib': '图表绘制',
    }
    all_ok = True
    for mod, desc in deps.items():
        try:
            __import__(mod)
            print(f"  [OK] {mod:20s} - {desc}")
        except ImportError:
            print(f"  [缺失] {mod:20s} - {desc}")
            all_ok = False

    if not all_ok:
        print("\n  请先安装依赖: pip install -r requirements.txt")
        return False

    print("  所有依赖已就绪\n")
    return True


def run_quick_test():
    """快速验证: 用小参数跑通全部流程"""
    from src.utils import print_header
    print_header("快速验证模式 (小参数)")

    # 1. 测试 Shamir 秘密共享
    print("\n[1] Shamir 秘密共享...")
    from src.crypto.shamir import ShamirSecretSharing
    p = 2**127 - 1  # 梅森素数
    sss = ShamirSecretSharing(p)
    secret = 123456789
    shares = sss.split(secret, 3, 5)
    recovered = sss.reconstruct(dict(list(shares.items())[:3]), 3)
    assert recovered == secret, "秘密共享重构失败!"
    print("  Shamir (3,5) 秘密共享: OK")

    # 2. 测试 Merkle 树
    print("\n[2] Merkle 树...")
    from src.crypto.merkle import MerkleTree
    tree = MerkleTree()
    items = [f"credential_{i}".encode() for i in range(16)]
    root = tree.build(items)
    proof = tree.get_proof(5)
    leaf_hash = tree.hash_func(items[5])
    # 注意: 因为排序, 叶子顺序可能变化, 这里用未排序模式验证
    tree2 = MerkleTree()
    root2 = tree2.build(items, sort=False)
    proof2 = tree2.get_proof(5)
    leaf_hash2 = tree2.hash_func(items[5])
    assert MerkleTree.verify_proof(leaf_hash2, proof2, root2), "Merkle 验证失败!"
    print(f"  Merkle 树 (16 叶子, 深度 {tree2.depth}): OK")

    # 3. 测试变色龙哈希
    print("\n[3] 变色龙哈希...")
    from src.crypto.chameleon_hash import ChameleonHash
    ch = ChameleonHash(bits=64)  # 小参数快速测试
    pk, td = ch.keygen()
    m1 = 42
    r1 = ch.random_r()
    commit = ch.hash(m1, r1)
    m2 = 99
    r2 = ch.forge(m1, r1, m2)
    assert ch.hash(m2, r2) == commit, "变色龙哈希碰撞失败!"
    print(f"  变色龙哈希碰撞: CH({m1},{r1}) == CH({m2},{r2}) = OK")

    # 4. 测试 Re-DKG
    print("\n[4] Re-DKG 轮转...")
    from src.crypto.redkg import ReDKG
    q = 2**127 - 1
    redkg = ReDKG(q, threshold=3)
    initial_secret = 987654321
    old_ids = [1, 2, 3, 4, 5]
    old_shares = sss.split(initial_secret, 3, 5, old_ids)
    new_ids = [3, 4, 5, 6, 7]  # 1,2 退出; 6,7 加入
    new_shares, timings = redkg.rotate(old_ids, new_ids, old_shares)
    recovered_new = sss.reconstruct(new_shares, 3)
    assert recovered_new == initial_secret, "Re-DKG 秘密恢复失败!"
    print(f"  Re-DKG 轮转: 秘密不变 = OK, 耗时 = {timings['total_ms']:.2f} ms")

    # 5. 测试 BLS 门限签名
    print("\n[5] BLS 门限签名 (首次运行较慢, py_ecc 纯 Python 实现)...")
    from src.crypto.bls_threshold import BLSThresholdSignature
    bls_ts = BLSThresholdSignature(threshold=2, num_members=3)
    bls_ts.keygen([1, 2, 3])
    msg = b"test credential content"
    sig, sig_timings = bls_ts.sign_and_time(msg, [1, 2])
    valid, verify_time = bls_ts.verify_and_time(msg, sig)
    assert valid, "BLS 签名验证失败!"
    print(f"  BLS (2,3) 门限签名: OK")
    print(f"    部分签名: {sig_timings['partial_sign_ms']:.1f} ms")
    print(f"    聚合:     {sig_timings['aggregate_ms']:.1f} ms")
    print(f"    验证:     {verify_time:.1f} ms")

    print("\n" + "=" * 50)
    print("  全部基础组件验证通过!")
    print("=" * 50)


def run_exp1(use_chain=True):
    from experiments.exp1_intra_domain import run_all
    return run_all(use_chain=use_chain)


def run_exp2(use_chain=True):
    from experiments.exp2_cross_domain import run_all
    return run_all(use_chain=use_chain)


def run_exp3(use_chain=True):
    from experiments.exp3_anchoring import run_all
    return run_all(use_chain=use_chain)


def run_exp4(use_chain=True):
    from experiments.exp4_availability import run_all
    return run_all(use_chain=use_chain)


def run_exp5(use_chain=True):
    from experiments.exp5_update_revoke import run_all
    return run_all(use_chain=use_chain)


def run_exp6(use_chain=True):
    from experiments.exp6_correctness import run_all
    return run_all(use_chain=use_chain)


def run_exp7(use_chain=True):
    from experiments.exp7_redkg import run_all
    return run_all(use_chain=use_chain)


EXPERIMENT_MAP = {
    'exp1': ('实验1: 域内验证性能', run_exp1),
    'exp2': ('实验2: 跨域验证性能', run_exp2),
    'exp3': ('实验3: 锚定与快照开销', run_exp3),
    'exp4': ('实验4: 服务可用性与恢复', run_exp4),
    'exp5': ('实验5: 更新/撤销开销', run_exp5),
    'exp6': ('实验6: 更新后验证正确性', run_exp6),
    'exp7': ('实验7: 陷门继承安全性', run_exp7),
}

GROUPS = {
    'p0': ['exp5', 'exp6'],
    'p1': ['exp2', 'exp3', 'exp7'],
    'p2': ['exp1', 'exp4'],
    'all': ['exp1', 'exp2', 'exp3', 'exp4', 'exp5', 'exp6', 'exp7'],
}


def main():
    print_banner()

    if not check_dependencies():
        sys.exit(1)

    # 解析命令行参数
    args = sys.argv[1:] if len(sys.argv) > 1 else ['quick']

    # 检查 --no-chain 标志
    use_chain = True
    if '--no-chain' in args:
        use_chain = False
        args = [a for a in args if a != '--no-chain']
        print("[模式] 纯链下运行 (--no-chain)\n")
    else:
        print("[模式] 含链上操作 (FISCO BCOS)\n")

    start = time.time()

    for arg in args:
        if arg == 'quick':
            run_quick_test()
        elif arg in EXPERIMENT_MAP:
            name, fn = EXPERIMENT_MAP[arg]
            print(f"\n>>> 运行 {name}")
            fn(use_chain=use_chain)
        elif arg in GROUPS:
            for exp_key in GROUPS[arg]:
                name, fn = EXPERIMENT_MAP[exp_key]
                print(f"\n>>> 运行 {name}")
                fn(use_chain=use_chain)
        else:
            print(f"未知参数: {arg}")
            print("可用: quick, exp1-exp7, p0, p1, p2, all, --no-chain")
            sys.exit(1)

    elapsed = time.time() - start
    print(f"\n总耗时: {elapsed:.1f} 秒")


if __name__ == '__main__':
    main()
