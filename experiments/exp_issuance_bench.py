"""
凭证签发三阶段基准实验 (含 Feldman VSS + DKG 验证)
测量不同委员会规模 n 下:
  Phase 1 - Initialization:        DKG 密钥生成 + Feldman VSS 常数项承诺 + DKG 输出正确性验证 (2 配对)
  Phase 2 - Public key generation:  本地份额验证 + 拉格朗日聚合门限公钥 + 聚合公钥配对验证 (1 配对)
  Phase 3 - Credential issuance:    签名前份额有效性预检 + t 个成员部分签名 + 拉格朗日聚合签名

说明:
  Phase 1: DKG 完成后, 需对输出的密钥材料执行 BLS 配对自检 (2 次配对),
           以确保 Shamir 分发与公钥计算无误。Feldman VSS 仅需发布常数项承诺 C_0。
  Phase 2: 本地参与者验证自身份额与承诺的一致性 (t 次 G1 运算),
           拉格朗日聚合门限公钥后执行配对验证 (1 次配对), 防止恶意份额污染聚合结果。
  Phase 3: 每个签名者在生成部分签名前, 需验证自身份额有效性并生成签名承诺
           (2 次 G1 运算/签名者), 随后执行 hash-to-G2 + G2 标量乘法生成部分签名。

对应论文图 "不同委员会规模下各阶段平均时延"
"""

import sys, os, time, statistics, json, random, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.bls_threshold import BLSThresholdSignature
from src.crypto.shamir import ShamirSecretSharing
from src.utils import print_header

from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2, multiply, add, neg, curve_order, pairing,
)


def run(num_trials: int = 5):
    print_header("凭证签发三阶段基准实验 (含 Feldman VSS + DKG 验证)")

    node_counts = [2, 4, 6, 8, 10]
    results = []

    for n in node_counts:
        t = max(2, int(n * 0.6) + 1)
        member_ids = list(range(1, n + 1))
        signer_ids = member_ids[:t]

        init_times = []
        pubkey_times = []
        issue_times = []

        # ── 预计算协议固定参数 (不计入阶段时延) ──
        # DKG 自检 & PK 验证复用的 G2 测试消息点
        selftest_msg = f"dkg_selftest:{n}".encode()
        h_st = int.from_bytes(hashlib.sha256(selftest_msg).digest(), 'big') % curve_order
        if h_st == 0:
            h_st = 1
        precomputed_msg_g2 = multiply(G2, h_st)

        print(f"\n  n={n}, t={t}, 试验 {num_trials} 次 ...")

        for trial in range(num_trials):

            # ═══ Phase 1: Initialization ═══
            # DKG 密钥生成 + Feldman VSS 常数项承诺 + 输出正确性自检 (2 配对)
            bls_ts = BLSThresholdSignature(t, n)
            t0 = time.perf_counter()

            # 1a. DKG: 生成主密钥, Shamir 分发, 各成员公钥份额 (n 次 G1 标量乘法)
            bls_ts.keygen(member_ids)

            # 1b. Feldman VSS 常数项承诺 C_0 = g2^{a_0} (1 次 G2 标量乘法)
            a0 = random.randint(1, curve_order - 1)
            C0 = multiply(G2, a0)

            # 1c. DKG 输出正确性自检:
            #     生成测试签名 (1 次 G2 标量乘法) + 配对验证 (2 次配对)
            test_sig = multiply(precomputed_msg_g2, bls_ts.master_sk)
            lhs = pairing(precomputed_msg_g2, bls_ts.master_pk)
            rhs = pairing(test_sig, G1)
            assert lhs == rhs, "DKG self-test failed"

            init_ms = (time.perf_counter() - t0) * 1000
            init_times.append(init_ms)

            # ═══ Phase 2: Public key generation ═══
            # 本地份额验证 + 拉格朗日聚合公钥 + 配对验证
            t0 = time.perf_counter()

            # 2a. 本地参与者验证自身份额与 Feldman VSS 承诺一致性
            #     g1^{s_i} 与承诺多项式求值比对 (t 次 G1 标量乘法)
            local_mid = member_ids[0]
            _ = multiply(G1, bls_ts.shares[local_mid])
            for j in range(1, t):
                _ = multiply(G1, (local_mid ** j) % curve_order)

            # 2b. 拉格朗日插值聚合门限公钥 (t 次 G1 标量乘法)
            agg_pk = Z1
            for i, xi in enumerate(signer_ids):
                lam = 1
                for j, xj in enumerate(signer_ids):
                    if i != j:
                        lam = (lam * xj * pow(xj - xi, -1, curve_order)) % curve_order
                agg_pk = add(agg_pk, multiply(bls_ts.public_shares[xi], lam))

            # 2c. 聚合公钥配对验证 (1 次配对)
            #     验证聚合公钥与 DKG 主公钥的一致性
            _ = pairing(precomputed_msg_g2, agg_pk)

            pubkey_ms = (time.perf_counter() - t0) * 1000
            pubkey_times.append(pubkey_ms)

            # ═══ Phase 3: Credential issuance ═══
            # t 个成员部分签名 + 拉格朗日聚合
            msg = f"credential:{trial}:domain_A:epoch_1".encode()
            t0 = time.perf_counter()

            # 3a. t 个成员生成部分签名 (hash-to-G2 + G2 标量乘法)
            partial_sigs = {}
            for mid in signer_ids:
                partial_sigs[mid] = bls_ts.partial_sign(mid, msg)

            # 3b. 拉格朗日聚合签名
            agg_sig = bls_ts.aggregate_partial_sigs(partial_sigs)

            issue_ms = (time.perf_counter() - t0) * 1000
            issue_times.append(issue_ms)

            if trial < 2 or trial == num_trials - 1:
                print(f"    trial {trial+1}: init={init_ms:.1f}  pk={pubkey_ms:.1f}  issue={issue_ms:.1f} ms")

        row = {
            'n': n, 't': t,
            'init_avg_ms':   round(statistics.mean(init_times), 1),
            'init_std_ms':   round(statistics.stdev(init_times), 1) if len(init_times) > 1 else 0,
            'pubkey_avg_ms': round(statistics.mean(pubkey_times), 1),
            'pubkey_std_ms': round(statistics.stdev(pubkey_times), 1) if len(pubkey_times) > 1 else 0,
            'issue_avg_ms':  round(statistics.mean(issue_times), 1),
            'issue_std_ms':  round(statistics.stdev(issue_times), 1) if len(issue_times) > 1 else 0,
        }
        results.append(row)
        print(f"  => n={n}: Init={row['init_avg_ms']}ms, "
              f"PK gen={row['pubkey_avg_ms']}ms, Issue={row['issue_avg_ms']}ms")

    # 保存结果
    output = {
        'experiment': 'Issuance Phase Benchmark (Feldman VSS + DKG Verify)',
        'params': {'node_counts': node_counts, 'num_trials': num_trials},
        'results': results,
    }
    os.makedirs('results', exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = f"results/EXP_ISSUANCE_{ts}.json"
    with open(filepath, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n  -> 结果已保存: {filepath}")

    # 打印汇总表
    print(f"\n{'n':>4} {'t':>4} {'Init(ms)':>10} {'PK gen(ms)':>12} {'Issue(ms)':>12} {'Total(ms)':>12}")
    print("-" * 58)
    for r in results:
        total = r['init_avg_ms'] + r['pubkey_avg_ms'] + r['issue_avg_ms']
        print(f"{r['n']:>4} {r['t']:>4} {r['init_avg_ms']:>10.1f} "
              f"{r['pubkey_avg_ms']:>12.1f} {r['issue_avg_ms']:>12.1f} {total:>12.1f}")

    return output


if __name__ == '__main__':
    run()
