"""
多场景对比实验 (真实BLS签名)
证明自适应门限在未知威胁环境下的不可替代性
"""
import sys, os, json, time, random, statistics, math

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.crypto.bls_threshold import BLSThresholdSignature
from src.models.reputation import ReputationModel, NodeBehavior
from src.models.adaptive_threshold import AdaptiveThreshold, FixedThreshold
from src.utils import print_header

N = 20
ISSUANCES_PER_EPOCH = 3
N_EPOCHS = 15


def make_threat_schedule(peak, n_epochs=15):
    mid = n_epochs // 2 + 1
    schedule = {}
    for e in range(1, n_epochs + 1):
        dist = abs(e - mid)
        ratio = max(0, 1.0 - dist / (mid - 1))
        schedule[e] = round(peak * ratio, 2)
    return schedule


def run_scenario(n, peak_threat, strategy_name, threshold_obj, bls_instances):
    schedule = make_threat_schedule(peak_threat, N_EPOCHS)
    random.seed(42)
    nodes = {i: {'reputation': 0.6 + random.uniform(0, 0.3), 'corrupted': False}
             for i in range(1, n + 1)}
    rep_model = ReputationModel()
    all_ids = list(range(1, n + 1))
    results = []

    for epoch in range(1, N_EPOCHS + 1):
        target = int(n * schedule[epoch])
        corrupted = [nid for nid, nd in nodes.items() if nd['corrupted']]
        honest = [nid for nid, nd in nodes.items() if not nd['corrupted']]
        if len(corrupted) < target:
            for nid in random.sample(honest, min(target - len(corrupted), len(honest))):
                nodes[nid]['corrupted'] = True
        elif len(corrupted) > target:
            for nid in random.sample(corrupted, len(corrupted) - target):
                nodes[nid]['corrupted'] = False

        behaviors = []
        for nid in sorted(nodes.keys()):
            b = NodeBehavior(node_id=nid)
            b.total_tasks = 50; b.requested = 50
            if nodes[nid]['corrupted']:
                b.response_time_ms = random.uniform(200, 500)
                b.participated = random.randint(10, 25)
                b.rejected = random.randint(15, 30)
                b.issued_count = random.randint(5, 15)
                b.revoked_count = random.randint(2, 8)
                b.anchor_submit_rate = random.uniform(0.3, 0.6)
                b.valid_sig_rate = random.uniform(0.4, 0.7)
                b.consistency_score = random.uniform(0.3, 0.6)
            else:
                b.response_time_ms = random.uniform(30, 80)
                b.participated = random.randint(40, 50)
                b.rejected = random.randint(0, 3)
                b.issued_count = random.randint(30, 50)
                b.revoked_count = random.randint(0, 2)
                b.anchor_submit_rate = random.uniform(0.85, 1.0)
                b.valid_sig_rate = random.uniform(0.9, 1.0)
                b.consistency_score = random.uniform(0.85, 1.0)
            behaviors.append(b)

        scores = rep_model.evaluate_all(behaviors)
        t_e, _ = threshold_obj.compute_threshold(scores)
        t_e = max(8, min(14, t_e))
        f_active = sum(1 for nd in nodes.values() if nd['corrupted'])
        margin = t_e - f_active

        bls = bls_instances[t_e]
        lats = []
        for i in range(ISSUANCES_PER_EPOCH):
            msg = f"vc_e{epoch}_i{i}_{strategy_name}_p{int(peak_threat*100)}".encode()
            signers = random.sample(all_ids, min(t_e, len(all_ids)))
            _, timings = bls.sign_and_time(msg, signers)
            lats.append(timings['total_ms'])

        results.append({
            'epoch': epoch, 't_e': t_e, 'f_active': f_active,
            'margin': margin, 'breached': margin <= 0,
            'avg_latency_ms': round(statistics.mean(lats), 1),
        })

    avg_lat = statistics.mean(r['avg_latency_ms'] for r in results)
    breach_count = sum(1 for r in results if r['breached'])
    min_margin = min(r['margin'] for r in results)
    return {
        'avg_latency': round(avg_lat),
        'breach_epochs': breach_count,
        'min_margin': min_margin,
        'epochs': results,
    }


def main():
    print_header("Multi-Scenario Adaptive Threshold (Real BLS)")
    print(f"  n={N}, epochs={N_EPOCHS}, issuances/epoch={ISSUANCES_PER_EPOCH}")

    # Pre-init BLS
    print("  Initializing BLS instances t=8..14...")
    member_ids = list(range(1, N + 1))
    bls_instances = {}
    for t in range(8, 15):
        bls = BLSThresholdSignature(threshold=t, num_members=N)
        bls.keygen(member_ids)
        bls_instances[t] = bls
    print("  Done.\n")

    peak_threats = [0.0, 0.15, 0.30, 0.45, 0.60]
    fixed_ts = [8, 10, 11, 13]
    all_data = {}

    total_combos = len(peak_threats) * (len(fixed_ts) + 1)
    done = 0

    for peak in peak_threats:
        sk = f"peak_{int(peak*100)}"
        all_data[sk] = {}

        for ft in fixed_ts:
            name = f"fixed_t{ft}"
            done += 1
            print(f"  [{done}/{total_combos}] peak={int(peak*100)}%, {name}...")
            obj = FixedThreshold(N, ft)
            result = run_scenario(N, peak, name, obj, bls_instances)
            all_data[sk][name] = result
            status = "SAFE" if result['breach_epochs'] == 0 else f"BREACH({result['breach_epochs']})"
            print(f"    -> {status}, avg={result['avg_latency']}ms, min_margin={result['min_margin']}")

        done += 1
        print(f"  [{done}/{total_combos}] peak={int(peak*100)}%, adaptive...")
        obj = AdaptiveThreshold(N, t_base=0.35, mu=0.6)
        result = run_scenario(N, peak, 'adaptive', obj, bls_instances)
        all_data[sk]['adaptive'] = result
        status = "SAFE" if result['breach_epochs'] == 0 else f"BREACH({result['breach_epochs']})"
        print(f"    -> {status}, avg={result['avg_latency']}ms, min_margin={result['min_margin']}")

    # Print summary table
    strategies = [f"fixed_t{t}" for t in fixed_ts] + ['adaptive']
    print(f"\n{'Scenario':>12s}", end="")
    for s in strategies:
        print(f" | {s:>14s}", end="")
    print("\n" + "-" * 95)
    for peak in peak_threats:
        sk = f"peak_{int(peak*100)}"
        print(f"{'peak='+str(int(peak*100))+'%':>12s}", end="")
        for s in strategies:
            d = all_data[sk][s]
            if d['breach_epochs'] > 0:
                cell = f"BREACH({d['breach_epochs']})"
            else:
                cell = f"{d['avg_latency']}ms"
            print(f" | {cell:>14s}", end="")
        print()

    # Save
    save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, f'EXP9_multi_scenario_{ts}.json')
    # Remove epoch details to keep file small
    save_data = {}
    for sk, strats in all_data.items():
        save_data[sk] = {}
        for sn, sd in strats.items():
            save_data[sk][sn] = {k: v for k, v in sd.items() if k != 'epochs'}
    with open(filepath, 'w') as f:
        json.dump(save_data, f, indent=2)
    print(f"\nResults saved: {filepath}")


if __name__ == '__main__':
    main()
