"""
实验4 v3: 信誉驱动选举 vs 随机选举 (含1轮检测延迟)

关键修正: 信誉选举使用上一轮的信誉分数进行本轮选举,
本轮行为观察结果在下一轮选举时才生效.
这模拟了真实系统中"观察行为->更新信誉->下轮选举"的时序.
"""
import sys, os, json, time, random, statistics

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from src.models.reputation import ReputationModel, NodeBehavior
from src.utils import print_header


def gen_behavior(nid, is_malicious):
    b = NodeBehavior(node_id=nid)
    b.total_tasks = 50
    b.requested = 50
    if is_malicious:
        b.response_time_ms = random.uniform(300, 800)
        b.participated = random.randint(5, 15)
        b.rejected = random.randint(20, 40)
        b.issued_count = random.randint(5, 15)
        b.revoked_count = random.randint(3, 10)
        b.anchor_submit_rate = random.uniform(0.2, 0.5)
        b.valid_sig_rate = random.uniform(0.3, 0.6)
        b.consistency_score = random.uniform(0.2, 0.5)
    else:
        b.response_time_ms = random.uniform(20, 80)
        b.participated = random.randint(42, 50)
        b.rejected = random.randint(0, 3)
        b.issued_count = random.randint(35, 50)
        b.revoked_count = random.randint(0, 2)
        b.anchor_submit_rate = random.uniform(0.9, 1.0)
        b.valid_sig_rate = random.uniform(0.95, 1.0)
        b.consistency_score = random.uniform(0.9, 1.0)
    return b


def simulate_issuance(committee, malicious_set, threshold, num_requests=300):
    honest_in_committee = [nid for nid in committee if nid not in malicious_set]
    success = 0
    for _ in range(num_requests):
        available = [nid for nid in honest_in_committee if random.random() < 0.95]
        if len(available) >= threshold:
            success += 1
    return success / num_requests * 100


def reputation_elect(scores, k, min_rep=0.3):
    """根据信誉分数选取前k个节点"""
    candidates = [(nid, s) for nid, s in scores.items() if s >= min_rep]
    candidates.sort(key=lambda x: x[1], reverse=True)
    return [nid for nid, _ in candidates[:k]]


def run_experiment():
    print_header("Exp4 v3: Reputation vs Random (1-epoch Detection Delay)")

    N = 30
    K = 20
    T = 12
    N_EPOCHS = 15
    inject_schedule = {4: 6, 7: 3}
    all_ids = list(range(1, N + 1))

    # ==========================================
    # Reputation-based election (with delay)
    # ==========================================
    print("\n  === Reputation-based Election (1-epoch delay) ===")
    random.seed(42)
    rep_model = ReputationModel()
    malicious_set = set()

    # prev_scores: 上一轮的信誉, 用于本轮选举
    prev_scores = {nid: 0.5 for nid in all_ids}
    # 初始委员会: 前K个
    committee = all_ids[:K]
    rep_results = []

    for epoch in range(1, N_EPOCHS + 1):
        # 1. 注入持续恶意节点
        if epoch in inject_schedule:
            n_inject = inject_schedule[epoch]
            candidates = list(set(all_ids) - malicious_set)
            if len(candidates) >= n_inject:
                new_mal = random.sample(candidates, n_inject)
                malicious_set.update(new_mal)

        # 2. 用上一轮信誉进行本轮选举 (检测延迟的关键!)
        if epoch > 1:
            committee = reputation_elect(prev_scores, K)

        # 3. 本轮运行: 生成行为, 计算信誉 (结果在下一轮才用于选举)
        behaviors = [gen_behavior(nid, nid in malicious_set) for nid in all_ids]
        current_scores = rep_model.evaluate_all(behaviors)

        # 4. 统计本轮委员会中的恶意节点
        mal_in = sum(1 for nid in committee if nid in malicious_set)
        success_rate = simulate_issuance(committee, malicious_set, T)
        avg_rep = statistics.mean(current_scores[nid] for nid in committee)

        rep_results.append({
            'epoch': epoch,
            'total_malicious': len(malicious_set),
            'mal_in_committee': mal_in,
            'success_rate': round(success_rate, 1),
            'avg_reputation': round(avg_rep, 4),
        })

        print("  Epoch {:2d}: mal_total={:2d}, mal_in_committee={:2d}/{}, "
              "success={:.1f}%, avg_R={:.3f}".format(
                  epoch, len(malicious_set), mal_in, K,
                  success_rate, avg_rep))

        # 5. 保存本轮信誉供下一轮选举使用
        prev_scores = dict(current_scores)

    # ==========================================
    # Random election
    # ==========================================
    print("\n  === Random Election ===")
    random.seed(42)
    rep_model2 = ReputationModel()
    malicious_set2 = set()
    rand_results = []

    for epoch in range(1, N_EPOCHS + 1):
        if epoch in inject_schedule:
            n_inject = inject_schedule[epoch]
            candidates = list(set(all_ids) - malicious_set2)
            if len(candidates) >= n_inject:
                new_mal = random.sample(candidates, n_inject)
                malicious_set2.update(new_mal)

        behaviors = [gen_behavior(nid, nid in malicious_set2) for nid in all_ids]
        scores = rep_model2.evaluate_all(behaviors)

        committee = random.sample(all_ids, K)

        mal_in = sum(1 for nid in committee if nid in malicious_set2)
        success_rate = simulate_issuance(committee, malicious_set2, T)
        avg_rep = statistics.mean(scores[nid] for nid in committee)

        rand_results.append({
            'epoch': epoch,
            'total_malicious': len(malicious_set2),
            'mal_in_committee': mal_in,
            'success_rate': round(success_rate, 1),
            'avg_reputation': round(avg_rep, 4),
        })

        print("  Epoch {:2d}: mal_total={:2d}, mal_in_committee={:2d}/{}, "
              "success={:.1f}%, avg_R={:.3f}".format(
                  epoch, len(malicious_set2), mal_in, K,
                  success_rate, avg_rep))

    return {'reputation': rep_results, 'random': rand_results}


def run_all(save_dir=None):
    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    os.makedirs(save_dir, exist_ok=True)

    results = run_experiment()

    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, 'EXP4v3_reputation_' + ts + '.json')
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\nResults saved: " + filepath)

    print("\n  === Summary ===")
    for strategy in ['reputation', 'random']:
        data = results[strategy]
        avg_sr = statistics.mean(r['success_rate'] for r in data)
        min_sr = min(r['success_rate'] for r in data)
        max_mal = max(r['mal_in_committee'] for r in data)
        print("  {}: avg_success={:.1f}%, min_success={:.1f}%, max_mal_in_committee={}".format(
            strategy, avg_sr, min_sr, max_mal))

    return results


if __name__ == '__main__':
    run_all()
