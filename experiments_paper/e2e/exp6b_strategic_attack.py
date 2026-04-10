"""
Task 3: 策略性诚实攻击仿真
=============================
对比两种攻击者模型:
  模型A(持续异常): 被腐蚀节点立即表现恶意, 信誉快速下降
  模型B(策略性诚实): 被腐蚀节点保持正常行为, 直到积累足够份额才暴露

验证: 即使信誉检测延迟增大, 门限密码学隔离层仍独立有效
"""

import sys
import os
import json
import time
import random
import statistics
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.models.reputation import ReputationModel, NodeBehavior


class MobileAttackSimulator:
    """移动性攻击仿真器"""

    def __init__(self, n=20, delta=0.8, theta=0.6):
        self.n = n
        self.delta = delta
        self.theta = theta
        self.k_star = math.ceil(math.log(theta) / math.log(delta))
        self.t_min = n // 2 + 1

    def _generate_behavior(self, node_id, is_corrupted, is_exposed):
        """
        生成节点行为:
        - 诚实节点/潜伏中的策略性攻击者: 正常行为
        - 持续异常攻击者/已暴露的策略性攻击者: 恶意行为
        """
        b = NodeBehavior(node_id=node_id)
        b.total_tasks = 50
        b.requested = 50

        if is_corrupted and is_exposed:
            # 恶意行为
            b.response_time_ms = random.uniform(300, 800)
            b.participated = random.randint(5, 15)
            b.rejected = random.randint(20, 35)
            b.issued_count = random.randint(5, 15)
            b.revoked_count = random.randint(3, 10)
            b.anchor_submit_rate = random.uniform(0.2, 0.5)
            b.valid_sig_rate = random.uniform(0.3, 0.6)
            b.consistency_score = random.uniform(0.2, 0.5)
        else:
            # 正常行为(诚实节点 或 潜伏中的策略性攻击者)
            b.response_time_ms = random.uniform(20, 80)
            b.participated = random.randint(42, 50)
            b.rejected = random.randint(0, 3)
            b.issued_count = random.randint(30, 50)
            b.revoked_count = random.randint(0, 2)
            b.anchor_submit_rate = random.uniform(0.85, 1.0)
            b.valid_sig_rate = random.uniform(0.9, 1.0)
            b.consistency_score = random.uniform(0.85, 1.0)

        return b

    def run_naive_attack(self, r, n_epochs=50):
        """
        模型A: 持续异常攻击
        被腐蚀节点立即表现恶意, 信誉在k*轮后降至θ以下被剔除
        """
        rep_model = ReputationModel()
        nodes = {i: {'corrupted': False, 'corrupted_epoch': -1}
                 for i in range(1, self.n + 1)}
        next_corrupt = 1

        for epoch in range(1, n_epochs + 1):
            # 每轮腐蚀r个新节点
            healthy = [nid for nid, nd in nodes.items() if not nd['corrupted']]
            to_corrupt = random.sample(healthy, min(r, len(healthy)))
            for nid in to_corrupt:
                nodes[nid]['corrupted'] = True
                nodes[nid]['corrupted_epoch'] = epoch

            # 信誉检测: 被腐蚀超过k*轮且信誉<θ的节点被剔除
            behaviors = []
            for nid, nd in nodes.items():
                is_exposed = nd['corrupted']  # 持续异常: 一旦腐蚀就暴露
                behaviors.append(self._generate_behavior(nid, nd['corrupted'], is_exposed))

            scores = rep_model.evaluate_all(behaviors)

            # 剔除: 被腐蚀超过k*轮 + 信誉<θ
            for nid, nd in nodes.items():
                if nd['corrupted']:
                    epochs_corrupted = epoch - nd['corrupted_epoch']
                    if epochs_corrupted >= self.k_star and scores.get(nid, 1.0) < self.theta:
                        nodes[nid]['corrupted'] = False  # 剔除(恢复为诚实替代)
                        nodes[nid]['corrupted_epoch'] = -1

            f_active = sum(1 for nd in nodes.values() if nd['corrupted'])
            if f_active >= self.t_min:
                return epoch  # 沦陷轮次

        return 50  # 50轮安全

    def run_strategic_attack(self, r, n_epochs=50):
        """
        模型B: 策略性诚实攻击
        被腐蚀节点保持正常行为(潜伏), 直到f_active=t_min-1时最后一个才暴露
        """
        rep_model = ReputationModel()
        nodes = {i: {'corrupted': False, 'corrupted_epoch': -1, 'exposed': False}
                 for i in range(1, self.n + 1)}

        for epoch in range(1, n_epochs + 1):
            # 每轮腐蚀r个新节点
            healthy = [nid for nid, nd in nodes.items() if not nd['corrupted']]
            to_corrupt = random.sample(healthy, min(r, len(healthy)))
            for nid in to_corrupt:
                nodes[nid]['corrupted'] = True
                nodes[nid]['corrupted_epoch'] = epoch
                nodes[nid]['exposed'] = False  # 初始潜伏

            f_active = sum(1 for nd in nodes.values() if nd['corrupted'])

            # 策略性暴露: 当f_active >= t_min时, 所有被腐蚀节点同时暴露(发动攻击)
            if f_active >= self.t_min:
                for nid, nd in nodes.items():
                    if nd['corrupted']:
                        nd['exposed'] = True

            # 生成行为(潜伏中的攻击者表现正常)
            behaviors = []
            for nid, nd in nodes.items():
                behaviors.append(self._generate_behavior(
                    nid, nd['corrupted'], nd['exposed']))

            scores = rep_model.evaluate_all(behaviors)

            # 信誉检测(只对已暴露的节点有效)
            for nid, nd in nodes.items():
                if nd['corrupted'] and nd['exposed']:
                    epochs_exposed = epoch - nd.get('exposed_epoch', epoch)
                    if nd.get('exposed_epoch') is None:
                        nd['exposed_epoch'] = epoch
                    epochs_exposed = epoch - nd['exposed_epoch']
                    if epochs_exposed >= self.k_star and scores.get(nid, 1.0) < self.theta:
                        nodes[nid]['corrupted'] = False
                        nodes[nid]['exposed'] = False
                        nodes[nid]['corrupted_epoch'] = -1

            f_active = sum(1 for nd in nodes.values() if nd['corrupted'])
            if f_active >= self.t_min:
                return epoch

        return 50

    def run_threshold_only(self, r, n_epochs=50):
        """仅门限隔离(无信誉检测): 被腐蚀节点永远不被剔除"""
        nodes = {i: {'corrupted': False} for i in range(1, self.n + 1)}

        for epoch in range(1, n_epochs + 1):
            healthy = [nid for nid, nd in nodes.items() if not nd['corrupted']]
            to_corrupt = random.sample(healthy, min(r, len(healthy)))
            for nid in to_corrupt:
                nodes[nid]['corrupted'] = True

            f_active = sum(1 for nd in nodes.values() if nd['corrupted'])
            if f_active >= self.t_min:
                return epoch

        return 50


def run_experiment(rates=None, n_repeats=20, n_epochs=50):
    if rates is None:
        rates = [1, 2, 3, 4, 5, 6]

    print("=" * 60)
    print("  移动性攻击防御对比: 持续异常 vs 策略性诚实")
    print("  n=20, δ=0.8, θ=0.6, k*=3, t_min=11")
    print("=" * 60)

    sim = MobileAttackSimulator()
    results = []

    for r in rates:
        threshold_only_epochs = []
        naive_epochs = []
        strategic_epochs = []

        for _ in range(n_repeats):
            random.seed(None)
            threshold_only_epochs.append(sim.run_threshold_only(r, n_epochs))
            naive_epochs.append(sim.run_naive_attack(r, n_epochs))
            strategic_epochs.append(sim.run_strategic_attack(r, n_epochs))

        t_avg = statistics.mean(threshold_only_epochs)
        n_avg = statistics.mean(naive_epochs)
        s_avg = statistics.mean(strategic_epochs)

        t_safe = sum(1 for e in threshold_only_epochs if e >= n_epochs)
        n_safe = sum(1 for e in naive_epochs if e >= n_epochs)
        s_safe = sum(1 for e in strategic_epochs if e >= n_epochs)

        print(f"\n  r={r}:")
        print(f"    仅门限:     平均沦陷@{t_avg:.1f}轮, 安全率={t_safe}/{n_repeats}")
        print(f"    持续异常:   平均沦陷@{n_avg:.1f}轮, 安全率={n_safe}/{n_repeats}")
        print(f"    策略性诚实: 平均沦陷@{s_avg:.1f}轮, 安全率={s_safe}/{n_repeats}")

        results.append({
            'r': r,
            'threshold_only_avg': round(t_avg, 1),
            'threshold_only_safe_rate': f"{t_safe}/{n_repeats}",
            'naive_avg': round(n_avg, 1),
            'naive_safe_rate': f"{n_safe}/{n_repeats}",
            'strategic_avg': round(s_avg, 1),
            'strategic_safe_rate': f"{s_safe}/{n_repeats}",
        })

    # 保存
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    path = os.path.join(results_dir, f'strategic_attack_{ts}.json')
    with open(path, 'w') as f:
        json.dump({'results': results, 'params': {
            'n': 20, 'delta': 0.8, 'theta': 0.6, 'k_star': 3, 't_min': 11,
            'r_max_theory': round(11 / 3, 2),
            'n_repeats': n_repeats, 'n_epochs': n_epochs,
        }}, f, indent=2)
    print(f"\n  Saved: {path}")

    # 打印对比表
    print("\n  === 攻击模型对比 ===")
    print(f"  {'r':>3s} | {'仅门限':>12s} | {'持续异常(HFA-DID)':>18s} | {'策略性诚实':>14s}")
    print("  " + "-" * 55)
    for r_data in results:
        print(f"  {r_data['r']:3d} | "
              f"BREACH@{r_data['threshold_only_avg']:4.1f} | "
              f"{'SAFE' if '20/20' in r_data['naive_safe_rate'] else 'BREACH@'+str(r_data['naive_avg']):>18s} | "
              f"{'SAFE' if '20/20' in r_data['strategic_safe_rate'] else 'BREACH@'+str(r_data['strategic_avg']):>14s}")

    return results


if __name__ == '__main__':
    if '--quick' in sys.argv:
        run_experiment(rates=[1, 3, 4, 6], n_repeats=5, n_epochs=50)
    else:
        run_experiment(rates=[1, 2, 3, 4, 5, 6], n_repeats=20, n_epochs=50)
