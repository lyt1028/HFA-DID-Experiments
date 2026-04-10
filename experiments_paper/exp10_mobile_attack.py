"""
实验7 (脚本编号exp10): 移动性攻击防御量化验证
对应小论文 7.7 节

目标: 通过仿真验证定理5 (移动性合谋攻击容忍界),
     量化三层防御机制的联合效果

输出: 表2 - 不同攻击速率 x 三种防御配置的安全持续时间
"""

import sys
import os
import json
import time
import random
import math
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.reputation import ReputationModel, NodeBehavior
from src.models.adaptive_threshold import AdaptiveThreshold, FixedThreshold
from src.utils import print_header, print_result_table


class MobileAdversarySimulator:
    """移动性攻击仿真器"""

    def __init__(self, n=20, delta=0.8, theta=0.6):
        """
        Args:
            n:     委员会规模
            delta: 信誉衰减因子
            theta: 选举阈值
        """
        self.n = n
        self.delta = delta
        self.theta = theta
        # 理论检测窗口 k* = ceil(ln(theta) / ln(delta))
        self.k_star = math.ceil(math.log(theta) / math.log(delta))
        self.t_min = n // 2 + 1
        # 理论最大容忍速率
        self.r_max_theory = self.t_min / self.k_star

    def _init_nodes(self):
        return {
            i: {
                'id': i,
                'reputation': 0.7 + random.uniform(0, 0.2),  # 初始高信誉
                'corrupted': False,
                'corrupted_at_epoch': -1,
                'detected': False,
            }
            for i in range(1, self.n + 1)
        }

    def _generate_behavior(self, node):
        b = NodeBehavior(node_id=node['id'])
        b.total_tasks = 50
        b.requested = 50

        if node['corrupted']:
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

        return b

    def run_single(self, attack_rate, defense_mode, max_epochs=50, seed=42):
        """
        运行单次仿真

        Args:
            attack_rate:  每轮新腐蚀节点数 r
            defense_mode: 防御模式
                - 'threshold_only':  仅门限隔离 (无信誉检测, 无自适应)
                - 'threshold_rep':   门限 + 信誉检测 (无自适应门限)
                - 'full':            完整三层 (门限 + 信誉 + 自适应)
            max_epochs:   最大仿真epoch数
            seed:         随机种子

        Returns:
            {safe_epochs, breached, breach_epoch, epoch_details}
        """
        random.seed(seed)
        nodes = self._init_nodes()
        rep_model = ReputationModel()

        if defense_mode == 'full':
            threshold_calc = AdaptiveThreshold(self.n, t_base=0.35, mu=0.6)
        else:
            threshold_calc = FixedThreshold(self.n, t=self.t_min)

        use_reputation = defense_mode in ('threshold_rep', 'full')
        epoch_details = []
        breached = False
        breach_epoch = -1

        for epoch in range(1, max_epochs + 1):
            # 1. 攻击者腐蚀新节点
            healthy = [nid for nid, nd in nodes.items()
                       if not nd['corrupted'] and not nd['detected']]
            num_to_corrupt = min(attack_rate, len(healthy))
            if num_to_corrupt > 0:
                targets = random.sample(healthy, num_to_corrupt)
                for nid in targets:
                    nodes[nid]['corrupted'] = True
                    nodes[nid]['corrupted_at_epoch'] = epoch

            # 2. 信誉评估与恶意检测
            active_nids = [nid for nid in sorted(nodes.keys())
                          if not nodes[nid]['detected']]
            behaviors = [self._generate_behavior(nodes[nid]) for nid in active_nids]
            scores = rep_model.evaluate_all(behaviors)

            detected_this_epoch = 0
            if use_reputation:
                for nid in list(nodes.keys()):
                    if nodes[nid]['corrupted'] and not nodes[nid]['detected']:
                        epochs_corrupted = epoch - nodes[nid]['corrupted_at_epoch']
                        node_rep = scores.get(nid, 0.5)
                        # 信誉低于阈值且已暴露足够轮次 -> 检测并剔除
                        if epochs_corrupted >= self.k_star and node_rep < self.theta:
                            nodes[nid]['detected'] = True
                            nodes[nid]['corrupted'] = False  # 剔除后视为移除
                            detected_this_epoch += 1

            # 3. 计算当前活跃被腐蚀节点数 (被腐蚀且未被检测到的)
            f_active = sum(1 for nid, nd in nodes.items()
                          if nd['corrupted'] and not nd['detected'])

            # 4. 计算门限
            active_scores = {nid: scores.get(nid, 0.5) for nid, nd in nodes.items()
                            if not nd['detected']}
            t_e, t_info = threshold_calc.compute_threshold(active_scores)

            # 5. 安全性判定
            is_secure = f_active < t_e

            epoch_details.append({
                'epoch': epoch,
                'f_active': f_active,
                't_e': t_e,
                'detected': detected_this_epoch,
                'is_secure': is_secure,
                'total_corrupted': sum(1 for nd in nodes.values() if nd['corrupted']),
                'total_detected': sum(1 for nd in nodes.values() if nd['detected']),
            })

            if not is_secure and not breached:
                breached = True
                breach_epoch = epoch

            # 如果所有节点都被腐蚀或检测, 停止
            remaining = sum(1 for nd in nodes.values()
                          if not nd['corrupted'] and not nd['detected'])
            if remaining == 0:
                break

        safe_epochs = breach_epoch - 1 if breached else max_epochs
        return {
            'attack_rate': attack_rate,
            'defense_mode': defense_mode,
            'safe_epochs': safe_epochs,
            'breached': breached,
            'breach_epoch': breach_epoch if breached else None,
            'total_epochs_run': len(epoch_details),
            'epoch_details': epoch_details,
        }


def run_all(save_dir=None):
    print_header("Exp10: Mobile Adversary Defense Verification")

    if save_dir is None:
        save_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(save_dir, exist_ok=True)

    sim = MobileAdversarySimulator(n=20, delta=0.8, theta=0.6)

    print(f"  Theoretical parameters:")
    print(f"    n={sim.n}, delta={sim.delta}, theta={sim.theta}")
    print(f"    k* (detection window) = {sim.k_star}")
    print(f"    t_min = {sim.t_min}")
    print(f"    r_max (theory) = {sim.r_max_theory:.2f}")

    attack_rates = [1, 2, 3, 4, 5, 6]
    defense_modes = ['threshold_only', 'threshold_rep', 'full']
    max_epochs = 50

    all_results = []
    summary_table = []

    for r in attack_rates:
        row = {'r': r, 'r_max_theory': round(sim.r_max_theory, 2)}
        for mode in defense_modes:
            print(f"\n  r={r}, defense={mode}...")
            result = sim.run_single(r, mode, max_epochs=max_epochs)
            all_results.append(result)

            status = "SAFE" if not result['breached'] else f"BREACH@{result['breach_epoch']}"
            row[mode] = status
            print(f"    -> {status} (safe_epochs={result['safe_epochs']})")

        summary_table.append(row)

    # 打印汇总表
    print("\n  === Summary Table ===")
    print(f"  {'r':>3s} | {'r_max':>5s} | {'threshold_only':>16s} | {'threshold+rep':>16s} | {'full (3-layer)':>16s}")
    print("  " + "-" * 70)
    for row in summary_table:
        print(f"  {row['r']:3d} | {row['r_max_theory']:5.2f} | "
              f"{row['threshold_only']:>16s} | {row['threshold_rep']:>16s} | {row['full']:>16s}")

    # 保存结果
    ts = time.strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(save_dir, f'EXP10_mobile_attack_{ts}.json')
    save_data = {
        'params': {
            'n': sim.n, 'delta': sim.delta, 'theta': sim.theta,
            'k_star': sim.k_star, 't_min': sim.t_min,
            'r_max_theory': sim.r_max_theory,
        },
        'summary': summary_table,
        'details': [{k: v for k, v in r.items() if k != 'epoch_details'}
                    for r in all_results],
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(save_data, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved: {filepath}")

    return all_results


if __name__ == '__main__':
    run_all()
