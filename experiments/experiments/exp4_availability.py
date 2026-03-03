"""
实验4: 服务可用性与恢复能力分析
对应论文 5.4.3 节

目标: 在多周期运行过程中注入不同类型和强度的扰动,
     量化系统性能退化的幅度和恢复到基线水平所需的周期数,
     验证动态信誉驱动的自适应恢复能力

优先级: P1 (已有部分12轮委员会演化数据, 本实验补充扰动与恢复分析)
"""

import sys
import os
import time
import random
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.reputation import ReputationModel, NodeBehavior
from src.models.committee import CommitteeManager
from src.utils import ExperimentResult, Timer, print_header, print_result_table

# 链交互（可选）
_fisco_client = None

def _get_chain_client():
    global _fisco_client
    if _fisco_client is None:
        from src.chain.fisco_client import FISCOClient
        _fisco_client = FISCOClient()
        _fisco_client.init()
    return _fisco_client


class PerturbationSimulator:
    """扰动模拟器 + 签发模拟"""

    def __init__(self, total_nodes: int, committee_size: int, threshold: int):
        self.total_nodes = total_nodes
        self.committee_size = committee_size
        self.threshold = threshold
        self.rep_model = ReputationModel()
        self.cm = CommitteeManager(committee_size, threshold, min_reputation=0.3)
        self.nodes = self._init_nodes()
        self.cm.current_committee = list(range(1, committee_size + 1))

    def _init_nodes(self):
        return {
            i: {
                'id': i,
                'reputation': 0.5 + random.uniform(0, 0.3),
                'online': True,
                'malicious': False,
                'refuse_sign': False,
                'extra_delay_ms': 0,
            }
            for i in range(1, self.total_nodes + 1)
        }

    def inject_offline(self, fraction: float):
        """注入节点离线"""
        committee = self.cm.current_committee
        offline_count = max(1, int(len(committee) * fraction))
        targets = random.sample(committee, min(offline_count, len(committee)))
        for nid in targets:
            self.nodes[nid]['online'] = False
        return targets

    def inject_delay(self, extra_ms: float):
        """注入通信延迟"""
        for nid in self.cm.current_committee:
            if self.nodes[nid]['online']:
                self.nodes[nid]['extra_delay_ms'] = extra_ms

    def inject_malicious(self, fraction: float):
        """注入恶意签名节点"""
        committee = self.cm.current_committee
        count = max(1, int(len(committee) * fraction))
        online = [nid for nid in committee if self.nodes[nid]['online']]
        targets = random.sample(online, min(count, len(online)))
        for nid in targets:
            self.nodes[nid]['malicious'] = True
        return targets

    def inject_refuse_sign(self, fraction: float):
        """注入拒签节点"""
        committee = self.cm.current_committee
        count = max(1, int(len(committee) * fraction))
        online = [nid for nid in committee if self.nodes[nid]['online']]
        targets = random.sample(online, min(count, len(online)))
        for nid in targets:
            self.nodes[nid]['refuse_sign'] = True
        return targets

    def clear_perturbations(self):
        """清除所有扰动"""
        for nid in self.nodes:
            self.nodes[nid]['online'] = True
            self.nodes[nid]['malicious'] = False
            self.nodes[nid]['refuse_sign'] = False
            self.nodes[nid]['extra_delay_ms'] = 0

    def simulate_issuance_round(self, num_requests: int) -> dict:
        """模拟一轮凭证签发过程"""
        committee = self.cm.current_committee
        results = {
            'success_count': 0,
            'total_count': num_requests,
            'latencies': [],
            'malicious_detected': 0,
            'refused_count': 0,
        }

        for _ in range(num_requests):
            available = [nid for nid in committee
                         if self.nodes[nid]['online'] and not self.nodes[nid]['refuse_sign']]
            refused = [nid for nid in committee if self.nodes[nid]['refuse_sign']]
            results['refused_count'] += len(refused)

            if len(available) < self.threshold:
                results['latencies'].append(5000)
                continue

            # 模拟签名收集
            latency = 0
            valid_sigs = 0
            for nid in available[:self.threshold]:
                sig_delay = 20 + self.nodes[nid]['extra_delay_ms'] + random.uniform(0, 10)
                latency = max(latency, sig_delay)

                if self.nodes[nid]['malicious']:
                    results['malicious_detected'] += 1
                else:
                    valid_sigs += 1

            if valid_sigs >= self.threshold:
                latency += 15  # 聚合时间
                results['success_count'] += 1
            else:
                latency = 5000

            results['latencies'].append(latency)

        return results

    def do_reputation_evaluation(self, round_results: dict):
        """根据本轮表现生成行为记录并评估信誉"""
        behaviors = []
        for nid in range(1, self.total_nodes + 1):
            node = self.nodes[nid]
            b = NodeBehavior(
                node_id=nid,
                issued_count=10,
                revoked_count=1 if node['malicious'] else 0,
                response_time_ms=20 + node['extra_delay_ms'] + random.uniform(0, 10),
                participated=8 if (node['online'] and not node['refuse_sign']) else 0,
                total_tasks=10,
                rejected=10 if node['refuse_sign'] else 0,
                requested=10,
                anchor_submit_rate=1.0 if node['online'] else 0.0,
                valid_sig_rate=0.0 if node['malicious'] else (1.0 if node['online'] else 0.0),
                consistency_score=0.3 if node['malicious'] else (1.0 if node['online'] else 0.5),
                online=node['online'],
                malicious=node['malicious'],
            )
            behaviors.append(b)

        # 选举新委员会
        new_committee, info = self.cm.elect(behaviors)
        return info


def run_exp4_perturbation_recovery(total_epochs=15,
                                     requests_per_epoch=500,
                                     total_nodes=20,
                                     committee_size=10,
                                     threshold=7,
                                     use_chain=True):
    """
    实验4: 多周期扰动注入与恢复分析

    扰动时间表:
      epoch 1-2:  基线 (无扰动)
      epoch 3-4:  10% 节点离线
      epoch 5:    通信延迟 +50ms
      epoch 6:    恢复观察
      epoch 7:    5% 恶意签名 + 10% 拒签
      epoch 8:    20% 节点离线 (高强度)
      epoch 9:    恢复
      epoch 10:   组合扰动 (离线+延迟+拒签)
      epoch 11-15: 恢复观察
    """
    print_header("实验4: 扰动注入与恢复分析")
    print(f"  总节点: {total_nodes}, 委员会: ({threshold},{committee_size})")
    print(f"  总周期: {total_epochs}, 每周期请求: {requests_per_epoch}")
    if use_chain:
        print("  [链上模式] 每轮委员会名单将发布到 FISCO BCOS")
        fc = _get_chain_client()

    sim = PerturbationSimulator(total_nodes, committee_size, threshold)
    epoch_records = []

    perturbation_schedule = {
        3: ('offline_10%', lambda s: s.inject_offline(0.1)),
        4: ('offline_10%', lambda s: s.inject_offline(0.1)),
        5: ('delay_50ms', lambda s: s.inject_delay(50)),
        7: ('malicious_5%+refuse_10%', lambda s: (s.inject_malicious(0.05), s.inject_refuse_sign(0.1))),
        8: ('offline_20%', lambda s: s.inject_offline(0.2)),
        10: ('combined', lambda s: (s.inject_offline(0.1), s.inject_delay(30), s.inject_refuse_sign(0.1))),
    }

    for epoch in range(1, total_epochs + 1):
        # 清除上一轮扰动并根据时间表注入新扰动
        sim.clear_perturbations()
        perturbation_label = "none"
        if epoch in perturbation_schedule:
            perturbation_label, inject_fn = perturbation_schedule[epoch]
            inject_fn(sim)

        # 模拟签发
        round_results = sim.simulate_issuance_round(requests_per_epoch)

        # 信誉评估与委员会轮换
        election_info = sim.do_reputation_evaluation(round_results)

        # 链上: 发布新委员会名单
        chain_roster_ms = 0
        if use_chain:
            members_str = [f"node_{nid}" for nid in sim.cm.current_committee]
            _, chain_roster_ms = fc.publish_roster("DCL_EXP4", epoch, members_str, threshold)

        # 统计
        latencies = round_results['latencies']
        success_rate = round_results['success_count'] / round_results['total_count'] * 100
        avg_lat = statistics.mean(latencies)
        p50 = statistics.median(latencies)
        sorted_lat = sorted(latencies)
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
        tps = round_results['success_count'] / (sum(latencies) / 1000) if sum(latencies) > 0 else 0

        # 治理指标
        high_rep_ratio = election_info.get('high_reputation_ratio', 0) if election_info.get('status') == 'SUCCESS' else 0
        retention = election_info.get('retention_rate', 100)
        avg_rep = election_info.get('avg_reputation', 0)

        record = {
            'epoch': epoch,
            'perturbation': perturbation_label,
            'success_rate': round(success_rate, 1),
            'avg_latency_ms': round(avg_lat, 1),
            'p50_ms': round(p50, 1),
            'p95_ms': round(p95, 1),
            'tps': round(tps, 1),
            'malicious_detected': round_results['malicious_detected'],
            'high_rep_ratio': round(high_rep_ratio, 1),
            'retention_rate': round(retention, 1),
            'avg_reputation': round(avg_rep, 3),
        }
        if use_chain:
            record['chain_roster_ms'] = round(chain_roster_ms, 1)
        epoch_records.append(record)
        print(f"  E{epoch:2d} [{perturbation_label:25s}] "
              f"成功率={record['success_rate']:5.1f}% "
              f"P95={record['p95_ms']:7.1f}ms "
              f"TPS={record['tps']:6.1f} "
              f"留存={record['retention_rate']:5.1f}%")

    # 汇总分析
    print("\n  === 退化与恢复分析 ===")

    # 基线 (epoch 1-2)
    baseline_success = statistics.mean([r['success_rate'] for r in epoch_records[:2]])
    baseline_p95 = statistics.mean([r['p95_ms'] for r in epoch_records[:2]])
    baseline_tps = statistics.mean([r['tps'] for r in epoch_records[:2]])

    print(f"  基线 (E1-E2): 成功率={baseline_success:.1f}%, P95={baseline_p95:.1f}ms, TPS={baseline_tps:.1f}")

    # 找最大退化
    worst_success = min(r['success_rate'] for r in epoch_records)
    worst_epoch = next(r['epoch'] for r in epoch_records if r['success_rate'] == worst_success)
    degradation = (baseline_success - worst_success) / baseline_success * 100 if baseline_success > 0 else 0
    print(f"  最大退化: E{worst_epoch} 成功率={worst_success:.1f}% (退化 {degradation:.1f}%)")

    # 恢复分析 (epoch 11-15)
    recovery_threshold = baseline_success * 0.95
    recovery_epoch = None
    for r in epoch_records[10:]:
        if r['success_rate'] >= recovery_threshold:
            recovery_epoch = r['epoch']
            break

    if recovery_epoch:
        print(f"  恢复到基线 95%: E{recovery_epoch} (需 {recovery_epoch - 10} 个周期)")
    else:
        print(f"  未在 E15 前恢复到基线 95%")

    print("\n  结果汇总:")
    print_result_table(epoch_records,
                       ['epoch', 'perturbation', 'success_rate', 'p95_ms', 'tps', 'retention_rate'])

    analysis = {
        'baseline_success_rate': round(baseline_success, 1),
        'baseline_p95_ms': round(baseline_p95, 1),
        'worst_degradation_percent': round(degradation, 1),
        'worst_epoch': worst_epoch,
        'recovery_epoch': recovery_epoch,
    }

    result = ExperimentResult(
        experiment_id='EXP4',
        experiment_name='Service Availability & Recovery',
        params={'total_epochs': total_epochs, 'total_nodes': total_nodes,
                'committee_size': committee_size, 'threshold': threshold,
                'use_chain': use_chain},
        extra={'epoch_records': epoch_records, 'analysis': analysis},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return epoch_records, analysis


def run_exp4b_static_vs_dynamic(total_epochs=12,
                                  requests_per_epoch=500,
                                  total_nodes=20,
                                  committee_size=10,
                                  threshold=7):
    """
    实验4b: 动态信誉委员会 vs 静态委员会的恢复能力对比 (消融)

    对比: 有信誉驱动选举 vs 无信誉(随机)选举
    """
    print_header("实验4b: 动态信誉 vs 静态委员会")

    perturbation_epochs = {5: 0.15, 6: 0.15}  # 这些epoch注入15%节点离线

    results = {}
    for mode in ['dynamic', 'static']:
        print(f"\n  模式: {mode}")
        sim = PerturbationSimulator(total_nodes, committee_size, threshold)
        records = []

        for epoch in range(1, total_epochs + 1):
            sim.clear_perturbations()
            if epoch in perturbation_epochs:
                sim.inject_offline(perturbation_epochs[epoch])
                sim.inject_refuse_sign(0.05)

            round_results = sim.simulate_issuance_round(requests_per_epoch)

            if mode == 'dynamic':
                sim.do_reputation_evaluation(round_results)
            # static: 不做信誉评估/委员会更换

            success_rate = round_results['success_count'] / round_results['total_count'] * 100
            records.append({
                'epoch': epoch,
                'success_rate': round(success_rate, 1),
                'avg_latency_ms': round(statistics.mean(round_results['latencies']), 1),
            })
            print(f"    E{epoch:2d}: 成功率={success_rate:.1f}%")

        results[mode] = records

    # 对比输出
    print("\n  对比汇总:")
    print(f"  {'Epoch':>5} | {'Dynamic':>10} | {'Static':>10}")
    print("-" * 30)
    for i in range(total_epochs):
        d = results['dynamic'][i]['success_rate']
        s = results['static'][i]['success_rate']
        print(f"  {i+1:5d} | {d:9.1f}% | {s:9.1f}%")

    result = ExperimentResult(
        experiment_id='EXP4b',
        experiment_name='Dynamic vs Static Committee Recovery',
        params={'total_epochs': total_epochs, 'total_nodes': total_nodes},
        extra={'dynamic': results['dynamic'], 'static': results['static']},
    )
    result.save(os.path.join(os.path.dirname(__file__), '..', 'results'))
    return results


def run_all(use_chain=True):
    """运行实验4全部子实验"""
    print_header("实验4: 服务可用性与恢复能力 (论文 5.4.3)")

    records, analysis = run_exp4_perturbation_recovery(
        total_epochs=15,
        requests_per_epoch=500,
        total_nodes=20,
        committee_size=10,
        threshold=7,
        use_chain=use_chain,
    )

    results_4b = run_exp4b_static_vs_dynamic(
        total_epochs=12,
        requests_per_epoch=500,
    )

    return {'exp4': (records, analysis), 'exp4b': results_4b}


if __name__ == '__main__':
    run_all()
