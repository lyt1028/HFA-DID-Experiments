"""
凭证委员会管理器
用于委员会选举、轮换与状态跟踪

对应论文:
  - 算法 4.1: 基于信誉约束的委员会选举算法
  - 4.2 节:  委员会治理目标与设计约束
"""

from typing import List, Dict, Tuple
from .reputation import ReputationModel, NodeBehavior


class CommitteeManager:
    """凭证委员会管理"""

    def __init__(self, committee_size: int, threshold: int,
                 min_reputation: float = 0.3):
        """
        Args:
            committee_size: 委员会规模 k
            threshold:      门限 t
            min_reputation: 最低信誉门限 R_min
        """
        self.committee_size = committee_size
        self.threshold = threshold
        self.min_reputation = min_reputation
        self.reputation_model = ReputationModel()

        self.current_committee: List[int] = []
        self.epoch: int = 0
        self.history: List[Dict] = []

    def elect(self, behaviors: List[NodeBehavior]) -> Tuple[List[int], Dict]:
        """
        基于信誉的委员会选举 (算法 4.1)

        Args:
            behaviors: 所有候选节点的行为记录

        Returns:
            (new_committee_ids, election_info)
        """
        # 阶段1: 计算信誉
        scores = self.reputation_model.evaluate_all(behaviors)

        # 阶段2: 候选资格筛选
        candidates = [
            (nid, score) for nid, score in scores.items()
            if score >= self.min_reputation
        ]

        if len(candidates) < self.committee_size:
            # 候选不足, 保持当前委员会
            return self.current_committee, {
                'status': 'FAILED',
                'reason': f'candidates ({len(candidates)}) < committee_size ({self.committee_size})',
                'scores': scores,
            }

        # 阶段3: 信誉排序选取前 k
        candidates.sort(key=lambda x: x[1], reverse=True)
        new_committee = [nid for nid, _ in candidates[:self.committee_size]]

        # 统计变更
        old_set = set(self.current_committee)
        new_set = set(new_committee)
        stayed = old_set & new_set
        rotated_out = old_set - new_set
        rotated_in = new_set - old_set

        retention_rate = len(stayed) / len(old_set) * 100 if old_set else 0
        high_rep = sum(1 for _, s in candidates[:self.committee_size] if s >= 0.6)
        high_rep_ratio = high_rep / self.committee_size * 100

        info = {
            'status': 'SUCCESS',
            'epoch': self.epoch + 1,
            'scores': scores,
            'stayed': list(stayed),
            'rotated_out': list(rotated_out),
            'rotated_in': list(rotated_in),
            'retention_rate': retention_rate,
            'high_reputation_ratio': high_rep_ratio,
            'avg_reputation': sum(scores[nid] for nid in new_committee) / len(new_committee),
        }

        self.current_committee = new_committee
        self.epoch += 1
        self.history.append(info)

        return new_committee, info
