"""
动态信誉模型
用于凭证委员会选举与演化

对应论文:
  - 公式 (4.1): R_i = alpha * R_long + beta * R_short + gamma * R_audit
  - 公式 (4.2): R_long  长期历史信誉 (指数衰减)
  - 公式 (4.3): R_short 短期动态信誉
  - 公式 (4.4)-(4.6): f_resp, f_part, f_reject
  - 公式 (4.7): R_audit 本地行为审计信誉
"""

import math
import random
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class NodeBehavior:
    """节点在一个治理周期内的行为记录"""
    node_id: int
    issued_count: int = 0       # 签发凭证数
    revoked_count: int = 0      # 被撤销凭证数
    response_time_ms: float = 50.0  # 平均签名响应时间
    participated: int = 0       # 成功参与签发任务数
    total_tasks: int = 0        # 分配的总任务数
    rejected: int = 0           # 拒绝/超时的任务数
    requested: int = 0          # 被请求参与的任务数
    anchor_submit_rate: float = 1.0   # 按期提交锚定比例
    valid_sig_rate: float = 1.0       # 签名验证通过比例
    consistency_score: float = 1.0    # 状态一致性得分
    online: bool = True
    malicious: bool = False


class ReputationModel:
    """多维信誉量化模型"""

    def __init__(self, alpha: float = 0.4, beta: float = 0.4, gamma: float = 0.2,
                 decay_lambda: float = 0.1, eval_period: float = 1.0):
        """
        Args:
            alpha: 长期信誉权重
            beta:  短期信誉权重
            gamma: 审计信誉权重
            decay_lambda: 历史衰减系数
            eval_period:  评估周期 T
        """
        assert abs(alpha + beta + gamma - 1.0) < 1e-9
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.decay_lambda = decay_lambda
        self.eval_period = eval_period

        # 短期信誉子权重
        self.a = 1.0  # 响应效率
        self.b = 1.0  # 参与程度
        self.c = 1.0  # (1-拒绝率)

        # 审计信誉子权重
        self.w1 = 0.4  # 锚定提交率
        self.w2 = 0.3  # 签名有效率
        self.w3 = 0.3  # 一致性得分

        # 历史信誉存储
        self.prev_reputation: Dict[int, float] = {}

    def compute_long_term(self, node_id: int, behavior: NodeBehavior) -> float:
        """
        长期历史信誉 (公式 4.2)
        R_long = exp(-lambda*T) * R_prev + (1 - exp(-lambda*T)) * (1 - revoked/issued)
        """
        decay = math.exp(-self.decay_lambda * self.eval_period)
        r_prev = self.prev_reputation.get(node_id, 0.5)

        if behavior.issued_count > 0:
            quality = 1.0 - behavior.revoked_count / behavior.issued_count
        else:
            quality = 0.5  # 无签发记录取中间值

        return decay * r_prev + (1 - decay) * quality

    def compute_short_term(self, behavior: NodeBehavior,
                           all_behaviors: List[NodeBehavior]) -> float:
        """
        短期动态信誉 (公式 4.3)
        R_short = (a*f_resp + b*f_part + c*(1-f_reject)) / (a+b+c)
        """
        # f_resp: 响应效率 (公式 4.4)
        rts = [b.response_time_ms for b in all_behaviors if b.online]
        if len(rts) > 1:
            rt_min, rt_max = min(rts), max(rts)
            if rt_max > rt_min:
                f_resp = 1.0 - (behavior.response_time_ms - rt_min) / (rt_max - rt_min)
            else:
                f_resp = 1.0
        else:
            f_resp = 1.0

        # f_part: 参与程度 (公式 4.5)
        if behavior.total_tasks > 0:
            f_part = behavior.participated / behavior.total_tasks
        else:
            f_part = 0.0

        # f_reject: 拒绝率 (公式 4.6)
        if behavior.requested > 0:
            f_reject = behavior.rejected / behavior.requested
        else:
            f_reject = 0.0

        f_resp = max(0.0, min(1.0, f_resp))
        f_part = max(0.0, min(1.0, f_part))
        f_reject = max(0.0, min(1.0, f_reject))

        return (self.a * f_resp + self.b * f_part + self.c * (1 - f_reject)) / (self.a + self.b + self.c)

    def compute_audit(self, behavior: NodeBehavior) -> float:
        """
        本地行为审计信誉 (公式 4.7)
        R_audit = w1*f_anchor + w2*f_validSig + w3*f_consistency
        """
        return (self.w1 * behavior.anchor_submit_rate +
                self.w2 * behavior.valid_sig_rate +
                self.w3 * behavior.consistency_score)

    def compute_total(self, node_id: int, behavior: NodeBehavior,
                      all_behaviors: List[NodeBehavior]) -> float:
        """
        综合信誉值 (公式 4.1)
        R_i = alpha * R_long + beta * R_short + gamma * R_audit
        """
        r_long = self.compute_long_term(node_id, behavior)
        r_short = self.compute_short_term(behavior, all_behaviors)
        r_audit = self.compute_audit(behavior)

        total = self.alpha * r_long + self.beta * r_short + self.gamma * r_audit
        return max(0.0, min(1.0, total))

    def evaluate_all(self, behaviors: List[NodeBehavior]) -> Dict[int, float]:
        """评估所有节点信誉, 返回 {node_id: reputation}"""
        scores = {}
        for b in behaviors:
            scores[b.node_id] = self.compute_total(b.node_id, b, behaviors)
        # 更新历史
        self.prev_reputation.update(scores)
        return scores
