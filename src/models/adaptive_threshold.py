"""
自适应门限模型
根据信誉分布动态调整门限参数 t(e)

对应论文:
  - 公式 (5): t(e) = clamp(ceil(n*(t_base + mu*nu)), t_min, t_max)
  - 定理 3:  自适应门限安全性
  - nu = sigma_R / R_bar  信誉变异系数
"""

import math
import statistics
from typing import List, Dict, Tuple


class AdaptiveThreshold:

    def __init__(self, n, t_base=0.35, mu=0.5, t_min=None, t_max=None):
        self.n = n
        self.t_base = t_base
        self.mu = mu
        self.t_min = t_min if t_min is not None else (n // 3 + 1)
        self.t_max = t_max if t_max is not None else (math.ceil(2 * n / 3) + 1)
        self.history = []

    def compute_variation_coefficient(self, reputations):
        values = list(reputations.values())
        if len(values) < 2:
            return 0.0
        mean_r = statistics.mean(values)
        if mean_r < 1e-9:
            return 1.0
        return statistics.stdev(values) / mean_r

    def compute_threshold(self, reputations):
        nu = self.compute_variation_coefficient(reputations)
        mean_r = statistics.mean(reputations.values()) if reputations else 0.5

        raw = math.ceil(self.n * (self.t_base + self.mu * nu))
        t_e = max(self.t_min, min(self.t_max, raw))

        info = {
            'n': self.n,
            'nu': round(nu, 4),
            'mean_R': round(mean_r, 4),
            'std_R': round(statistics.stdev(reputations.values()), 4) if len(reputations) > 1 else 0,
            'raw_threshold': raw,
            't_min': self.t_min,
            't_max': self.t_max,
            't_e': t_e,
        }
        self.history.append(info)
        return t_e, info


class FixedThreshold:

    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.history = []

    def compute_threshold(self, reputations):
        nu = 0.0
        if len(reputations) > 1:
            mean_r = statistics.mean(reputations.values())
            if mean_r > 1e-9:
                nu = statistics.stdev(reputations.values()) / mean_r
        info = {'n': self.n, 'nu': round(nu, 4), 't_e': self.t}
        self.history.append(info)
        return self.t, info
