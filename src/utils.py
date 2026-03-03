"""
实验工具函数: 计时器、统计、结果保存
"""

import time
import json
import statistics
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional


@dataclass
class ExperimentResult:
    """实验结果数据结构"""
    experiment_id: str
    experiment_name: str
    params: dict = field(default_factory=dict)
    latencies: List[float] = field(default_factory=list)
    success_count: int = 0
    total_count: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def avg_latency(self) -> float:
        return statistics.mean(self.latencies) if self.latencies else 0

    @property
    def p50_latency(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0

    @property
    def p95_latency(self) -> float:
        if not self.latencies:
            return 0
        s = sorted(self.latencies)
        return s[int(len(s) * 0.95)]

    @property
    def std_latency(self) -> float:
        return statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0

    @property
    def success_rate(self) -> float:
        return (self.success_count / self.total_count * 100) if self.total_count else 0

    def summary(self) -> dict:
        return {
            'experiment': self.experiment_name,
            'params': self.params,
            'avg_ms': round(self.avg_latency, 3),
            'p50_ms': round(self.p50_latency, 3),
            'p95_ms': round(self.p95_latency, 3),
            'std_ms': round(self.std_latency, 3),
            'success_rate': round(self.success_rate, 2),
            'total_count': self.total_count,
            **self.extra,
        }

    def save(self, results_dir: str = 'results'):
        os.makedirs(results_dir, exist_ok=True)
        ts = time.strftime('%Y%m%d_%H%M%S')
        filename = f"{self.experiment_id}_{ts}.json"
        filepath = os.path.join(results_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.summary(), f, indent=2, ensure_ascii=False)
        print(f"  -> 结果已保存: {filepath}")
        return filepath


class Timer:
    """简单计时上下文管理器"""
    def __init__(self):
        self.elapsed_ms = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000


def print_header(title: str):
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def print_result_table(results: List[dict], columns: List[str] = None):
    """打印结果表格"""
    if not results:
        return
    if columns is None:
        columns = list(results[0].keys())

    # 计算列宽
    widths = {}
    for col in columns:
        widths[col] = max(len(str(col)), max(len(str(r.get(col, ''))) for r in results))

    # 表头
    header = " | ".join(str(col).ljust(widths[col]) for col in columns)
    print(header)
    print("-" * len(header))

    # 数据行
    for r in results:
        row = " | ".join(str(r.get(col, '')).ljust(widths[col]) for col in columns)
        print(row)
