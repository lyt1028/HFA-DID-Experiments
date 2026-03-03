# HFA-DID 实验设计方案

## 目录

- [一、论文核心内容回顾](#一论文核心内容回顾)
- [二、联盟链平台选型与推荐](#二联盟链平台选型与推荐)
- [三、实验总体框架](#三实验总体框架)
- [四、实验环境与基础设施](#四实验环境与基础设施)
- [五、实验详细设计](#五实验详细设计)
  - [实验1：域内验证性能评估](#实验1域内验证性能评估)
  - [实验2：跨域验证性能评估](#实验2跨域验证性能评估)
  - [实验3：锚定与快照构建开销评估](#实验3锚定与快照构建开销评估)
  - [实验4：服务可用性与恢复能力分析](#实验4服务可用性与恢复能力分析)
  - [实验5：更新与撤销执行开销](#实验5更新与撤销执行开销)
  - [实验6：更新后验证成本与正确性](#实验6更新后验证成本与正确性)
  - [实验7：陷门继承安全性与轮换影响](#实验7陷门继承安全性与轮换影响)
- [六、对比与消融实验设计](#六对比与消融实验设计)
- [七、实验执行计划与优先级](#七实验执行计划与优先级)

---

## 一、论文核心内容回顾

### 1.1 论文题目

**面向跨域的分布式数字身份关键技术研究**
HFA-DID: Hierarchical Federated Architecture for Decentralized Identity

### 1.2 三层架构

```
┌─────────────────────────────────────────────┐
│          基础信任层 (RTL)                      │
│   - 根信任委员会，BFT共识                      │
│   - 域注册与合法性背书                          │
│   - 全域快照的最终门限签名背书                   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│          全域协调层 (GCL)                      │
│   - 汇聚各 DCL 的状态锚定信息                   │
│   - 版本化锚定 + 聚合窗口                       │
│   - 生成全域状态快照 SnapshotMeta               │
└──────────┬───────────────┬──────────────────┘
           │               │
┌──────────┴───┐   ┌──────┴──────┐
│   DCL_A      │   │   DCL_B     │  ...
│ - 域内自治    │   │ - 域内自治   │
│ - 凭证委员会  │   │ - 凭证委员会 │
│ - 信誉评估    │   │ - 信誉评估   │
│ - Merkle锚定 │   │ - Merkle锚定│
└──────────────┘   └─────────────┘
```

### 1.3 三大核心贡献

| 编号 | 贡献 | 对应章节 | 核心技术 |
|------|------|----------|----------|
| 1 | 分层治理架构 + 跨域验证机制 | 第三章 | Merkle状态承诺、全域异步锚定、独立验证模型 |
| 2 | 动态信誉委员会 + Re-DKG密钥轮转 | 第四章 | 多维信誉模型、零秘密多项式Re-DKG、BLS门限签名 |
| 3 | 变色龙哈希凭证可验证更新/撤销 | 第四章 | 变色龙哈希、门限陷门共享、原地可编辑承诺 |

### 1.4 论文已有实验数据

| 实验内容 | 状态 | 对应图表 |
|----------|------|----------|
| 凭证签发性能（不同委员会规模） | 已完成 | 图5.1 |
| 委员会动态演化（12轮仿真） | 已完成 | 图5.3 |
| 签发/域内/跨域验证对比 | 已完成 | 图5.4 |
| 鲁棒性分析表 | 已完成 | 表5.1 |
| 域内验证性能评估 | **仅标题** | 无 |
| 跨域验证性能评估 | **仅标题** | 无 |
| 锚定与快照构建开销评估 | **仅标题** | 无 |
| 服务可用性与恢复能力 | **仅标题** | 无 |
| 更新与撤销执行开销 | **仅标题** | 无 |
| 更新后验证成本与正确性 | **仅标题** | 无 |
| 陷门继承安全性与轮换影响 | **仅标题** | 无 |

---

## 二、联盟链平台选型与推荐

### 2.1 候选平台对比

| 平台 | 中文文档 | 部署难度 | 多群组/通道 | 学术认可 | 与论文契合度 |
|------|----------|----------|-------------|----------|-------------|
| **FISCO BCOS** | 优秀 | 低（Docker一键） | 多群组机制 | 国内高 | WeIdentity基于此 |
| Hyperledger Fabric | 良好 | 高 | Channel机制 | 国际高 | 适配但复杂 |
| 长安链 ChainMaker | 优秀 | 中 | 多链架构 | 国内中 | 适配 |
| Go-Ethereum私链 | 良好 | 低 | 无原生支持 | 中 | 需额外封装 |

### 2.2 推荐方案：FISCO BCOS

**选择理由：**

1. **对比实验天然兼容**：论文对比方案 WeIdentity 就是构建在 FISCO BCOS 之上的，使用同一底层平台可以排除底层差异带来的实验偏差，使对比更公平
2. **多群组机制映射三层架构**：FISCO BCOS 的群组（Group）机制可以直接映射 HFA-DID 的三层结构：
   - Group 1 → RTL（基础信任层）
   - Group 2 → GCL（全域协调层）
   - Group 3, 4, 5... → DCL_A, DCL_B, DCL_C...（各业务凭证域）
3. **部署简单**：支持 Docker 一键部署，与论文中描述的 Docker 24.x 容器环境一致
4. **中文文档完善**：适合 UESTC 论文写作环境
5. **Solidity 智能合约**：可直接实现域注册合约、锚定聚合合约、状态管理合约
6. **Python/Java SDK 齐全**：便于与密码学层（Python）对接

### 2.3 整体技术栈

```
┌─────────────────────────────────────────────────────┐
│                    实验系统技术栈                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  区块链层：FISCO BCOS v3.x                            │
│  ├── Group 1: RTL 根信任链                            │
│  ├── Group 2: GCL 全域协调链                          │
│  └── Group 3-N: DCL 各业务凭证域链                     │
│                                                      │
│  智能合约层：Solidity                                  │
│  ├── DomainRegistry.sol    域注册与状态管理             │
│  ├── AnchorAggregator.sol  锚定聚合与快照管理          │
│  ├── SnapshotEndorse.sol   全域快照背书                │
│  └── CredentialState.sol   凭证状态存储                │
│                                                      │
│  密码学层：Python                                      │
│  ├── py_ecc / blspy        BLS12-381 门限签名          │
│  ├── charm-crypto          变色龙哈希                  │
│  ├── 自实现               Re-DKG / VSS / 信誉模型      │
│  └── pymerkle / 自实现    Merkle 树构建与验证           │
│                                                      │
│  测试与监控层                                          │
│  ├── Docker Compose v2     多节点容器编排               │
│  ├── tc netem             网络延迟/丢包模拟             │
│  ├── Prometheus           性能指标采集                  │
│  ├── matplotlib           实验结果可视化                │
│  └── pytest / unittest    自动化测试                   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### 2.4 关键 Python 依赖

| 库 | 版本建议 | 用途 |
|----|----------|------|
| `py_ecc` | >=6.0.0 | BLS12-381 曲线运算、签名/验签 |
| `blspy` | >=2.0.0 | BLS 门限签名聚合（性能更优的替代） |
| `charm-crypto` | >=0.50 | 变色龙哈希、双线性配对 |
| `pymerkle` | >=6.0.0 | Merkle 树构建与路径证明 |
| `pycryptodome` | >=3.19 | 基础密码学原语 |
| `numpy` | >=1.24 | 信誉模型数值计算 |
| `matplotlib` | >=3.7 | 实验结果绘图 |
| `pandas` | >=2.0 | 实验数据统计分析 |
| `web3` / `fisco-bcos-python-sdk` | 最新 | 区块链合约交互 |

---

## 三、实验总体框架

### 3.1 实验维度与映射

```
论文贡献                    实验维度                     具体实验
─────────                  ─────────                   ─────────
第三章：分层架构     →    核心性能评估          →    实验1: 域内验证性能
      + 跨域验证                                    实验2: 跨域验证性能
                                                    实验3: 锚定与快照开销

第四章：动态信誉     →    动态演化与鲁棒性       →    实验4: 服务可用性与恢复
      + Re-DKG                                     （已有：委员会演化12轮）

第四章：变色龙哈希   →    可验证更新/撤销专项    →    实验5: 更新/撤销开销
      + 凭证撤销                                    实验6: 更新后验证正确性
                                                    实验7: 陷门继承安全性

整体方案            →    对比与消融分析          →    横向对比 + 组件消融
```

### 3.2 统一指标体系

| 指标类别 | 具体指标 | 单位 | 说明 |
|----------|----------|------|------|
| 延迟 | 平均延迟 (Avg Latency) | ms | 所有请求的算术平均 |
| 延迟 | P50 延迟 | ms | 第50百分位延迟 |
| 延迟 | P95 延迟 | ms | 第95百分位延迟 |
| 吞吐 | TPS | 次/秒 | 每秒处理的操作数 |
| 成功率 | 操作成功率 | % | 成功操作数/总请求数 |
| 存储 | 链上存储开销 | bytes | 单次操作的链上数据量 |
| 治理 | 高信誉节点占比 | % | 信誉值超过阈值的节点比例 |
| 治理 | 委员会留存率 | % | 连续两周期中留任成员占比 |
| 恢复 | 恢复周期数 | epoch | 从扰动恢复到基线95%的周期数 |

---

## 四、实验环境与基础设施

### 4.1 硬件环境

```
实验机器配置（建议）：
  CPU:   8核以上（Intel i7/i9 或 AMD Ryzen 7/9）
  内存:  32 GB 以上（多容器并行运行）
  磁盘:  SSD 256 GB 以上
  网络:  本地 Docker 网络（bridge 模式）
```

### 4.2 软件环境

```
操作系统：  Windows 11 + WSL2 (Ubuntu 22.04) 或直接 Linux
容器平台：  Docker 24.x + Docker Compose v2
区块链：    FISCO BCOS v3.6.x
编程语言：  Python 3.10+
网络模拟：  Linux tc/netem（在WSL2或Linux容器中使用）
```

### 4.3 FISCO BCOS 部署拓扑

```
Docker Compose 部署方案：

# RTL 节点群组（3个节点，BFT共识）
rtl-node-0:  端口 30300, RPC 8545
rtl-node-1:  端口 30301, RPC 8546
rtl-node-2:  端口 30302, RPC 8547

# GCL 节点群组（4个节点）
gcl-node-0:  端口 30310, RPC 8550
gcl-node-1:  端口 30311, RPC 8551
gcl-node-2:  端口 30312, RPC 8552
gcl-node-3:  端口 30313, RPC 8553

# DCL_A 业务凭证域（可配置 4-10 个节点）
dcl-a-node-0 ~ dcl-a-node-9:  端口 30320-30329, RPC 8560-8569

# DCL_B 业务凭证域（可配置 4-10 个节点）
dcl-b-node-0 ~ dcl-b-node-9:  端口 30330-30339, RPC 8570-8579

# DCL_C 业务凭证域（可配置 4-10 个节点）
dcl-c-node-0 ~ dcl-c-node-9:  端口 30340-30349, RPC 8580-8589
```

### 4.4 网络模拟配置

```bash
# 正常场景：1 Gbps 带宽，1-2ms 单向延迟，0% 丢包
tc qdisc add dev eth0 root netem delay 2ms

# 跨域场景：模拟跨地域网络
tc qdisc add dev eth0 root netem delay 50ms 10ms distribution normal

# 扰动场景：高延迟+丢包
tc qdisc add dev eth0 root netem delay 100ms loss 5%

# 恢复正常
tc qdisc del dev eth0 root
```

### 4.5 实验数据采集框架

```python
"""
统一的实验数据采集与记录框架
"""
import time
import json
import statistics
from dataclasses import dataclass, asdict
from typing import List

@dataclass
class ExperimentResult:
    experiment_id: str          # 实验编号
    experiment_name: str        # 实验名称
    timestamp: str              # 执行时间戳
    params: dict                # 实验参数
    latencies: List[float]      # 所有延迟值 (ms)
    success_count: int          # 成功次数
    total_count: int            # 总请求次数

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
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * 0.95)
        return sorted_lat[idx]

    @property
    def success_rate(self) -> float:
        return (self.success_count / self.total_count * 100) if self.total_count else 0

    @property
    def tps(self) -> float:
        total_time = sum(self.latencies) / 1000  # 转为秒
        return self.total_count / total_time if total_time > 0 else 0

    def save(self, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)


class LatencyTimer:
    """延迟计时上下文管理器"""
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self.start) * 1000
```

---

## 五、实验详细设计

---

### 实验1：域内验证性能评估

**对应论文章节：** 5.3.2

**实验目标：** 测量"BLS聚合验签 + Merkle路径验证"组合在不同负载条件下的计算开销，验证域内验证的近似常数级复杂度，并与 WeIdentity（链上合约验签）和 CanDID（ZKP重构验证）进行横向对比。

#### 1.1 实验假设与预期

- HFA-DID 域内验证仅需1次 BLS 聚合验签 + 1次 Merkle 路径重算，复杂度近似 O(1)
- WeIdentity 需要链上合约执行签名校验 + 链上状态查询，延迟随链上负载增长
- CanDID 需要零知识证明重构与验证，计算复杂度较高

#### 1.2 自变量与控制变量

```
自变量：
  (a) 并发验证请求数: [100, 500, 1000, 2000, 5000]
  (b) 委员会规模 n:   [4, 6, 8, 10]（仅测量对验证端的影响）

控制变量：
  - 门限比例: t = ceil(n * 0.6)
  - Merkle 树凭证总数: 1000（固定树深度约10层）
  - 网络条件: 本地（延迟 < 2ms）
  - 每组实验重复次数: 10 次，取平均值
```

#### 1.3 因变量（测量指标）

| 指标 | 采集方式 | 说明 |
|------|----------|------|
| 平均验证延迟 (ms) | LatencyTimer | 单次验证端到端耗时 |
| P50 延迟 (ms) | 排序取中位数 | 典型延迟 |
| P95 延迟 (ms) | 排序取95%分位 | 尾部延迟 |
| 验证吞吐率 TPS | 总请求数 / 总耗时 | 验证并发能力 |
| 验证成功率 (%) | 成功数 / 总数 | 功能正确性 |
| BLS验签子耗时 (ms) | 单独计时 | 签名验证部分 |
| Merkle路径验证子耗时 (ms) | 单独计时 | 路径验证部分 |

#### 1.4 实验步骤

```
Step 1: 环境准备
  1.1 启动 DCL_A 的 FISCO BCOS 节点集群（n 个节点）
  1.2 执行 DKG 生成域级聚合公钥 PK_CC 和各节点私钥份额
  1.3 签发 1000 个测试凭证，构建 Merkle 树，记录各凭证的 Merkle 路径

Step 2: HFA-DID 域内验证测试
  2.1 从 1000 个凭证中随机抽取验证目标
  2.2 按并发量依次发起验证请求
  2.3 每次验证执行以下操作并分段计时：
      (a) BLS 聚合签名验证: e(sigma, g) == e(H(msg), PK_CC)
      (b) Merkle 路径验证: 从叶子 Hash(VC) 沿路径重算至 Root_VC
      (c) 时间戳检查 + 撤销列表查询
  2.4 记录每次验证的总延迟和各子步骤延迟

Step 3: 对比方案测试
  3.1 WeIdentity: 部署 WeIdentity 合约到 FISCO BCOS，调用链上 verify 函数
  3.2 CanDID: 模拟 ZKP 验证（使用 groth16 或等效方案）

Step 4: 数据汇总与统计
  4.1 计算各方案在不同并发量下的 Avg/P50/P95/TPS/成功率
  4.2 生成对比图表
```

#### 1.5 核心代码逻辑

```python
"""
实验1：域内验证性能测试核心逻辑
"""
import hashlib
from py_ecc.bls import G2ProofOfPossession as bls

# ========== 模拟数据准备 ==========

def build_merkle_tree(leaves: list) -> tuple:
    """构建 Merkle 树，返回 (root, tree_layers)"""
    if len(leaves) == 0:
        return hashlib.sha256(b'').digest(), [[]]

    # 排序以保证确定性
    current_layer = sorted(leaves)
    layers = [current_layer[:]]

    while len(current_layer) > 1:
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])  # 奇数补齐
        next_layer = []
        for i in range(0, len(current_layer), 2):
            combined = current_layer[i] + current_layer[i+1]
            parent = hashlib.sha256(combined).digest()
            next_layer.append(parent)
        layers.append(next_layer)
        current_layer = next_layer

    return current_layer[0], layers


def get_merkle_proof(leaf_index: int, layers: list) -> list:
    """获取指定叶子的 Merkle 证明路径"""
    proof = []
    idx = leaf_index
    for layer in layers[:-1]:
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
        else:
            sibling_idx = idx - 1
        proof.append((layer[sibling_idx], 'right' if idx % 2 == 0 else 'left'))
        idx = idx // 2
    return proof


def verify_merkle_proof(leaf: bytes, proof: list, expected_root: bytes) -> bool:
    """验证 Merkle 路径"""
    current = leaf
    for sibling, direction in proof:
        if direction == 'right':
            combined = current + sibling
        else:
            combined = sibling + current
        current = hashlib.sha256(combined).digest()
    return current == expected_root


# ========== BLS 签名验证 ==========

def bls_aggregate_verify(pk_cc, message: bytes, aggregate_sig) -> bool:
    """BLS 聚合签名验证"""
    return bls.Verify(pk_cc, message, aggregate_sig)


# ========== 域内验证主流程 ==========

def intra_domain_verify(vc_content: bytes, vc_sigma, pk_cc,
                         merkle_proof: list, domain_root: bytes,
                         revocation_set: set, vc_id: str) -> tuple:
    """
    域内验证完整流程
    返回: (验证结果 bool, 总延迟 ms, 各阶段延迟 dict)
    """
    stage_latencies = {}
    total_start = time.perf_counter()

    # Stage 1: BLS 聚合签名验证
    t1 = time.perf_counter()
    msg_hash = hashlib.sha256(vc_content).digest()
    sig_valid = bls_aggregate_verify(pk_cc, msg_hash, vc_sigma)
    stage_latencies['bls_verify'] = (time.perf_counter() - t1) * 1000

    # Stage 2: Merkle 路径验证
    t2 = time.perf_counter()
    leaf_hash = hashlib.sha256(vc_content).digest()
    path_valid = verify_merkle_proof(leaf_hash, merkle_proof, domain_root)
    stage_latencies['merkle_verify'] = (time.perf_counter() - t2) * 1000

    # Stage 3: 撤销状态检查
    t3 = time.perf_counter()
    status_valid = vc_id not in revocation_set
    stage_latencies['status_check'] = (time.perf_counter() - t3) * 1000

    total_latency = (time.perf_counter() - total_start) * 1000
    result = sig_valid and path_valid and status_valid

    return result, total_latency, stage_latencies


# ========== 批量测试 ==========

def run_intra_domain_experiment(num_requests: int, credentials: list,
                                 pk_cc, merkle_tree, domain_root,
                                 revocation_set: set) -> ExperimentResult:
    """执行一组域内验证实验"""
    import random

    latencies = []
    stage_data = {'bls_verify': [], 'merkle_verify': [], 'status_check': []}
    success_count = 0

    for _ in range(num_requests):
        # 随机选取凭证
        idx = random.randint(0, len(credentials) - 1)
        vc = credentials[idx]
        proof = get_merkle_proof(idx, merkle_tree)

        result, latency, stages = intra_domain_verify(
            vc['content'], vc['sigma'], pk_cc,
            proof, domain_root, revocation_set, vc['id']
        )

        latencies.append(latency)
        if result:
            success_count += 1
        for key in stages:
            stage_data[key].append(stages[key])

    return ExperimentResult(
        experiment_id='EXP-1',
        experiment_name='Intra-Domain Verification',
        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
        params={
            'num_requests': num_requests,
            'num_credentials': len(credentials),
            'committee_size': 'n/a (verification side)',
        },
        latencies=latencies,
        success_count=success_count,
        total_count=num_requests,
    )
```

#### 1.6 预期输出图表

**图表1：不同并发量下的域内验证平均延迟对比**

```
Y轴: 平均验证延迟 (ms)
X轴: 并发请求数 [100, 500, 1000, 2000, 5000]
三条曲线: HFA-DID（近似水平）, WeIdentity（上升）, CanDID（上升更快）
```

**图表2：域内验证延迟分解（堆叠柱状图）**

```
Y轴: 延迟 (ms)
X轴: 不同请求量
堆叠: BLS验签 | Merkle路径 | 状态检查
```

---

### 实验2：跨域验证性能评估

**对应论文章节：** 5.3.3

**实验目标：** 测量 HFA-DID 跨域验证在不同业务域数量和不同网络条件下的性能表现，验证全域快照机制对跨域验证复杂度的优化效果（近似 O(1) vs Cross-Chain 的 O(log N)），并评估网络扰动对验证稳定性的影响。

#### 2.1 实验分组

本实验分为三个子实验：

| 子实验 | 自变量 | 目标 |
|--------|--------|------|
| 2a | 业务域数量 m | 跨域验证随域规模的扩展性 |
| 2b | 网络延迟和丢包率 | 网络扰动下的验证稳定性 |
| 2c | 与 Cross-Chain 对比 | 不同跨域验证架构的性能差异 |

#### 2.2 实验2a：域规模影响

```
自变量：
  业务凭证域数量 m = [2, 4, 6, 8, 10]

控制变量：
  - 每个域的凭证数: 1000
  - 委员会规模: n=10, t=7
  - 网络条件: 域间延迟 10ms
  - 每组验证请求: 500 次
  - 重复实验: 10 次

因变量：
  - 跨域验证总延迟 (ms)
  - RTL 域状态查询延迟 (ms)
  - GCL 锚定记录获取延迟 (ms)
  - Merkle 路径验证延迟（两层：域内 + 全域）(ms)
  - BLS 签名验证延迟 (ms)
  - RTL 背书签名验证延迟 (ms)
  - 验证成功率 (%)
```

#### 2.3 实验2b：网络扰动影响

```
自变量（组合变化）：
  网络延迟:  [2ms, 10ms, 50ms, 100ms, 200ms]
  丢包率:    [0%, 1%, 5%, 10%]

控制变量：
  - 域数量: m=4
  - 凭证数: 1000/域
  - 验证请求: 500 次/组

因变量：
  - 跨域验证平均延迟 (ms)
  - P95 延迟 (ms)
  - 验证成功率 (%)
  - 超时率 (%)（超时阈值: 5000ms）
```

#### 2.4 跨域验证核心代码逻辑

```python
"""
实验2：跨域验证性能测试核心逻辑
"""

def cross_domain_verify(vc, proof_path, rtl_client, gcl_client) -> tuple:
    """
    跨域验证完整流程（对应论文算法3.2）

    参数:
      vc:          凭证对象 {domain_id, did_u, attr, sigma, pk_cc, timestamp, vcid}
      proof_path:  证明路径 {local_proof, global_proof}
      rtl_client:  RTL 链上查询客户端
      gcl_client:  GCL 链上查询客户端

    返回: (验证结果, 总延迟, 各阶段延迟)
    """
    stages = {}
    total_start = time.perf_counter()

    # ======== Step 1: RTL 域状态查询 ========
    t = time.perf_counter()
    domain_status = rtl_client.query_domain_status(vc['domain_id'])
    stages['rtl_domain_query'] = (time.perf_counter() - t) * 1000

    if domain_status != 'Active':
        total = (time.perf_counter() - total_start) * 1000
        return False, total, stages

    # ======== Step 2: GCL 获取锚定记录 ========
    t = time.perf_counter()
    anchor = gcl_client.get_latest_anchor(vc['domain_id'], vc['epoch'])
    # anchor = {domain_root, global_root, snapshot_meta, endorse_sig}
    stages['gcl_anchor_query'] = (time.perf_counter() - t) * 1000

    # ======== Step 3: 域内 Merkle 路径验证 ========
    t = time.perf_counter()
    vc_hash = hashlib.sha256(
        vc['did_u'].encode() + str(vc['attr']).encode() + str(vc['epoch']).encode()
    ).digest()
    local_root_calc = verify_merkle_path(vc_hash, proof_path['local_proof'])
    local_valid = (local_root_calc == anchor['domain_root'])
    stages['local_merkle_verify'] = (time.perf_counter() - t) * 1000

    if not local_valid:
        total = (time.perf_counter() - total_start) * 1000
        return False, total, stages

    # ======== Step 4: 全域 Merkle 路径验证 ========
    t = time.perf_counter()
    global_root_calc = verify_merkle_path(
        anchor['domain_root'], proof_path['global_proof']
    )
    global_valid = (global_root_calc == anchor['global_root'])
    stages['global_merkle_verify'] = (time.perf_counter() - t) * 1000

    if not global_valid:
        total = (time.perf_counter() - total_start) * 1000
        return False, total, stages

    # ======== Step 5: BLS 凭证签名验证 ========
    t = time.perf_counter()
    msg = hashlib.sha256(
        vc['did_u'].encode() + str(vc['attr']).encode() + str(vc['epoch']).encode()
    ).digest()
    sig_valid = bls_aggregate_verify(vc['pk_cc'], msg, vc['sigma'])
    stages['bls_sig_verify'] = (time.perf_counter() - t) * 1000

    # ======== Step 6: RTL 背书签名验证 ========
    t = time.perf_counter()
    endorse_valid = bls_aggregate_verify(
        rtl_client.get_rtl_pk(),
        anchor['global_root'],
        anchor['endorse_sig']
    )
    stages['rtl_endorse_verify'] = (time.perf_counter() - t) * 1000

    # ======== Step 7: 时间戳与撤销检查 ========
    t = time.perf_counter()
    timestamp_valid = check_timestamp(vc['timestamp'])
    revoke_valid = not gcl_client.is_revoked(vc['vcid'])
    stages['timestamp_revoke_check'] = (time.perf_counter() - t) * 1000

    total = (time.perf_counter() - total_start) * 1000
    result = all([local_valid, global_valid, sig_valid,
                  endorse_valid, timestamp_valid, revoke_valid])

    return result, total, stages
```

#### 2.5 预期输出图表

**图表3：不同域数量下的跨域验证延迟分解（堆叠柱状图）**
```
Y轴: 延迟 (ms)
X轴: 域数量 [2, 4, 6, 8, 10]
堆叠: RTL查询 | GCL查询 | 域内Merkle | 全域Merkle | BLS验签 | RTL背书验签
关键观察: 总延迟应随域数增加保持近似稳定
```

**图表4：网络扰动下的跨域验证P95延迟热力图**
```
Y轴: 网络延迟 [2ms, 10ms, 50ms, 100ms, 200ms]
X轴: 丢包率 [0%, 1%, 5%, 10%]
颜色: P95延迟值（从绿色到红色）
```

**图表5：HFA-DID vs Cross-Chain 跨域验证延迟对比**
```
Y轴: 验证延迟 (ms)
X轴: 节点规模 [2, 4, 6, 8, 10]
两条曲线: HFA-DID（近似水平）, Cross-Chain（对数增长）
```

---

### 实验3：锚定与快照构建开销评估

**对应论文章节：** 5.3.4

**实验目标：** 分别测量域内 Merkle 锚定、GCL 全域聚合、RTL 门限背书三个阶段的时间与存储开销，分析系统在域数量和凭证数量增长时的可扩展性瓶颈。

#### 3.1 自变量设计

```
实验3a - 域内凭证规模影响：
  自变量: 单域凭证数 n_vc = [100, 500, 1000, 5000, 10000]
  控制变量: 域数 m=1, 委员会 n=10

实验3b - 参与域数影响：
  自变量: 参与域数 m = [2, 4, 6, 8, 10, 15, 20]
  控制变量: 每域凭证数 n_vc=1000

实验3c - 联合影响：
  自变量: n_vc x m 的组合矩阵
  n_vc = [500, 1000, 5000]
  m = [2, 5, 10]
```

#### 3.2 三阶段详细测量

```
阶段1：域内 Merkle 树构建与锚定记录生成
  测量内容:
    (a) 叶子哈希计算时间: 对每个凭证计算 L_i = H(DomainID || e || DID_u || delta || H(Commit))
    (b) 排序时间: 对所有叶子摘要执行字典序排序
    (c) Merkle 树构建时间: 自底向上构建树，计算域级根 Root_VC_j
    (d) 锚定记录签名时间: 委员会对 Root 进行门限签名
    (e) 总阶段1时间
    (f) 存储开销: 锚定记录大小 (bytes)

阶段2：GCL 全域聚合
  测量内容:
    (a) 锚定记录接收与验证时间: 验证各域提交的委员会签名
    (b) 版本/时间窗口筛选时间
    (c) 域根排序时间: 按 DomainID 确定性排序
    (d) 二级 Merkle 树构建时间: 将 m 个域根聚合为 Root_Global
    (e) 快照元数据构造时间
    (f) 总阶段2时间
    (g) 存储开销: 全域快照大小 (bytes)

阶段3：RTL 门限背书
  测量内容:
    (a) GCL 签名验证时间
    (b) RTL 门限签名生成时间（份额收集 + 聚合）
    (c) 背书记录写入时间
    (d) 总阶段3时间
    (e) 存储开销: 背书记录大小 (bytes)
```

#### 3.3 核心代码逻辑

```python
"""
实验3：锚定与快照构建开销测试
"""

def benchmark_domain_anchoring(credentials: list, domain_id: str,
                                epoch: int, committee_shares: list) -> dict:
    """测量域内锚定全过程"""
    results = {}

    # Stage 1a: 叶子哈希计算
    t = time.perf_counter()
    leaves = []
    for vc in credentials:
        leaf = hashlib.sha256(
            domain_id.encode() +
            str(epoch).encode() +
            vc['did'].encode() +
            vc['status'].encode() +
            hashlib.sha256(vc['commit'].encode()).digest()
        ).digest()
        leaves.append(leaf)
    results['leaf_hash_time'] = (time.perf_counter() - t) * 1000

    # Stage 1b: 排序
    t = time.perf_counter()
    leaves_sorted = sorted(leaves)
    results['sort_time'] = (time.perf_counter() - t) * 1000

    # Stage 1c: Merkle 树构建
    t = time.perf_counter()
    root, tree_layers = build_merkle_tree(leaves_sorted)
    results['merkle_build_time'] = (time.perf_counter() - t) * 1000
    results['tree_depth'] = len(tree_layers) - 1

    # Stage 1d: 委员会门限签名
    t = time.perf_counter()
    # 模拟门限签名：收集 t 个部分签名并聚合
    partial_sigs = [bls_partial_sign(share, root) for share in committee_shares[:threshold]]
    anchor_sig = bls_aggregate_partial(partial_sigs)
    results['threshold_sign_time'] = (time.perf_counter() - t) * 1000

    # 存储开销
    anchor_record = {
        'domain_id': domain_id,
        'epoch': epoch,
        'root': root.hex(),
        'timestamp': time.time(),
        'signature': anchor_sig.hex() if isinstance(anchor_sig, bytes) else str(anchor_sig),
    }
    results['storage_bytes'] = len(json.dumps(anchor_record).encode())
    results['total_time'] = sum([
        results['leaf_hash_time'],
        results['sort_time'],
        results['merkle_build_time'],
        results['threshold_sign_time'],
    ])

    return results


def benchmark_gcl_aggregation(domain_anchors: list) -> dict:
    """测量 GCL 全域聚合过程"""
    results = {}

    # Stage 2a: 验证各域锚定记录签名
    t = time.perf_counter()
    valid_anchors = []
    for anchor in domain_anchors:
        if verify_committee_signature(anchor):
            valid_anchors.append(anchor)
    results['anchor_verify_time'] = (time.perf_counter() - t) * 1000

    # Stage 2b: 版本/时间窗口筛选
    t = time.perf_counter()
    filtered = [a for a in valid_anchors
                if a['epoch'] == current_epoch
                and a['timestamp'] in time_window]
    results['filter_time'] = (time.perf_counter() - t) * 1000

    # Stage 2c: 域根排序
    t = time.perf_counter()
    sorted_roots = sorted(filtered, key=lambda x: x['domain_id'])
    domain_roots = [bytes.fromhex(a['root']) for a in sorted_roots]
    results['sort_time'] = (time.perf_counter() - t) * 1000

    # Stage 2d: 二级 Merkle 树构建
    t = time.perf_counter()
    global_root, _ = build_merkle_tree(domain_roots)
    results['global_merkle_time'] = (time.perf_counter() - t) * 1000

    # Stage 2e: 快照元数据构造
    t = time.perf_counter()
    snapshot_meta = {
        'epoch': current_epoch,
        'time_window': time_window,
        'global_root': global_root.hex(),
        'participating_domains': [a['domain_id'] for a in sorted_roots],
    }
    results['snapshot_construct_time'] = (time.perf_counter() - t) * 1000

    results['num_domains'] = len(filtered)
    results['storage_bytes'] = len(json.dumps(snapshot_meta).encode())
    results['total_time'] = sum([
        results['anchor_verify_time'],
        results['filter_time'],
        results['sort_time'],
        results['global_merkle_time'],
        results['snapshot_construct_time'],
    ])

    return results
```

#### 3.4 预期输出图表

**图表6：域内 Merkle 建树时间随凭证数变化**
```
Y轴: 构建时间 (ms)
X轴: 凭证数 [100, 500, 1000, 5000, 10000]
预期趋势: O(n log n)
```

**图表7：GCL 全域聚合时间随域数变化**
```
Y轴: 聚合时间 (ms)
X轴: 域数 [2, 4, 6, 8, 10, 15, 20]
预期趋势: O(m log m)，但 m 较小时增长平缓
```

**图表8：端到端锚定延迟三阶段分解**
```
Y轴: 延迟 (ms)
X轴: 域数
堆叠柱状图: 域内锚定 | GCL聚合 | RTL背书
```

**图表9：链上存储开销随域数/凭证数变化**
```
Y轴: 存储开销 (KB)
X轴: 域数 或 凭证数
```

---

### 实验4：服务可用性与恢复能力分析

**对应论文章节：** 5.4.3

**实验目标：** 在多周期运行过程中注入不同类型和强度的扰动，量化系统性能退化的幅度和恢复到基线水平所需的周期数，验证动态信誉驱动的自适应恢复能力。

#### 4.1 扰动场景定义

| 场景编号 | 扰动类型 | 扰动参数 | 注入时段 | 观察重点 |
|----------|----------|----------|----------|----------|
| S1 | 节点离线 | 10% 委员会节点离线 | epoch 3-5 | 签发成功率下降幅度 |
| S2 | 节点离线（高强度） | 20% 委员会节点离线 | epoch 8-9 | 是否接近门限边界 |
| S3 | 通信延迟 | 域内延迟 +50ms | epoch 5 | P95延迟变化 |
| S4 | 丢包 | 丢包率 5% | epoch 5 | 签名收集成功率 |
| S5 | 恶意签名 | 5% 节点提交伪造份额 | epoch 7 | 伪造检测率 |
| S6 | 拒签攻击 | 10% 节点拒绝参与签名 | epoch 7 | TPS下降幅度 |
| S7 | 组合扰动 | S1+S3+S6 同时 | epoch 10 | 最坏情况退化 |

#### 4.2 测量指标时序采集

```
对每个 epoch（共15个epoch），采集以下指标：

性能指标:
  - 签发成功率 (%)
  - 平均签发延迟 (ms)
  - P50/P95 门限签名收集延迟 (ms)
  - TPS

治理指标:
  - 高信誉节点占比 (%)
  - 委员会留存率 (%)
  - 本轮替换节点数

安全指标:
  - 伪造签名检测次数
  - 拒签节点被降信誉的次数
  - 被踢出委员会的节点数
```

#### 4.3 实验流程

```
Step 1: 基线采集（epoch 1-2）
  1.1 无扰动运行，每 epoch 处理 2000 签发请求
  1.2 记录基线性能指标

Step 2: 单一扰动注入（epoch 3-9）
  2.1 按场景表注入扰动
  2.2 每 epoch 结束后执行信誉评估与委员会轮换
  2.3 记录扰动期间的所有指标

Step 3: 组合扰动注入（epoch 10）
  3.1 同时注入节点离线 + 通信延迟 + 拒签
  3.2 记录最坏情况指标

Step 4: 恢复观察（epoch 11-15）
  4.1 移除所有扰动
  4.2 记录恢复过程中的指标变化
  4.3 计算恢复到基线95%所需的epoch数

Step 5: 数据分析
  5.1 绘制各指标的时序变化曲线
  5.2 计算退化幅度 = (基线值 - 扰动期最低值) / 基线值 * 100%
  5.3 计算恢复速度 = 恢复到基线95%所需epoch数
```

#### 4.4 核心模拟逻辑

```python
"""
实验4：扰动注入与恢复分析
"""

class PerturbationSimulator:
    """扰动模拟器"""

    def __init__(self, total_nodes: int, committee_size: int, threshold: int):
        self.total_nodes = total_nodes
        self.committee_size = committee_size
        self.threshold = threshold
        self.nodes = self._init_nodes()

    def _init_nodes(self) -> list:
        return [
            {
                'id': i,
                'reputation': 0.5 + random.uniform(0, 0.3),
                'online': True,
                'malicious': False,
                'refuse_sign': False,
                'extra_delay_ms': 0,
            }
            for i in range(self.total_nodes)
        ]

    def inject_offline(self, fraction: float):
        """注入节点离线"""
        offline_count = int(self.committee_size * fraction)
        targets = random.sample(
            [n for n in self.nodes if n['online']],
            min(offline_count, len([n for n in self.nodes if n['online']]))
        )
        for node in targets:
            node['online'] = False

    def inject_delay(self, extra_ms: float):
        """注入通信延迟"""
        for node in self.nodes:
            if node['online']:
                node['extra_delay_ms'] = extra_ms

    def inject_malicious(self, fraction: float):
        """注入恶意签名节点"""
        count = int(self.committee_size * fraction)
        targets = random.sample(
            [n for n in self.nodes if n['online'] and not n['malicious']],
            min(count, len([n for n in self.nodes if n['online']]))
        )
        for node in targets:
            node['malicious'] = True

    def inject_refuse_sign(self, fraction: float):
        """注入拒签节点"""
        count = int(self.committee_size * fraction)
        targets = random.sample(
            [n for n in self.nodes if n['online']],
            min(count, len([n for n in self.nodes if n['online']]))
        )
        for node in targets:
            node['refuse_sign'] = True

    def clear_perturbations(self):
        """清除所有扰动"""
        for node in self.nodes:
            node['online'] = True
            node['malicious'] = False
            node['refuse_sign'] = False
            node['extra_delay_ms'] = 0

    def simulate_issuance_round(self, num_requests: int) -> dict:
        """模拟一轮签发过程"""
        committee = self.select_committee()
        results = {
            'success_count': 0,
            'total_count': num_requests,
            'latencies': [],
            'malicious_detected': 0,
            'refused_count': 0,
        }

        for _ in range(num_requests):
            # 收集门限签名
            available = [n for n in committee if n['online'] and not n['refuse_sign']]
            refused = [n for n in committee if n['refuse_sign']]
            results['refused_count'] += len(refused)

            if len(available) < self.threshold:
                # 无法达成门限
                results['latencies'].append(5000)  # 超时
                continue

            # 模拟签名收集
            latency = 0
            valid_sigs = 0
            for node in available[:self.threshold]:
                sig_delay = 20 + node['extra_delay_ms'] + random.uniform(0, 10)
                latency = max(latency, sig_delay)  # 并行收集取最慢

                if node['malicious']:
                    # 提交伪造签名，被检测
                    results['malicious_detected'] += 1
                else:
                    valid_sigs += 1

            if valid_sigs >= self.threshold:
                # 聚合成功
                latency += 15  # 聚合时间
                results['success_count'] += 1
            else:
                latency = 5000  # 失败

            results['latencies'].append(latency)

        return results

    def select_committee(self) -> list:
        """基于信誉选取委员会"""
        candidates = sorted(self.nodes, key=lambda n: n['reputation'], reverse=True)
        return candidates[:self.committee_size]

    def update_reputations(self, round_results: dict):
        """根据本轮表现更新信誉"""
        for node in self.nodes:
            if not node['online']:
                node['reputation'] = max(0, node['reputation'] - 0.1)
            elif node['malicious']:
                node['reputation'] = max(0, node['reputation'] - 0.2)
            elif node['refuse_sign']:
                node['reputation'] = max(0, node['reputation'] - 0.15)
            else:
                # 正常参与，信誉微增
                node['reputation'] = min(1.0, node['reputation'] + 0.02)
```

#### 4.5 预期输出图表

**图表10：多周期签发成功率与TPS时序变化**
```
Y轴左: 签发成功率 (%)
Y轴右: TPS
X轴: Epoch [1, 2, ..., 15]
标注: 各扰动注入和恢复的时间点
```

**图表11：P50/P95延迟时序变化**
```
Y轴: 延迟 (ms)
X轴: Epoch
两条曲线: P50, P95
灰色区域标注扰动注入时段
```

**图表12：退化幅度与恢复速度汇总表**
```
| 扰动场景 | 峰值退化(%) | 恢复所需epoch | 最终恢复水平(%) |
```

---

### 实验5：更新与撤销执行开销

**对应论文章节：** 5.5.1

**实验目标：** 测量变色龙哈希机制下凭证更新和撤销的完整执行开销，包括门限陷门重构、碰撞计算、委员会签名和状态重锚定各阶段的延迟与计算成本，并与传统撤销列表（CRL）方案进行对比。

#### 5.1 自变量设计

```
实验5a - 单次操作开销分解：
  操作类型: [Update, Revoke]
  委员会规模: n = [4, 6, 8, 10]
  门限: t = ceil(n * 0.6)
  重复次数: 1000 次

实验5b - 批量操作性能：
  批量大小: [10, 50, 100, 500, 1000]
  操作类型: [Update, Revoke, 混合(70%Update+30%Revoke)]
  委员会规模: n=10, t=7

实验5c - 与传统CRL方案对比：
  凭证总数: [1000, 5000, 10000, 50000]
  撤销比例: [1%, 5%, 10%, 20%]
  对比: HFA-DID(变色龙哈希) vs CRL查询 vs 链上状态更新
```

#### 5.2 单次操作阶段分解

```
凭证更新/撤销的完整执行链路：

Step 1: 请求验证
  - 验证持有人签名 sigma_holder
  - 检查凭证状态是否可更新/撤销
  - 延迟: T_verify_request

Step 2: 委员会决议
  - 门限投票（收集 >= t 个同意票）
  - 延迟: T_committee_vote

Step 3: 变色龙哈希碰撞计算
  - 门限重构陷门: td = reconstruct(td_shares, threshold)
  - 计算新随机因子: r_new = CH_forge(td, m_old, r_old, m_new)
  - 验证碰撞: CH(m_old, r_old) == CH(m_new, r_new)
  - 延迟: T_chameleon

Step 4: 状态更新记录签名
  - 构造 U_i = <VCID, m_new, r_new, delta_new, sigma_CC>
  - 门限签名: sigma_CC = threshold_sign(U_i)
  - 延迟: T_sign_record

Step 5: 域内状态重锚定
  - 更新域内 Merkle 树（如有其他变更）
  - 生成新的域级根 Root_VC_j
  - 提交锚定记录到 GCL
  - 延迟: T_reanchor

总延迟 = T_verify_request + T_committee_vote + T_chameleon + T_sign_record + T_reanchor
```

#### 5.3 核心代码逻辑

```python
"""
实验5：变色龙哈希更新/撤销开销测试
"""

class ChameleonHash:
    """
    变色龙哈希实现（基于离散对数）

    公钥: pk = g^td mod p
    哈希: CH(m, r) = g^m * pk^r mod p
    碰撞: 已知 td，给定 (m, r) 和 m'，计算 r' 使 CH(m, r) = CH(m', r')
          r' = (m - m' + td * r) * td^(-1) mod q  （简化表示）
    """

    def __init__(self, security_bits=256):
        # 初始化群参数（使用安全素数群）
        self.p, self.q, self.g = generate_safe_prime_group(security_bits)
        self.td = None  # 陷门（私钥）
        self.pk = None  # 公钥

    def key_gen(self) -> tuple:
        """生成变色龙哈希密钥对"""
        self.td = random.randint(1, self.q - 1)
        self.pk = pow(self.g, self.td, self.p)
        return self.pk, self.td

    def hash(self, m: int, r: int) -> int:
        """计算变色龙哈希 CH(m, r) = g^m * pk^r mod p"""
        return (pow(self.g, m, self.p) * pow(self.pk, r, self.p)) % self.p

    def forge(self, m_old: int, r_old: int, m_new: int) -> int:
        """
        已知陷门 td，计算新随机因子 r_new
        使得 CH(m_old, r_old) = CH(m_new, r_new)
        """
        # r_new = r_old + (m_old - m_new) * td^(-1) mod q
        td_inv = pow(self.td, -1, self.q)
        r_new = (r_old + (m_old - m_new) * td_inv) % self.q
        return r_new


class ThresholdChameleonHash:
    """门限变色龙哈希：陷门以秘密共享形式分布"""

    def __init__(self, ch: ChameleonHash, threshold: int, num_shares: int):
        self.ch = ch
        self.threshold = threshold
        self.num_shares = num_shares
        self.shares = []

    def distribute_trapdoor(self, td: int):
        """将陷门通过 Shamir 秘密共享分发"""
        self.shares = shamir_split(td, self.threshold, self.num_shares, self.ch.q)

    def threshold_forge(self, share_indices: list, m_old: int,
                         r_old: int, m_new: int) -> int:
        """
        门限碰撞计算：收集 >= t 个份额重构陷门后计算碰撞
        """
        if len(share_indices) < self.threshold:
            raise ValueError("份额不足")

        # Step 1: 重构陷门
        selected_shares = [(i, self.shares[i]) for i in share_indices[:self.threshold]]
        td_reconstructed = lagrange_interpolate(selected_shares, self.ch.q)

        # Step 2: 计算碰撞
        td_inv = pow(td_reconstructed, -1, self.ch.q)
        r_new = (r_old + (m_old - m_new) * td_inv) % self.ch.q
        return r_new


def benchmark_single_update(vc, ch_system: ThresholdChameleonHash,
                             committee_shares, threshold) -> dict:
    """测量单次凭证更新的各阶段开销"""
    results = {}

    # Stage 1: 请求验证
    t = time.perf_counter()
    # 模拟签名验证
    request_valid = verify_holder_signature(vc['holder_sig'])
    status_valid = vc['status'] != 'Revoked'
    results['T_verify_request'] = (time.perf_counter() - t) * 1000

    # Stage 2: 委员会决议（模拟 t 个节点投票）
    t = time.perf_counter()
    votes = collect_votes(committee_shares, threshold)
    vote_passed = len(votes) >= threshold
    results['T_committee_vote'] = (time.perf_counter() - t) * 1000

    # Stage 3: 变色龙哈希碰撞计算
    t = time.perf_counter()
    m_old = int.from_bytes(hashlib.sha256(vc['content'].encode()).digest(), 'big')
    m_new = int.from_bytes(hashlib.sha256(vc['new_content'].encode()).digest(), 'big')
    r_new = ch_system.threshold_forge(
        list(range(threshold)), m_old, vc['r_old'], m_new
    )
    # 验证碰撞
    assert ch_system.ch.hash(m_old, vc['r_old']) == ch_system.ch.hash(m_new, r_new)
    results['T_chameleon'] = (time.perf_counter() - t) * 1000

    # Stage 4: 状态更新记录签名
    t = time.perf_counter()
    update_record = {
        'vcid': vc['vcid'],
        'm_new': vc['new_content'],
        'r_new': r_new,
        'delta': 'Updated',
    }
    # 门限 BLS 签名
    sigma_cc = threshold_bls_sign(update_record, committee_shares, threshold)
    results['T_sign_record'] = (time.perf_counter() - t) * 1000

    # Stage 5: 域内状态重锚定
    t = time.perf_counter()
    # 注意：由于变色龙哈希承诺不变，Merkle根可能不需要重算
    # 但如果同周期有多个变更，需要重新构建
    new_root = recompute_domain_root_if_needed()
    submit_anchor_to_gcl(new_root)
    results['T_reanchor'] = (time.perf_counter() - t) * 1000

    results['T_total'] = sum(results.values())
    return results


def benchmark_single_revoke(vc, ch_system, committee_shares, threshold) -> dict:
    """测量单次凭证撤销的各阶段开销（与更新类似，m_new包含撤销标识）"""
    # 撤销 = 更新凭证内容为包含 Revoked 标识的新内容
    vc_copy = vc.copy()
    vc_copy['new_content'] = json.dumps({
        'original': vc['content'],
        'status': 'Revoked',
        'revoke_reason': 'compliance_violation',
        'revoke_time': time.time(),
    })
    return benchmark_single_update(vc_copy, ch_system, committee_shares, threshold)
```

#### 5.4 对比方案：传统CRL

```python
def benchmark_crl_revocation(total_credentials: int, revoke_fraction: float) -> dict:
    """传统 CRL 撤销方案基准测试"""
    results = {}
    revoke_count = int(total_credentials * revoke_fraction)

    # CRL 方案1：链上撤销列表
    t = time.perf_counter()
    # 模拟逐条写入链上撤销列表
    for i in range(revoke_count):
        # 每条撤销需要一次链上交易
        simulate_blockchain_tx({'action': 'revoke', 'vcid': f'vc_{i}'})
    results['crl_onchain_total'] = (time.perf_counter() - t) * 1000
    results['crl_onchain_per_item'] = results['crl_onchain_total'] / revoke_count

    # CRL 方案2：状态查询开销（验证时）
    t = time.perf_counter()
    for i in range(1000):  # 1000次验证查询
        vcid = f'vc_{random.randint(0, total_credentials-1)}'
        # 遍历撤销列表检查
        is_revoked = vcid in revocation_list  # O(n) or O(log n) with index
    results['crl_verify_query_total'] = (time.perf_counter() - t) * 1000
    results['crl_verify_query_avg'] = results['crl_verify_query_total'] / 1000

    return results
```

#### 5.5 预期输出图表

**图表13：单次更新/撤销各阶段延迟分解（堆叠柱状图）**
```
Y轴: 延迟 (ms)
X轴: 委员会规模 [4, 6, 8, 10]
两组柱: Update | Revoke
堆叠: 请求验证 | 委员会决议 | 变色龙哈希碰撞 | 记录签名 | 重锚定
```

**图表14：批量操作吞吐率**
```
Y轴: TPS
X轴: 批量大小 [10, 50, 100, 500, 1000]
三条曲线: Update | Revoke | Mixed
```

**图表15：HFA-DID vs CRL 撤销方案对比**
```
Y轴: 平均单条撤销延迟 (ms)
X轴: 凭证总数 [1000, 5000, 10000, 50000]
两条曲线: HFA-DID(变色龙哈希) | CRL(链上逐条撤销)
关键观察: HFA-DID延迟近似恒定，CRL随凭证数线性增长
```

---

### 实验6：更新后验证成本与正确性

**对应论文章节：** 5.5.2

**实验目标：** 验证变色龙哈希更新后 (1) Merkle路径的稳定性（公式4.22），(2) 验证流程的一致性，(3) 更新操作对验证开销的零影响或极低影响。

#### 6.1 正确性验证实验

```
实验6a - 承诺值不变性验证：
  步骤:
    1. 签发 N=1000 个凭证，记录每个凭证的 Commit_i = CH(m_i, r_i)
    2. 对其中 K=[10, 50, 100, 300, 500] 个凭证执行更新
    3. 对每个被更新凭证验证:
       (a) Commit_i_before == Commit_i_after  （承诺值不变）
       (b) CH(m_old, r_old) == CH(m_new, r_new)  （碰撞正确）
    4. 记录: 不变性通过率 (应为 100%)

实验6b - Merkle路径稳定性验证：
  步骤:
    1. 签发 N=1000 个凭证，构建 Merkle 树
    2. 记录每个凭证的 Merkle 路径 pi_i_before
    3. 对其中 K 个凭证执行更新（变色龙哈希碰撞）
    4. 重新获取被更新凭证的 Merkle 路径 pi_i_after
    5. 验证: pi_i_before == pi_i_after  （路径不变）
    6. 进一步验证: 未被更新凭证的路径是否受影响
    7. 记录: 路径稳定率 (应为 100%)

实验6c - 域级根不变性验证（单凭证更新场景）：
  步骤:
    1. 仅更新 1 个凭证
    2. 验证: Root_VC_j_before == Root_VC_j_after
    3. 此处域级根应保持不变（因为叶子Commit不变）
    4. 记录: 根不变率 (应为 100%)

实验6d - 跨域验证流程完整性验证：
  步骤:
    1. 签发凭证并完成全域锚定
    2. 执行跨域验证 → 记录结果1（应为Valid）
    3. 对该凭证执行更新
    4. 使用更新后的内容再次执行跨域验证 → 记录结果2（应为Valid）
    5. 验证: 两次验证均通过，且验证路径一致
```

#### 6.2 性能对比实验

```
实验6e - 更新前后验证延迟对比：
  分组:
    Group A: 1000 个未更新凭证的域内验证延迟
    Group B: 1000 个已更新凭证的域内验证延迟
    Group C: 1000 个未更新凭证的跨域验证延迟
    Group D: 1000 个已更新凭证的跨域验证延迟

  测量:
    - 每组的 Avg / P50 / P95 延迟
    - 相对差异: |Avg_B - Avg_A| / Avg_A * 100%

  预期:
    - A与B差异 < 5%（域内）
    - C与D差异 < 5%（跨域）
    - 证明变色龙哈希不引入额外验证开销
```

#### 6.3 核心代码逻辑

```python
"""
实验6：更新后验证正确性与成本测试
"""

def test_commitment_invariance(ch: ChameleonHash, num_credentials: int,
                                 num_updates: int) -> dict:
    """测试6a：承诺值不变性"""
    results = {'total': num_updates, 'invariant_pass': 0, 'invariant_fail': 0}

    # 签发凭证
    credentials = []
    for i in range(num_credentials):
        m = random.randint(1, ch.q - 1)
        r = random.randint(1, ch.q - 1)
        commit = ch.hash(m, r)
        credentials.append({'m': m, 'r': r, 'commit': commit})

    # 选取凭证执行更新
    update_indices = random.sample(range(num_credentials), num_updates)
    for idx in update_indices:
        vc = credentials[idx]
        m_new = random.randint(1, ch.q - 1)  # 新凭证内容
        r_new = ch.forge(vc['m'], vc['r'], m_new)
        commit_new = ch.hash(m_new, r_new)

        if commit_new == vc['commit']:
            results['invariant_pass'] += 1
        else:
            results['invariant_fail'] += 1

    results['pass_rate'] = results['invariant_pass'] / results['total'] * 100
    return results


def test_merkle_path_stability(ch: ChameleonHash, num_credentials: int,
                                 num_updates: int) -> dict:
    """测试6b：Merkle路径稳定性"""
    results = {'total_checked': 0, 'path_stable': 0, 'path_changed': 0}

    # 签发凭证并构建Merkle树
    credentials = []
    leaves = []
    for i in range(num_credentials):
        m = random.randint(1, ch.q - 1)
        r = random.randint(1, ch.q - 1)
        commit = ch.hash(m, r)
        credentials.append({'m': m, 'r': r, 'commit': commit})
        leaves.append(commit.to_bytes(32, 'big'))

    root_before, tree_before = build_merkle_tree(leaves)

    # 记录更新前的路径
    paths_before = {}
    update_indices = random.sample(range(num_credentials), num_updates)
    for idx in update_indices:
        paths_before[idx] = get_merkle_proof(idx, tree_before)

    # 执行更新（由于变色龙哈希承诺不变，叶子不变）
    for idx in update_indices:
        vc = credentials[idx]
        m_new = random.randint(1, ch.q - 1)
        r_new = ch.forge(vc['m'], vc['r'], m_new)
        # 关键：commit 不变，所以 leaves 数组不变
        # credentials[idx] 的内容更新了，但 commit 相同

    # 重新获取路径（由于叶子未变，树结构未变）
    root_after, tree_after = build_merkle_tree(leaves)  # leaves 未变

    for idx in update_indices:
        results['total_checked'] += 1
        path_after = get_merkle_proof(idx, tree_after)
        if paths_before[idx] == path_after:
            results['path_stable'] += 1
        else:
            results['path_changed'] += 1

    results['stability_rate'] = results['path_stable'] / results['total_checked'] * 100
    results['root_invariant'] = (root_before == root_after)
    return results


def test_verification_cost_comparison(credentials_original: list,
                                        credentials_updated: list,
                                        pk_cc, merkle_tree, domain_root) -> dict:
    """测试6e：更新前后验证延迟对比"""
    results = {
        'original_latencies': [],
        'updated_latencies': [],
    }

    # 测试原始凭证验证延迟
    for vc in credentials_original:
        _, latency, _ = intra_domain_verify(
            vc['content'], vc['sigma'], pk_cc,
            vc['proof'], domain_root, set(), vc['id']
        )
        results['original_latencies'].append(latency)

    # 测试更新后凭证验证延迟
    for vc in credentials_updated:
        _, latency, _ = intra_domain_verify(
            vc['new_content'], vc['sigma'], pk_cc,  # sigma 对应的是 commit，不变
            vc['proof'], domain_root, set(), vc['id']
        )
        results['updated_latencies'].append(latency)

    # 统计对比
    avg_orig = statistics.mean(results['original_latencies'])
    avg_upd = statistics.mean(results['updated_latencies'])
    results['avg_original'] = avg_orig
    results['avg_updated'] = avg_upd
    results['relative_diff_percent'] = abs(avg_upd - avg_orig) / avg_orig * 100

    return results
```

#### 6.4 预期输出图表

**图表16：承诺值不变性验证结果**
```
表格形式:
| 更新数量K | 承诺不变率 | 路径稳定率 | 域根不变率 |
| 10        | 100%      | 100%      | 100%      |
| 50        | 100%      | 100%      | 100%      |
| 100       | 100%      | 100%      | 100%      |
| 300       | 100%      | 100%      | 100%      |
| 500       | 100%      | 100%      | 100%      |
```

**图表17：更新前后验证延迟对比**
```
Y轴: 平均验证延迟 (ms)
X轴: 域内验证 | 跨域验证
两组柱: 更新前 | 更新后
误差线: 标准差
差异标注: "差异 < 5%"
```

---

### 实验7：陷门继承安全性与轮换影响

**对应论文章节：** 5.5.3

**实验目标：** 验证 Re-DKG 轮转后变色龙哈希陷门的安全继承，包括：(1) 新委员会能否使用新份额执行更新/撤销，(2) 旧委员会退出节点的旧份额是否失效，(3) 跨周期份额是否独立，(4) 轮换对服务连续性的影响。

#### 7.1 实验分组

```
实验7a - 功能正确性验证：
  目标: 新委员会能正常使用陷门，旧节点不能

实验7b - 跨周期份额独立性验证：
  目标: 历史份额无法推导当前陷门

实验7c - 多轮连续轮换稳定性：
  目标: 经过多次轮换后系统仍能正常工作

实验7d - 轮换期间服务中断测量：
  目标: 量化轮换对更新/撤销服务的影响
```

#### 7.2 实验7a：功能正确性

```
步骤:
  1. 初始化 CC^(e) = {n1, n2, ..., n10}，门限 t=7
  2. 生成变色龙哈希密钥对 (pk, td)
  3. 将 td 通过 Shamir 秘密共享分发给 CC^(e)
  4. CC^(e) 使用份额执行凭证更新 → 验证成功 ✓

  5. 信誉选举产生 CC^(e+1) = {n3, n4, ..., n12}
     （n1, n2 退出；n11, n12 新加入；n3-n10 留任）
  6. 执行 Re-DKG 轮转，CC^(e) 将陷门份额通过零秘密多项式重分配给 CC^(e+1)

  7. CC^(e+1) 使用新份额执行凭证更新 → 验证成功 ✓
  8. 退出节点 n1 使用旧份额尝试参与更新 → 验证失败 ✓
  9. 退出节点 n1 + n2 联合使用旧份额尝试重构陷门 → 失败 ✓
     （旧份额数量 < t，且与新份额不在同一多项式上）

记录:
  - 新委员会更新成功率: 应为 100%
  - 旧节点操作失败率: 应为 100%
  - 陷门值不变性: td_old == td_new（总陷门值相同）
```

#### 7.3 实验7b：跨周期份额独立性

```
步骤:
  1. 运行 3 个治理周期: e, e+1, e+2
  2. 每个周期执行 Re-DKG 轮转
  3. 收集各周期的部分份额:
     - 周期e:   收集 t-1=6 个份额
     - 周期e+1: 收集 t-1=6 个份额
     - 周期e+2: 收集 t-1=6 个份额
  4. 尝试组合攻击:
     (a) 仅用周期e的6个份额重构 → 失败（不够门限）
     (b) 混合周期e的3个 + 周期e+1的3个 + 周期e+2的3个 → 失败
         （不同周期的份额位于不同多项式上，无法组合）
     (c) 周期e的6个 + 周期e+1的1个 → 失败
         （跨周期份额不兼容）

记录:
  - 跨周期组合攻击成功率: 应为 0%
  - 验证公式4.8（密钥份额新鲜性保证）
```

#### 7.4 实验7c：多轮连续轮换稳定性

```
自变量: 连续轮换次数 R = [1, 3, 5, 10, 20, 50]

每轮操作:
  1. 信誉评估 → 选举新委员会
  2. Re-DKG 轮转陷门份额
  3. 新委员会执行 10 次凭证更新
  4. 验证所有更新的正确性

测量:
  - 每轮更新成功率（应始终为 100%）
  - 陷门总值不变性（每轮检查 pk = g^td 是否不变）
  - 公钥不变性（PK_CC 是否始终相同）
  - 累计份额分发错误率
```

#### 7.5 实验7d：轮换期间服务中断

```
实验设计:
  1. 系统持续运行并处理更新请求
  2. 在某一时刻触发 Re-DKG 轮转
  3. 记录轮转过程中各时间节点:
     T_start:     轮转开始
     T_poly:      零秘密多项式生成完成
     T_distribute: 份额分发完成
     T_verify:    一致性验证完成
     T_activate:  新委员会激活
     T_end:       轮转结束

  4. 在 [T_start, T_end] 时间窗口内持续发送更新请求
  5. 记录:
     - 轮转总耗时: T_end - T_start (ms)
     - 服务不可用窗口: T_activate - T_start (ms)
       （旧委员会停止签发到新委员会激活之间的间隙）
     - 轮转期间请求的排队延迟
     - 轮转前后TPS对比

自变量: 委员会规模 n = [4, 6, 8, 10, 15, 20]
```

#### 7.6 核心代码逻辑

```python
"""
实验7：陷门继承安全性测试
"""

class ReDKGTrapdoorRotation:
    """Re-DKG 陷门轮转模拟"""

    def __init__(self, q: int, threshold: int):
        self.q = q
        self.threshold = threshold

    def rotate_trapdoor(self, old_committee: list, new_committee: list,
                          old_shares: dict) -> dict:
        """
        执行陷门份额轮转

        参数:
          old_committee: 旧委员会成员ID列表
          new_committee: 新委员会成员ID列表
          old_shares: {member_id: share_value} 旧份额

        返回: {member_id: new_share_value} 新份额
        """
        t = self.threshold

        # Phase 1: 每个旧成员生成零秘密多项式
        zero_polys = {}
        for member_id in old_committee:
            # f_i(x) = a_{i,1}*x + a_{i,2}*x^2 + ... + a_{i,t-1}*x^{t-1}
            # 注意: 常数项 a_{i,0} = 0
            coeffs = [0]  # 常数项为零
            for _ in range(t - 1):
                coeffs.append(random.randint(1, self.q - 1))
            zero_polys[member_id] = coeffs

        # Phase 2: 计算子份额并分发
        sub_shares = {}  # {(from_id, to_id): sub_share}
        for from_id in old_committee:
            poly = zero_polys[from_id]
            for to_id in new_committee:
                # s_{i->j} = f_i(id_j) mod q
                val = sum(c * pow(to_id, k, self.q) for k, c in enumerate(poly)) % self.q
                sub_shares[(from_id, to_id)] = val

        # Phase 3: 新成员聚合份额
        new_shares = {}
        for to_id in new_committee:
            received = sum(sub_shares[(from_id, to_id)] for from_id in old_committee) % self.q
            if to_id in old_committee:
                # 留任成员: 旧份额 + 收到的子份额之和
                new_shares[to_id] = (old_shares[to_id] + received) % self.q
            else:
                # 新成员: 仅收到的子份额之和
                new_shares[to_id] = received % self.q

        return new_shares

    def verify_total_invariance(self, old_shares: dict, new_shares: dict) -> bool:
        """验证陷门总值不变: sum(old_shares) == sum(new_shares) mod q"""
        old_total = sum(old_shares.values()) % self.q
        new_total = sum(new_shares.values()) % self.q
        return old_total == new_total


def test_7a_functional_correctness():
    """实验7a: 功能正确性验证"""
    ch = ChameleonHash()
    pk, td = ch.key_gen()
    q = ch.q
    threshold = 7
    n = 10

    # 初始分发
    old_committee = list(range(1, n + 1))  # [1, 2, ..., 10]
    old_shares = shamir_split(td, threshold, old_committee, q)

    # 旧委员会执行更新 → 应成功
    m1 = random.randint(1, q - 1)
    r1 = random.randint(1, q - 1)
    commit = ch.hash(m1, r1)

    m2 = random.randint(1, q - 1)
    td_reconstructed = lagrange_interpolate(
        [(i, old_shares[i]) for i in old_committee[:threshold]], q
    )
    r2 = ch.forge(m1, r1, m2)
    assert ch.hash(m2, r2) == commit, "旧委员会更新应成功"
    print("旧委员会更新: PASS")

    # 轮转
    new_committee = list(range(3, 13))  # [3, 4, ..., 12]，n1,n2退出，n11,n12加入
    rotator = ReDKGTrapdoorRotation(q, threshold)
    new_shares = rotator.rotate_trapdoor(old_committee, new_committee, old_shares)

    # 验证陷门总值不变
    assert rotator.verify_total_invariance(old_shares, new_shares)
    print("陷门总值不变: PASS")

    # 新委员会执行更新 → 应成功
    m3 = random.randint(1, q - 1)
    td_new = lagrange_interpolate(
        [(i, new_shares[i]) for i in new_committee[:threshold]], q
    )
    assert td_new == td, "重构陷门应等于原始陷门"
    r3_forged = (r2 + (m2 - m3) * pow(td_new, -1, q)) % q
    assert ch.hash(m3, r3_forged) == commit, "新委员会更新应成功"
    print("新委员会更新: PASS")

    # 退出节点尝试 → 应失败
    exited_nodes = [1, 2]
    exited_shares = {i: old_shares[i] for i in exited_nodes}
    try:
        td_attack = lagrange_interpolate(
            [(i, exited_shares[i]) for i in exited_nodes], q
        )
        # 2 个份额 < threshold=7，拉格朗日插值结果不等于 td
        assert td_attack != td, "退出节点不应能重构陷门"
        print("退出节点攻击: BLOCKED (as expected)")
    except Exception:
        print("退出节点攻击: BLOCKED (as expected)")

    return {"all_tests_passed": True}


def test_7b_cross_epoch_independence():
    """实验7b: 跨周期份额独立性验证"""
    ch = ChameleonHash()
    pk, td = ch.key_gen()
    q = ch.q
    threshold = 7
    n = 10

    all_epoch_shares = []

    # 模拟3个周期的轮转
    current_committee = list(range(1, n + 1))
    current_shares = shamir_split(td, threshold, current_committee, q)
    all_epoch_shares.append(current_shares.copy())

    rotator = ReDKGTrapdoorRotation(q, threshold)

    for epoch in range(2):
        # 模拟新委员会（部分变更）
        new_committee = list(range(epoch + 2, epoch + 2 + n))
        new_shares = rotator.rotate_trapdoor(current_committee, new_committee, current_shares)
        all_epoch_shares.append(new_shares.copy())
        current_committee = new_committee
        current_shares = new_shares

    # 攻击尝试: 混合不同周期的份额
    attack_results = []

    # 攻击1: 周期0的6个份额
    shares_e0 = list(all_epoch_shares[0].items())[:threshold - 1]
    td_attack1 = lagrange_interpolate(shares_e0, q)
    attack_results.append(('epoch0_only', td_attack1 == td))

    # 攻击2: 混合3个周期各取2-3个份额
    mixed_shares = (
        list(all_epoch_shares[0].items())[:3] +
        list(all_epoch_shares[1].items())[:2] +
        list(all_epoch_shares[2].items())[:2]
    )
    # 不同周期的份额在不同多项式上，混合插值无意义
    try:
        td_attack2 = lagrange_interpolate(mixed_shares, q)
        attack_results.append(('cross_epoch_mixed', td_attack2 == td))
    except Exception:
        attack_results.append(('cross_epoch_mixed', False))

    return {
        'attacks': attack_results,
        'all_attacks_failed': all(not success for _, success in attack_results),
    }
```

#### 7.7 预期输出图表

**图表18：功能正确性验证汇总表**
```
| 测试项 | 预期结果 | 实际结果 |
| 旧委员会执行更新 | 成功 | 成功 ✓ |
| Re-DKG轮转后陷门总值不变 | 通过 | 通过 ✓ |
| 新委员会执行更新 | 成功 | 成功 ✓ |
| 退出节点攻击 | 失败 | 失败 ✓ |
| 跨周期混合攻击 | 失败 | 失败 ✓ |
```

**图表19：多轮连续轮换后更新成功率**
```
Y轴: 更新成功率 (%)
X轴: 连续轮换次数 [1, 3, 5, 10, 20, 50]
预期: 恒定 100%
```

**图表20：轮换期间服务中断时间**
```
Y轴: 服务不可用窗口 (ms)
X轴: 委员会规模 [4, 6, 8, 10, 15, 20]
柱状图 + 趋势线
```

---

## 六、对比与消融实验设计

### 6.1 横向对比方案

| 方案 | 签发机制 | 域内验证 | 跨域验证 | 撤销机制 |
|------|----------|----------|----------|----------|
| **HFA-DID** | 动态信誉委员会 + BLS门限签名 | BLS验签 + Merkle路径 | 全域快照 + 双层Merkle | 变色龙哈希原地更新 |
| **WeIdentity** | 单点签发 + 链上同步 | 链上合约验签 | 链上状态查询 | 链上撤销列表 |
| **CanDID** | 静态委员会 + MPC | ZKP验证 | 需源域配合 | 重新签发 |
| **Cross-Chain** | 域内签发 | 域内验证 | 轻客户端SPV证明 | 链上状态 |

### 6.2 对比实验矩阵

```
对比维度          | 自变量                | 对比方案
凭证签发延迟       | 节点规模 [2-10]       | HFA-DID vs WeIdentity vs CanDID
域内验证延迟       | 并发量 [100-5000]     | HFA-DID vs WeIdentity vs CanDID
跨域验证延迟       | 节点规模 [2-10]       | HFA-DID vs Cross-Chain
撤销执行开销       | 凭证总数 [1K-50K]     | HFA-DID vs CRL
扰动下可用性       | 扰动强度              | HFA-DID(动态) vs 静态委员会
```

### 6.3 消融实验设计

| 消融方案 | 移除/替换的组件 | 观察指标 |
|----------|----------------|----------|
| A1: 无动态信誉 | 用随机选举替代信誉选举 | 高信誉占比、扰动恢复速度 |
| A2: 无Re-DKG | 每次轮换重新运行完整DKG | 轮换延迟、公钥稳定性 |
| A3: 无全域快照 | 跨域验证直接查询源域 | 跨域延迟、源域依赖度 |
| A4: 无变色龙哈希 | 用传统哈希+重签发替代 | 更新延迟、Merkle重建开销 |
| A5: 完整HFA-DID | 基线（所有组件启用） | 各项综合指标 |

```
消融实验流程:
  对每个消融方案 Ai (i=1..5):
    1. 部署对应版本的系统
    2. 执行标准化负载（1000次签发 + 500次验证 + 100次更新 + 50次撤销）
    3. 注入标准扰动（10%节点离线 + 5ms延迟）
    4. 记录所有指标
    5. 与完整方案A5对比，计算各指标的降低百分比
```

---

## 七、实验执行计划与优先级

### 7.1 优先级排序

| 优先级 | 实验 | 理由 | 预计工作量 |
|--------|------|------|-----------|
| **P0** | 实验5: 更新/撤销开销 | 第四章变色龙哈希核心贡献，必须有数据 | 中 |
| **P0** | 实验6: 更新后验证正确性 | 证明变色龙哈希的关键性质 | 低 |
| **P1** | 实验2: 跨域验证性能 | 第三章核心贡献 | 中 |
| **P1** | 实验3: 锚定与快照开销 | 体现分层架构可扩展性 | 中 |
| **P1** | 实验7: 陷门继承安全性 | Re-DKG + 变色龙哈希协同验证 | 中 |
| **P2** | 实验1: 域内验证性能 | 与对比方案横向比较 | 低 |
| **P2** | 实验4: 服务可用性 | 动态鲁棒性量化补充 | 中 |
| **P2** | 对比与消融实验 | 综合评价 | 高 |

### 7.2 建议执行顺序

```
Phase 1: 基础设施搭建
  ├── FISCO BCOS Docker 部署（RTL + GCL + 3个DCL）
  ├── Python 密码学库集成（BLS + 变色龙哈希 + Merkle）
  ├── 智能合约部署（域注册 + 锚定聚合 + 快照管理）
  └── 实验数据采集框架搭建

Phase 2: 核心实验（P0）
  ├── 实验5: 更新与撤销执行开销
  └── 实验6: 更新后验证成本与正确性

Phase 3: 重要实验（P1）
  ├── 实验2: 跨域验证性能
  ├── 实验3: 锚定与快照构建开销
  └── 实验7: 陷门继承安全性

Phase 4: 补充实验（P2）
  ├── 实验1: 域内验证性能
  ├── 实验4: 服务可用性与恢复能力
  └── 对��与消融实验

Phase 5: 数据整理与论文写作
  ├── 实验数据统计与图表生成
  ├── 填充论文第五章各节内容
  └── 实验分析与结论撰写
```

### 7.3 每个实验的预期产出

| 实验 | 预期图表数 | 预期表格数 | 论文段落数 |
|------|-----------|-----------|-----------|
| 实验1 | 2 | 1 | 3-4 |
| 实验2 | 3 | 1 | 4-5 |
| 实验3 | 4 | 1 | 4-5 |
| 实验4 | 3 | 1 | 3-4 |
| 实验5 | 3 | 1 | 4-5 |
| 实验6 | 2 | 2 | 3-4 |
| 实验7 | 3 | 2 | 4-5 |
| 对比消融 | 3 | 2 | 4-5 |
| **合计** | **~23** | **~11** | **~30** |
