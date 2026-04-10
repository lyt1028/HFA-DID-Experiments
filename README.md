# HFA-DID-Experiments

**HFA-DID: Hierarchical Federated Architecture for Decentralized Identity**

面向跨域的分布式数字身份关键技术研究 — 实验代码仓库

## 目录

- [项目简介](#项目简介)
- [系统架构](#系统架构)
- [环境要求](#环境要求)
- [安装与配置](#安装与配置)
- [实验说明](#实验说明)
- [运行方式](#运行方式)
- [Docker 网络仿真](#docker-网络仿真)
- [目录结构](#目录结构)
- [实验结果](#实验结果)

---

## 项目简介

本项目是 HFA-DID（分层联邦身份认证架构）论文的完整实验实现，集成了：

- **BLS12-381 门限签名**：凭证签发与锚定背书
- **变色龙哈希**：凭证可验证更新与撤销
- **Merkle 状态树**：域内凭证状态承诺与跨域全域快照
- **Re-DKG 密钥轮换**：委员会变更时的密钥安全继承
- **多维信誉模型**：动态委员会选举与自适应门限调整
- **FISCO BCOS 区块链集成**：4 节点 PBFT 共识的链上锚定与验证

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    RTL (Root Trust Layer)                    │
│            BLS 门限背书 + 全域快照签名                        │
└────────────────────────┬────────────────────────────────────┘
                         │ 锚定 (Merkle Root + BLS Sig)
┌────────────────────────┴────────────────────────────────────┐
│                    GCL (Global Coordination Layer)           │
│            全域 Merkle 聚合 + 跨域验证路由                    │
│            FISCO BCOS 4-node PBFT 共识网络                   │
└───┬──────────────┬──────────────┬──────────────┬────────────┘
    │              │              │              │
┌───┴───┐    ┌─────┴───┐    ┌────┴────┐    ┌────┴────┐
│ DCL-A │    │  DCL-B  │    │  DCL-C  │    │  ...    │
│域内委员会│   │域内委员会│   │域内委员会│    │         │
│凭证管理 │   │凭证管理  │   │凭证管理  │    │         │
└───────┘    └─────────┘    └─────────┘    └─────────┘
```

## 环境要求

### 软件版本

| 组件 | 版本 | 说明 |
|------|------|------|
| **操作系统** | Ubuntu 22.04 LTS | 推荐，也支持其他 Linux 发行版 |
| **Python** | 3.10+ | 建议 3.10.12 |
| **FISCO BCOS** | 2.11.1 | 4 节点本地集群，仅链上实验需要 |
| **FISCO Python SDK** | 最新版 | 路径默认 `/root/python-sdk` |
| **Docker** | 20.10+ | 仅网络仿真实验需要 |
| **Docker Compose** | v2.0+ | 仅网络仿真实验需要 |

### 硬件建议

| 资源 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 2 核 | 4 核+ |
| 内存 | 4 GB | 8 GB+ |
| 磁盘 | 10 GB | 20 GB+ |

> **注意**: BLS12-381 运算使用 `py_ecc` 纯 Python 实现，计算密集。首次运行 BLS 签名约需数秒预热。

### Python 依赖

```
py_ecc>=7.0.0          # BLS12-381 椭圆曲线运算
pycryptodome>=3.19     # 密码学原语 (AES, SHA, RSA)
numpy>=1.24            # 数值计算
matplotlib>=3.7        # 图表绘制
pandas>=2.0            # 数据处理
scipy>=1.10            # 统计分析
```

---

## 安装与配置

### 1. 克隆仓库

```bash
git clone https://github.com/lyt1028/HFA-DID-Experiments.git
cd HFA-DID-Experiments
```

### 2. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 3. 配置 FISCO BCOS（链上实验需要）

> 如果只需运行链下模式（`--no-chain`），可跳过此步骤。

#### 3.1 部署 FISCO BCOS 网络

```bash
# 下载建链脚本
cd ~ && mkdir -p fisco && cd fisco
curl -#LO https://github.com/FISCO-BCOS/FISCO-BCOS/releases/download/v2.11.1/build_chain.sh
chmod +x build_chain.sh

# 构建 4 节点本地集群 (PBFT 共识)
bash build_chain.sh -l 127.0.0.1:4 -p 30300,20200,8545

# 启动所有节点
bash nodes/127.0.0.1/start_all.sh

# 验证节点运行状态（应看到 4 个 fisco-bcos 进程）
ps aux | grep fisco-bcos | grep -v grep
```

节点端口分配：

| 节点 | P2P 端口 | Channel 端口 | RPC 端口 |
|------|----------|-------------|----------|
| node0 | 30300 | 20200 | 8545 |
| node1 | 30301 | 20201 | 8546 |
| node2 | 30302 | 20202 | 8547 |
| node3 | 30303 | 20203 | 8548 |

#### 3.2 安装 FISCO Python SDK

```bash
cd ~
git clone https://github.com/FISCO-BCOS/python-sdk.git
cd python-sdk
pip install -r requirements.txt

# 复制节点证书到 SDK
cp ~/fisco/nodes/127.0.0.1/sdk/* bin/

# 验证 SDK 连接
python console.py getNodeVersion
```

#### 3.3 部署智能合约

项目使用两个 Solidity 智能合约，ABI 文件在 `src/chain/contracts/` 目录：

- **CredentialRegistry**：凭证注册、状态查询、域根锚定
- **CommitteeGovernance**：委员会治理、成员变更记录

通过 FISCO Python SDK 控制台部署合约后，将地址写入项目根目录：

```bash
cat > contract_addresses.json << EOF
{
  "CredentialRegistry": "<部署后的合约地址>",
  "CommitteeGovernance": "<部署后的合约地址>"
}
EOF
```

> 仓库中已有的 `contract_addresses.json` 仅对原始实验服务器有效，复现时需重新部署合约。

---

## 实验说明

### 核心实验（EXP1-EXP7）

| 实验 | 脚本 | 论文章节 | 内容 | 优先级 |
|------|------|----------|------|--------|
| EXP1 | `exp1_intra_domain.py` | §5.3.2 | 域内验证性能（BLS 聚合验签 + Merkle 路径验证） | P2 |
| EXP2 | `exp2_cross_domain.py` | §5.3.3 | 跨域验证性能（全域快照机制 vs SPV 轻客户端） | P1 |
| EXP3 | `exp3_anchoring.py` | §5.3.4 | 锚定与快照构建开销（DCL→GCL→RTL 三阶段分解） | P1 |
| EXP4 | `exp4_availability.py` | §5.4.3 | 服务可用性与恢复（信誉驱动的自适应恢复能力） | P2 |
| EXP5 | `exp5_update_revoke.py` | §5.5.1 | 凭证更新/撤销执行开销（变色龙哈希 vs CRL） | **P0** |
| EXP6 | `exp6_correctness.py` | §5.5.2 | 更新后验证正确性（承诺不变性、Merkle 路径稳定性） | **P0** |
| EXP7 | `exp7_redkg.py` | §5.5.3 | Re-DKG 陷门继承安全性与多轮轮换稳定性 | P1 |

### 补充实验

| 实验 | 脚本 | 内容 |
|------|------|------|
| EXP8 | `exp8_multiprocess.py` | 多进程并发性能测试 |
| EXP8-Net | `exp8_network_simulation.py` | 网络延迟注入仿真 |
| EXP9 | `exp9_availability_*.py` | 可用性对比实验（多版本迭代） |

### 论文投稿补充实验（`experiments_paper/`）

| 实验 | 脚本 | 内容 |
|------|------|------|
| 跨域全流程 | `exp2_cross_full.py` | 扩展至 30 域的大规模跨域验证 |
| 信誉评估 | `exp4_reputation.py` | 多维信誉模型有效性验证 |
| 自适应门限 | `exp9_adaptive_threshold.py` | 自适应门限 t(e) = clamp(⌈n·(t_base + μν)⌉, t_min, t_max) |
| 多场景门限 | `exp9_multi_scenario.py` | 固定高/固定低/自适应三种策略对比 |
| 移动性攻击 | `exp10_mobile_attack.py` | 移动性合谋攻击防御量化（三层防御累加效果） |
| Re-DKG 路径 | `exp_redkg_path.py` | 乐观路径 vs 完整路径性能对比 |
| 端到端跨域 | `e2e/e2e_cross_domain_experiment.py` | 端到端跨域验证全流程 |
| 策略攻击 | `e2e/exp6b_strategic_attack.py` | 策略性攻击行为仿真 |

---

## 运行方式

### 快速验证（链下，无需区块链）

```bash
python run_experiments.py quick
```

此命令用小参数跑通全部密码学组件：Shamir 秘密共享 → Merkle 树 → 变色龙哈希碰撞 → Re-DKG 轮转 → BLS 门限签名。

### 运行单个实验

```bash
# 链上模式（需要 FISCO BCOS 节点运行中）
python run_experiments.py exp1

# 纯链下模式（跳过所有链上操作，仅测密码学计算开销）
python run_experiments.py --no-chain exp1
```

### 按优先级批量运行

```bash
# P0（论文核心贡献验证）: EXP5 + EXP6
python run_experiments.py p0

# P1: EXP2 + EXP3 + EXP7
python run_experiments.py p1

# P2: EXP1 + EXP4
python run_experiments.py p2

# 全部 7 个实验
python run_experiments.py all

# 全部实验，链下模式
python run_experiments.py --no-chain all
```

### 运行论文投稿补充实验

```bash
cd experiments_paper

# 自适应门限实验
python exp9_adaptive_threshold.py

# 移动性攻击防御
python exp10_mobile_attack.py

# 跨域全流程（扩展至 30 域）
python exp2_cross_full.py

# Re-DKG 乐观路径 vs 完整路径
python exp_redkg_path.py

# 信誉模型验证
python exp4_reputation.py

# 端到端跨域验证
python e2e/e2e_cross_domain_experiment.py
```

### 链上实验专用脚本

```bash
# 确保 FISCO BCOS 节点已启动
bash ~/fisco/nodes/127.0.0.1/start_all.sh

# EXP5 链上（并行版本）
python run_exp5a_parallel.py

# EXP5 链上
python run_exp5_chain.py

# EXP6 链上
python run_exp6_chain.py
```

---

## Docker 网络仿真

使用 Docker 容器模拟真实多域网络拓扑，通过 `tc netem` 注入网络延迟、抖动和丢包。

### 网络拓扑

```
Verifier (172.20.0.100)  ─── WAN ───>  GCL (172.20.0.20)  ─── LAN ───>  RTL (172.20.0.10)
                                        │
                                        ├─── MAN ───>  DCL-A (172.20.0.30)
                                        ├─── MAN ───>  DCL-B (172.20.0.40)
                                        └─── WAN ───>  DCL-C (172.20.0.50)
```

### 网络延迟配置

| 链路类型 | 典型场景 | 基准延迟 | 抖动 | 丢包率 |
|----------|----------|----------|------|--------|
| LAN | 域内通信 | 1ms | ±0.5ms | 0% |
| MAN | 同区域跨域 | 10ms | ±3ms | 0.1% |
| WAN | 广域跨域 | 50ms | ±15ms | 0.5% |

### 启动步骤

```bash
cd docker

# 1. 构建镜像
docker build -t hfa-did-node .

# 2. 启动容器（5 节点拓扑）
docker compose up -d

# 3. 注入网络延迟
bash setup_network.sh

# 4. 批量运行不同网络配置
bash run_all_profiles.sh

# 5. 扩展规模测试（可选）
docker compose -f docker-compose-scale.yml up -d

# 停止所有容器
docker compose down
```

---

## 目录结构

```
HFA-DID-Experiments/
├── run_experiments.py             # 实验统一入口
├── run_exp5_chain.py              # EXP5 链上运行脚本
├── run_exp5a_parallel.py          # EXP5 链上并行版
├── run_exp6_chain.py              # EXP6 链上运行脚本
├── requirements.txt               # Python 依赖
├── contract_addresses.json        # FISCO BCOS 合约部署地址
│
├── src/                           # 核心源代码
│   ├── crypto/                    # 密码学原语
│   │   ├── bls_threshold.py       #   BLS12-381 门限签名 (py_ecc)
│   │   ├── chameleon_hash.py      #   变色龙哈希 (离散对数构造)
│   │   ├── merkle.py              #   Merkle 状态树与证明
│   │   ├── redkg.py               #   Re-DKG 密钥轮换协议
│   │   └── shamir.py              #   Shamir 秘密共享
│   ├── models/                    # 系统模型
│   │   ├── committee.py           #   委员会选举与管理
│   │   ├── reputation.py          #   多维信誉评估模型
│   │   └── adaptive_threshold.py  #   自适应门限调整模型
│   ├── chain/                     # 区块链交互层
│   │   ├── fisco_client.py        #   FISCO BCOS Python SDK 封装
│   │   └── contracts/             #   智能合约 ABI 文件
│   │       ├── CredentialRegistry.abi
│   │       └── CommitteeGovernance.abi
│   └── utils.py                   # 工具 (ExperimentResult, Timer)
│
├── experiments/                   # 核心实验脚本
│   ├── exp1_intra_domain.py       #   EXP1: 域内验证性能
│   ├── exp2_cross_domain.py       #   EXP2: 跨域验证性能
│   ├── exp3_anchoring.py          #   EXP3: 锚定与快照开销
│   ├── exp4_availability.py       #   EXP4: 服务可用性
│   ├── exp5_update_revoke.py      #   EXP5: 更新/撤销开销
│   ├── exp6_correctness.py        #   EXP6: 更新后正确性
│   ├── exp7_redkg.py              #   EXP7: Re-DKG 安全性
│   ├── exp8_multiprocess.py       #   EXP8: 多进程性能
│   ├── exp8_network_simulation.py #   EXP8: 网络仿真
│   └── exp9_availability_*.py     #   EXP9: 可用性对比
│
├── experiments_paper/             # 论文投稿补充实验
│   ├── e2e/                       #   端到端实验
│   ├── exp*.py                    #   各项补充实验
│   └── plot_*.py                  #   论文图表绘制
│
├── docker/                        # Docker 网络仿真
│   ├── Dockerfile                 #   Python 运行环境
│   ├── docker-compose.yml         #   5 容器拓扑定义
│   ├── docker-compose-scale.yml   #   扩展规模配置
│   ├── node_service.py            #   节点 Flask REST API
│   ├── setup_network.sh           #   tc netem 延迟注入
│   └── run_all_profiles.sh        #   批量配置运行
│
├── plots/                         # 绘图
│   ├── hfadid_plot/               #   绘图脚本集合
│   ├── exp8/                      #   EXP8 专用绘图
│   └── output/                    #   输出图表 (PDF/PNG)
│
├── results/                       # 实验结果 JSON (自动生成)
└── fonts/                         # 中文绘图字体 (文泉驿微米黑)
```

---

## 实验结果

实验结果以 JSON 格式自动保存在 `results/` 目录，命名格式为 `EXP{id}_{YYYYMMDD_HHMMSS}.json`。

每个结果文件包含：

```json
{
  "experiment_id": "EXP1a",
  "experiment_name": "Intra-domain verification latency",
  "params": {
    "committee_size": 6,
    "num_credentials": 1000
  },
  "latency_ms": 12.5,
  "success_count": 1000,
  "p50_ms": 11.2,
  "p95_ms": 18.7,
  "extra": {},
  "timestamp": "2026-03-09T15:33:37"
}
```

### 生成图表

```bash
# 综合绘图（全部实验）
cd plots/hfadid_plot
python plot_all.py

# 单独绘制
python plot_anchoring.py           # 锚定策略开销分析
python plot_candid_compare.py      # 与 CanDID 方案对比
python plot_intra_verify.py        # 域内验证对比
python plot_cross_verify.py        # 跨域验证对比

# 论文投稿图表
cd experiments_paper
python plot_fig4_updated.py        # 图4: 核心操作性能
python plot_fig5_combined.py       # 图5: 跨域验证对比
python plot_exp9_10.py             # 自适应门限 + 攻击防御
```

---

## 核心参数说明

| 参数 | 符号 | 默认值 | 说明 |
|------|------|--------|------|
| 委员会规模 | n | 6 | 域内签发委员会节点数 |
| 签名门限 | t | ⌊n/2⌋+1 | BLS 门限签名与陷门重构所需最少份额数 |
| 变色龙哈希安全参数 | ch_bits | 128 | 位数越大越安全但越慢 |
| 信誉衰减因子 | δ | 0.8 | 历史行为权重的指数衰减系数 |
| 信誉剔除阈值 | θ | 0.6 | 低于此值的节点将被标记/剔除 |
| Re-DKG 留存率阈值 | ρ_th | 0.7 | 高于此值触发乐观路径（通信 O(|Δ|·n)） |
| 自适应门限基线 | t_base | 0.5 | 门限的基础比例 |
| 门限波动系数 | μ | 0.3 | 信誉变异系数对门限调整的影响权重 |

---

## 许可证

本项目仅用于学术研究，请勿用于商业用途。

## 联系方式

如有问题或建议，请联系 lyt1028（360444150@qq.com）。
