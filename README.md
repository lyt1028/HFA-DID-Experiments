# HFA-DID-Experiments

分层联邦身份认证（HFA-DID） × FISCO BCOS 区块链集成实验项目

## 项目简介
本项目用于论文实验，集成了分层联邦身份认证（HFA-DID）方案与 FISCO BCOS 区块链，支持链上/链下多场景性能评测、智能合约交互、密码学原语验证等。

## 目录结构
```
HFA-DID-Experiments/
├── contract_addresses.json      # 合约部署地址
├── experiment-design.md         # 实验设计说明
├── requirements.txt             # Python 依赖
├── run_experiments.py           # 实验统一入口
├── experiments/                 # 7 个实验脚本
├── results/                     # 实验结果
├── plots/                       # 绘图输出
├── results/                     # 实验结果（自动生成，已 .gitignore）
├── plots/                       # 绘图输出（自动生成，已 .gitignore）
├── src/
│   ├── chain/                   # 区块链交互模块
│   │   ├── fisco_client.py      # FISCOClient 封装类
│   │   └── contracts/           # 合约 ABI 文件
│   ├── crypto/                  # 密码学原语
│   ├── models/                  # 委员会/信誉模型
│   └── utils.py                 # 工具函数
```

## 快速开始
1. 安装依赖
   ```bash
   pip install -r requirements.txt
   ```
2. 运行实验（含链上操作）
   ```bash
   python3 run_experiments.py all
   ```
3. 生成图表
   ```bash
   python3 plots/plot_exp1.py
   # 结果见 plots/ 目录
   ```

## 主要功能
- 支持 FISCO BCOS 区块链 4 节点 PBFT 共识模拟
- 智能合约：CredentialRegistry、CommitteeGovernance
- FISCOClient 封装链交互，自动计时、上下文管理
- 7 个实验脚本，覆盖域内/跨域验证、锚定快照、服务可用性、更新撤销、正确性验证、Re-DKG 安全等
- 自动保存实验结果 JSON，支持一键绘图

## 代码同步与运维
- 推荐使用 VSCode Remote-SSH 远程开发
- 代码同步：scp 上传/下载
- 清除缓存：`find . -name '__pycache__' -exec rm -rf {} +`

## 版本管理
- 已配置 .gitignore，排除缓存、结果、图片、密钥等
- 建议分支开发，主分支保持稳定

## 参考文档
- INTEGRATION_GUIDE.md：集成与实验详细说明
- experiment-design.md：实验设计与流程

## 许可证
请根据实际需求补充 LICENSE 文件。

---
如有问题或建议，请联系 lyt1028（360444150@qq.com）。
