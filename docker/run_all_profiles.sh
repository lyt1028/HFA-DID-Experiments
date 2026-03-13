#!/usr/bin/env bash
# ============================================================
# 一键运行全部网络 profile 实验
# 用法: cd ~/HFA-DID-Experiments && bash docker/run_all_profiles.sh
# 前提: docker compose up -d 已启动
# ============================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

echo "============================================"
echo " HFA-DID 全 Profile 网络仿真实验"
echo " 工作目录: $PROJECT_DIR"
echo "============================================"

# 等待所有服务就绪
echo "[1/6] 等待服务启动..."
for i in $(seq 1 30); do
    if docker exec hfa-verifier curl -sf http://172.20.0.20:5000/ping > /dev/null 2>&1; then
        echo "  服务就绪"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  [ERROR] 服务启动超时, 请检查 docker compose logs"
        exit 1
    fi
    sleep 1
done

PROFILES=("lan" "metro" "wan" "cross_region" "asymmetric")

for profile in "${PROFILES[@]}"; do
    echo ""
    echo "============================================"
    echo " Profile: $profile"
    echo "============================================"

    # 配置网络
    bash "$SCRIPT_DIR/setup_network.sh" "$profile"
    sleep 3  # 等待 netem 规则生效

    # 在 verifier 容器中运行实验
    echo "[RUN] exp8a + exp8b + exp8c under $profile ..."
    docker exec hfa-verifier python experiments/exp8_network_simulation.py 2>&1 | tee "results/exp8_${profile}.log"

    echo "[DONE] $profile 完成"
done

echo ""
echo "============================================"
echo " 全部实验完成! 结果保存在 results/ 目录"
echo "============================================"
echo ""
echo "结果文件:"
ls -la results/EXP8* 2>/dev/null || echo "  (请检查 results 目录)"
