#!/usr/bin/env bash
# ============================================================
# HFA-DID 网络仿真配置脚本
# 用 tc netem 为各容器注入差异化网络条件
#
# 用法:
#   bash setup_network.sh <profile>
#   profile = lan | metro | wan | cross_region | asymmetric
#
# 原理:
#   tc qdisc 作用于容器出口 (egress), 实际 RTT = 两端单向延迟之和
#   例: verifier 出口 25ms + gcl 出口 25ms → RTT ≈ 50ms
# ============================================================

set -euo pipefail

PROFILE="${1:-wan}"

echo "=========================================="
echo " HFA-DID Network Simulation Profile: $PROFILE"
echo "=========================================="

# ---- 清除所有容器的旧 tc 规则 ----
for c in hfa-rtl hfa-gcl hfa-dcl-a hfa-dcl-b hfa-dcl-c hfa-verifier; do
    docker exec "$c" tc qdisc del dev eth0 root 2>/dev/null || true
done
echo "[OK] 已清除所有旧规则"

# ---- 按 profile 配置 ----

case "$PROFILE" in

  # ========== LAN: 同机房基准 ==========
  lan)
    echo "LAN: RTT ~2ms, 0% loss"
    # verifier → gcl: 1ms
    docker exec hfa-verifier tc qdisc add dev eth0 root netem delay 1ms
    # gcl → rtl: 0.5ms
    docker exec hfa-gcl tc qdisc add dev eth0 root netem delay 0.5ms
    # dcl → gcl: 0.5ms
    for c in hfa-dcl-a hfa-dcl-b hfa-dcl-c; do
      docker exec "$c" tc qdisc add dev eth0 root netem delay 0.5ms
    done
    ;;

  # ========== Metro: 同城跨机房 ==========
  metro)
    echo "Metro: RTT ~10ms, 0.1% loss, 1ms jitter"
    docker exec hfa-verifier tc qdisc add dev eth0 root netem \
      delay 5ms 1ms distribution normal loss 0.1%
    docker exec hfa-gcl tc qdisc add dev eth0 root netem \
      delay 3ms 0.5ms distribution normal loss 0.05%
    for c in hfa-dcl-a hfa-dcl-b hfa-dcl-c; do
      docker exec "$c" tc qdisc add dev eth0 root netem \
        delay 3ms 0.5ms distribution normal loss 0.05%
    done
    docker exec hfa-rtl tc qdisc add dev eth0 root netem \
      delay 2ms 0.3ms distribution normal
    ;;

  # ========== WAN: 跨城市广域网 ==========
  wan)
    echo "WAN: RTT ~50ms, 0.5% loss, 5ms jitter"
    docker exec hfa-verifier tc qdisc add dev eth0 root netem \
      delay 25ms 5ms distribution normal loss 0.5%
    docker exec hfa-gcl tc qdisc add dev eth0 root netem \
      delay 15ms 3ms distribution normal loss 0.3%
    for c in hfa-dcl-a hfa-dcl-b; do
      docker exec "$c" tc qdisc add dev eth0 root netem \
        delay 10ms 2ms distribution normal loss 0.2%
    done
    docker exec hfa-dcl-c tc qdisc add dev eth0 root netem \
      delay 30ms 5ms distribution normal loss 0.5%
    docker exec hfa-rtl tc qdisc add dev eth0 root netem \
      delay 5ms 1ms distribution normal loss 0.1%
    ;;

  # ========== Cross-Region: 跨地域 ==========
  cross_region)
    echo "Cross-Region: RTT ~150ms, 1% loss, 20ms jitter"
    docker exec hfa-verifier tc qdisc add dev eth0 root netem \
      delay 75ms 20ms distribution normal loss 1%
    docker exec hfa-gcl tc qdisc add dev eth0 root netem \
      delay 40ms 10ms distribution normal loss 0.5%
    for c in hfa-dcl-a hfa-dcl-b; do
      docker exec "$c" tc qdisc add dev eth0 root netem \
        delay 30ms 8ms distribution normal loss 0.5%
    done
    docker exec hfa-dcl-c tc qdisc add dev eth0 root netem \
      delay 80ms 15ms distribution normal loss 1%
    docker exec hfa-rtl tc qdisc add dev eth0 root netem \
      delay 10ms 3ms distribution normal loss 0.2%
    ;;

  # ========== Asymmetric: 异构网络(域间差异大) ==========
  asymmetric)
    echo "Asymmetric: DCL_A=LAN, DCL_B=metro, DCL_C=cross-region"
    docker exec hfa-verifier tc qdisc add dev eth0 root netem \
      delay 25ms 5ms distribution normal loss 0.3%
    docker exec hfa-gcl tc qdisc add dev eth0 root netem \
      delay 10ms 2ms distribution normal loss 0.2%
    # DCL_A: 低延迟
    docker exec hfa-dcl-a tc qdisc add dev eth0 root netem \
      delay 1ms
    # DCL_B: 中等延迟
    docker exec hfa-dcl-b tc qdisc add dev eth0 root netem \
      delay 15ms 3ms distribution normal loss 0.3%
    # DCL_C: 高延迟
    docker exec hfa-dcl-c tc qdisc add dev eth0 root netem \
      delay 80ms 15ms distribution normal loss 1%
    docker exec hfa-rtl tc qdisc add dev eth0 root netem \
      delay 5ms 1ms distribution normal
    ;;

  *)
    echo "未知 profile: $PROFILE"
    echo "可选: lan | metro | wan | cross_region | asymmetric"
    exit 1
    ;;
esac

echo ""
echo "[OK] 网络仿真已配置, 验证 RTT:"
docker exec hfa-verifier ping -c 3 -W 2 172.20.0.20 || true
echo "---"
docker exec hfa-gcl ping -c 3 -W 2 172.20.0.10 || true
