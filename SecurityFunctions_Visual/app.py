#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于大模型的网络安全功能柔性重组智能监控系统 - Web版
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
import random
import time
import threading
import json
import re
import os

app = Flask(__name__)

# 全局状态变量
simulator_state = {
    "defense_scheme": "traditional",  # 'traditional' 或 'flexible'，默认为传统防御方案
    "attack_types": [],  # []无攻击，[1, 2]编码对应攻击类型
    "attack_traffic": {},  # 攻击类型对应流量字典
    "mttr": 0.7,  # 平均修复时间（秒）
    "container_qps": 500,  # 容器每秒查询数
    "normal_traffic": random.randint(200, 600),  # 正常安全数据流量
    "resource_allocation": {
        "IDS-AGV": 30,
        "IDS-Scheduler": 30,
        "Firewall-AGV": 35,
        "Firewall-Scheduler": 35,
    },
    "component_names": {
        "ids_agv": "静态IDS-AGV",
        "ids_scheduler": "静态IDS-RCS",
        "fw_agv": "静态防火墙-AGV",
        "fw_scheduler": "静态防火墙-RCS"
    },
    "is_attacking": False,
    "attack_logs": [  # 初始化一些正常生产的日志
        {"timestamp": time.strftime("%H:%M:%S", time.localtime()), "type": "info", "content": "AGV控制系统正常运行中，无异常"},
        {"timestamp": time.strftime("%H:%M:%S", time.localtime(time.time()-30)), "type": "info", "content": "调度系统正常运行中，无异常"},
        {"timestamp": time.strftime("%H:%M:%S", time.localtime(time.time()-60)), "type": "info", "content": "传统IDS和防火墙正常监控网络流量"}
    ],
    "agv_active": True,  # AGV是否正常运行
    "ids_active": True,  # 传统IDS默认是激活的
    "ids_security": 0,  # 默认IDS安全能力
    "fw_security": 85,  # 默认防火墙安全能力
    "ids_rate_1": "N/A（无攻击发生）",
    "ids_rate_2": "N/A（无攻击发生）",
    "fw_rate_1": "N/A（无攻击需阻断）",
    "fw_rate_2": "N/A（无攻击需阻断）",
    "attacks_detected": 0,
    "attacks_blocked": 0,
    "risk_level": "低",
    "ids_cpu_usage": 30,  # 默认CPU使用率 - 传统IDS 1
    "ids_cpu_usage_2": 30,  # 默认CPU使用率 - 传统IDS 2
    "fw_cpu_usage": 35,  # 默认CPU使用率 - 传统防火墙 1
    "fw_cpu_usage_2": 35,  # 默认CPU使用率 - 传统防火墙 2
}

@app.route('/')
def index():
    """渲染主页"""
    return render_template('index.html')

@app.route('/static/external/<path:filename>')
def external_static(filename):
    """提供外部组件静态文件"""
    return send_from_directory('static/external', filename)

@app.route('/api/defense-schemes', methods=['GET'])
def get_defense_schemes():
    """获取可用的防御方案"""
    return jsonify({
        "schemes": [
            {"id": "traditional", "name": "传统防御方案"},
            {"id": "flexible", "name": "AI安全功能柔性重组方案"}
        ]
    })

@app.route('/api/attack-types', methods=['GET'])
def get_attack_types():
    """获取可用的攻击类型"""
    return jsonify({
        "types": [
            {"id": 0, "name": "无攻击"},
            {"id": 1, "name": "攻击AGV控制系统"},
            {"id": 2, "name": "攻击调度系统"},
            {"id": 3, "name": "同时攻击AGV和调度系统"}
        ]
    })

@app.route('/api/set-defense-scheme', methods=['POST'])
def set_defense_scheme():
    """设置防御方案"""
    data = request.json
    old_scheme = simulator_state["defense_scheme"]
    new_scheme = data.get("scheme")

    # 如果防御方案没有变化，直接返回
    if old_scheme == new_scheme:
        return jsonify({"status": "success", "message": f"防御方案未变化: {new_scheme}"})

    # 更新防御方案
    simulator_state["defense_scheme"] = new_scheme

    # 更新组件名称 - 简化版本
    if new_scheme == "traditional":
        # 传统方案：使用静态IDS和防火墙
        simulator_state["component_names"] = {
            "ids_agv": "静态IDS-AGV",
            "ids_scheduler": "静态IDS-RCS",
            "fw_agv": "静态防火墙-AGV",
            "fw_scheduler": "静态防火墙-RCS"
        }
    else:
        # AI方案：使用AGV和RCS专用的IDS和防火墙
        simulator_state["component_names"] = {
            "ids_agv": "AGV-IDS",
            "ids_scheduler": "RCS-IDS",
            "fw_agv": "AGV-防火墙",
            "fw_scheduler": "RCS-防火墙"
        }

    # 更新IDS检测率和防火墙阻断率
    update_security_rates()

    # 平滑过渡资源分配和CPU使用率
    # 保存当前的CPU使用率，用于平滑过渡
    current_ids_cpu = simulator_state["ids_cpu_usage"]
    current_ids_cpu2 = simulator_state["ids_cpu_usage_2"]
    current_fw_cpu = simulator_state["fw_cpu_usage"]
    current_fw_cpu2 = simulator_state["fw_cpu_usage_2"]

    # 更新资源分配情况 - 使用更合理的资源分配范围
    if new_scheme == "flexible" and simulator_state["attack_types"]:
        # 柔性重组方案在攻击时，资源分配较高但不超过80%
        simulator_state["resource_allocation"] = {
            "IDS-AGV": random.uniform(55, 75),
            "IDS-Scheduler": random.uniform(55, 75),
            "Firewall-AGV": random.uniform(60, 80),
            "Firewall-Scheduler": random.uniform(60, 80),
        }
    else:
        # 其他情况下，资源分配较低
        simulator_state["resource_allocation"] = {
            "IDS-AGV": random.uniform(15, 25),
            "IDS-Scheduler": random.uniform(15, 25),
            "Firewall-AGV": random.uniform(20, 30),
            "Firewall-Scheduler": random.uniform(20, 30),
        }

    # 计算目标CPU使用率
    if new_scheme == "traditional":
        # 传统方案：无攻击时资源消耗较低，攻击时资源消耗较高且稍微波动
        if not simulator_state["attack_types"]:
            # 无攻击状态下，CPU使用率较低
            cpu_base = 30
            fluctuation = 2
        else:
            # 攻击状态下，CPU使用率较高但会卡在一个值
            cpu_base = 55
            fluctuation = 2

        # 计算目标CPU使用率
        target_ids_cpu = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        target_ids_cpu2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        target_fw_cpu = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        target_fw_cpu2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
    else:
        # 柔性重组方案：基于资源分配动态调整
        # 获取当前资源分配
        ids_agv_alloc = simulator_state["resource_allocation"].get("IDS-AGV", 0)
        ids_sched_alloc = simulator_state["resource_allocation"].get("IDS-Scheduler", 0)
        fw_agv_alloc = simulator_state["resource_allocation"].get("Firewall-AGV", 0)
        fw_sched_alloc = simulator_state["resource_allocation"].get("Firewall-Scheduler", 0)

        # 计算目标CPU使用率
        target_ids_cpu = random.uniform(15, 45) + ids_agv_alloc * 0.5
        target_ids_cpu2 = random.uniform(15, 45) + ids_sched_alloc * 0.5
        target_fw_cpu = random.uniform(15, 50) + fw_agv_alloc * 0.7
        target_fw_cpu2 = random.uniform(15, 50) + fw_sched_alloc * 0.7

    # 平滑过渡到目标CPU使用率 - 使用加权平均
    weight = 0.3  # 权重因子，控制过渡速度
    simulator_state["ids_cpu_usage"] = current_ids_cpu * (1 - weight) + target_ids_cpu * weight
    simulator_state["ids_cpu_usage_2"] = current_ids_cpu2 * (1 - weight) + target_ids_cpu2 * weight
    simulator_state["fw_cpu_usage"] = current_fw_cpu * (1 - weight) + target_fw_cpu * weight
    simulator_state["fw_cpu_usage_2"] = current_fw_cpu2 * (1 - weight) + target_fw_cpu2 * weight

    # 添加日志
    if new_scheme == "traditional":
        add_log("info", "已切换到传统防御方案，静态IDS和防火墙将用于防御")
    else:
        add_log("info", "已切换到AI安全功能柔性重组方案，系统将根据攻击动态调整防御策略")

    return jsonify({"status": "success", "message": f"已设置防御方案: {new_scheme}"})

@app.route('/api/set-attack', methods=['POST'])
def set_attack():
    """设置攻击类型和流量"""
    data = request.json
    attack_id = data.get("attack_id", 0)

    # 重置攻击状态
    simulator_state["attack_types"] = []
    simulator_state["attack_traffic"] = {}

    # 更新IDS检测率和防火墙阻断率
    update_security_rates(attack_id)

    if attack_id == 0:
        # 无攻击
        pass
    elif attack_id == 1:
        # 攻击AGV控制系统
        simulator_state["attack_types"] = [1]
        simulator_state["attack_traffic"] = {1: data.get("agv_traffic", 2000)}
    elif attack_id == 2:
        # 攻击调度系统
        simulator_state["attack_types"] = [2]
        simulator_state["attack_traffic"] = {2: data.get("scheduler_traffic", 1500)}
    elif attack_id == 3:
        # 同时攻击
        simulator_state["attack_types"] = [1, 2]
        simulator_state["attack_traffic"] = {
            1: data.get("agv_traffic", 2000),
            2: data.get("scheduler_traffic", 1500)
        }

    return jsonify({
        "status": "success",
        "message": "攻击设置已更新",
        "attack_types": simulator_state["attack_types"],
        "attack_traffic": simulator_state["attack_traffic"]
    })

@app.route('/api/trigger-attack', methods=['POST'])
def trigger_attack():
    """触发攻击或停止攻击"""
    # 如果当前正在攻击中，则停止攻击
    if simulator_state["is_attacking"]:
        # 停止攻击，重置状态
        simulator_state["is_attacking"] = False
        simulator_state["attack_types"] = []

        # 重置安全能力指标
        simulator_state["ids_security"] = 0
        simulator_state["fw_security"] = 85

        # 重置AGV和IDS状态
        simulator_state["agv_active"] = True
        simulator_state["ids_active"] = True

        # 重置风险等级
        simulator_state["risk_level"] = "低"

        # 根据防御方案设置不同的恢复状态
        if simulator_state["defense_scheme"] == "traditional":
            # 传统方案：停止攻击后，系统恢复到无攻击状态
            simulator_state["attacks_blocked"] += 1

            # 重置CPU使用率到无攻击状态 - 与visual_interface.py一致
            cpu_base = 30
            fluctuation = 2
            simulator_state["ids_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["fw_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

            # 重置检测率和阻断率
            simulator_state["ids_rate_1"] = "N/A（无攻击发生）"
            simulator_state["ids_rate_2"] = "N/A（无攻击发生）"
            simulator_state["fw_rate_1"] = "N/A（无攻击需阻断）"
            simulator_state["fw_rate_2"] = "N/A（无攻击需阻断）"

            # 重置MTTR和QPS - 与visual_interface.py一致
            simulator_state["mttr"] = max(0.2, min(0.5, simulator_state["mttr"] + random.uniform(-0.05, 0.05)))
            simulator_state["container_qps"] = random.randint(700, 800)

            # 重置组件名称
            simulator_state["component_names"] = {
                "ids_agv": "静态IDS-AGV",
                "ids_scheduler": "静态IDS-RCS",
                "fw_agv": "静态防火墙-AGV",
                "fw_scheduler": "静态防火墙-RCS"
            }

            # 添加系统重置日志
            add_log("success", "攻击已手动停止，系统已重置")
        else:
            # AI柔性重组方案：停止攻击后，系统恢复到无攻击状态
            simulator_state["attacks_blocked"] += 1

            # 重置CPU使用率到无攻击状态 - 与visual_interface.py一致
            cpu_base = 30
            fluctuation = 2
            simulator_state["ids_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["fw_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

            # 重置检测率和阻断率
            simulator_state["ids_rate_1"] = "N/A（无攻击发生）"
            simulator_state["ids_rate_2"] = "N/A（无攻击发生）"
            simulator_state["fw_rate_1"] = "N/A（无攻击需阻断）"
            simulator_state["fw_rate_2"] = "N/A（无攻击需阻断）"

            # 重置MTTR和QPS - 与visual_interface.py一致
            simulator_state["mttr"] = max(0.2, min(0.5, simulator_state["mttr"] + random.uniform(-0.05, 0.05)))
            simulator_state["container_qps"] = random.randint(700, 800)

            # 重置组件名称 - AI方案
            simulator_state["component_names"] = {
                "ids_agv": "AGV-IDS",
                "ids_scheduler": "RCS-IDS",
                "fw_agv": "AGV-防火墙",
                "fw_scheduler": "RCS-防火墙"
            }

            # 添加成功恢复的日志
            add_log("success", "攻击已手动停止，系统已恢复正常")

        return jsonify({"status": "success", "message": "攻击已停止"})

    # 如果当前没有攻击，则开始攻击
    # 确保攻击类型已设置
    if not simulator_state["attack_types"]:
        # 如果没有设置攻击类型，默认设置为同时攻击
        simulator_state["attack_types"] = [1, 2]
        simulator_state["attack_traffic"] = {1: 2000, 2: 1500}

    # 更新组件名称 - 简化版本
    if simulator_state["defense_scheme"] == "traditional":
        # 传统方案：使用静态IDS和防火墙
        simulator_state["component_names"] = {
            "ids_agv": "静态IDS-AGV",
            "ids_scheduler": "静态IDS-RCS",
            "fw_agv": "静态防火墙-AGV",
            "fw_scheduler": "静态防火墙-RCS"
        }
    else:
        # AI方案：使用AGV和RCS专用的IDS和防火墙
        simulator_state["component_names"] = {
            "ids_agv": "AGV-IDS",
            "ids_scheduler": "RCS-IDS",
            "fw_agv": "AGV-防火墙",
            "fw_scheduler": "RCS-防火墙"
        }

    # 更新IDS检测率和防火墙阻断率
    update_security_rates()

    # 立即更新QPS和MTTR的值，使其与检测率和阻断率的更新时机保持一致
    if simulator_state["defense_scheme"] == "traditional":
        # 传统方案：QPS低，MTTR高
        simulator_state["mttr"] = random.uniform(2.23, 3.18)
        simulator_state["container_qps"] = random.randint(140, 200)
    else:
        # AI方案：QPS高，MTTR低
        simulator_state["mttr"] = random.uniform(0.7, 0.9)
        simulator_state["container_qps"] = random.randint(800, 1000)

    # 启动攻击模拟线程
    simulator_state["is_attacking"] = True
    # 保留之前的日志，不清空

    # 在新线程中执行攻击模拟
    threading.Thread(target=simulate_attack).start()

    return jsonify({"status": "success", "message": "攻击已触发"})

@app.route('/api/status', methods=['GET'])
def get_status():
    """获取当前系统状态"""
    # 确保在无攻击状态下也返回动态变化的数据
    if not simulator_state["is_attacking"]:
        # 更新正常安全数据流量
        simulator_state["normal_traffic"] = random.randint(200, 600)

        # 这部分MTTR和QPS的更新已经移到下面的CPU使用率更新部分，这里可以删除

        # 更新CPU使用率 - 完全按照visual_interface.py的逻辑实现
        if simulator_state["defense_scheme"] == "traditional":
            # 传统方案：无攻击时资源消耗较低，攻击时资源消耗较高且稍微波动
            if not simulator_state["is_attacking"]:
                # 无攻击状态下，CPU使用率较低
                cpu_base = 30
                fluctuation = 2
                # 无攻击状态下的检测率和阻断率
                simulator_state["ids_rate_1"] = "N/A（无攻击发生）"
                simulator_state["ids_rate_2"] = "N/A（无攻击发生）"
                simulator_state["fw_rate_1"] = "N/A（无攻击需阻断）"
                simulator_state["fw_rate_2"] = "N/A（无攻击需阻断）"
            else:
                # 攻击状态下，CPU使用率较高但会卡在一个值
                cpu_base = 55
                fluctuation = 2
                # 攻击状态下的检测率和阻断率 - 完全按照visual_interface.py的值
                simulator_state["ids_rate_1"] = f"{random.uniform(0.45, 0.55) * 100:.2f}%"
                simulator_state["fw_rate_1"] = f"{random.uniform(0.3, 0.5) * 100:.2f}%"
                simulator_state["ids_rate_2"] = f"{random.uniform(0.35, 0.65) * 100:.2f}%"
                simulator_state["fw_rate_2"] = f"{random.uniform(0.2, 0.6) * 100:.2f}%"

            # 模拟传统方案的IDS和防火墙资源使用
            ids_cpu_1 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            ids_cpu_2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            fw_cpu_1 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            fw_cpu_2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

            # 更新状态
            simulator_state["ids_cpu_usage"] = ids_cpu_1
            simulator_state["ids_cpu_usage_2"] = ids_cpu_2
            simulator_state["fw_cpu_usage"] = fw_cpu_1
            simulator_state["fw_cpu_usage_2"] = fw_cpu_2

            # 传统方案：QPS低，MTTR高 - 使变化更加平滑
            if simulator_state["is_attacking"]:
                # 攻击状态下，MTTR应该逐渐增加到2.23-3.18范围
                target_mttr_min = 2.23
                target_mttr_max = 3.18
                target_qps_min = 140
                target_qps_max = 200
            else:
                # 无攻击状态下，MTTR应该逐渐降低到0.65-0.75范围
                target_mttr_min = 0.65
                target_mttr_max = 0.75
                target_qps_min = 400
                target_qps_max = 500

            # 当前MTTR值
            current_mttr = simulator_state["mttr"]
            current_qps = simulator_state["container_qps"]

            # 计算目标MTTR值 - 在目标范围内随机选择一个值
            target_mttr = random.uniform(target_mttr_min, target_mttr_max)
            target_qps = random.randint(target_qps_min, target_qps_max)

            # 平滑过渡 - 每次只移动一小步
            mttr_step = 0.02  # 每次最多变化0.02
            qps_step = 10     # 每次最多变化10

            # 计算MTTR的变化方向和大小
            if abs(target_mttr - current_mttr) < mttr_step:
                # 如果差距很小，直接设置为目标值
                simulator_state["mttr"] = target_mttr
            else:
                # 否则，向目标值移动一小步
                direction = 1 if target_mttr > current_mttr else -1
                simulator_state["mttr"] = current_mttr + direction * min(mttr_step, abs(target_mttr - current_mttr))

            # 计算QPS的变化方向和大小
            if abs(target_qps - current_qps) < qps_step:
                # 如果差距很小，直接设置为目标值
                simulator_state["container_qps"] = target_qps
            else:
                # 否则，向目标值移动一小步
                direction = 1 if target_qps > current_qps else -1
                simulator_state["container_qps"] = current_qps + direction * min(qps_step, abs(target_qps - current_qps))
        else:
            # 柔性重组方案：基于资源分配动态调整
            # 获取当前资源分配
            ids_agv_alloc = simulator_state["resource_allocation"].get("IDS-AGV", 0)
            ids_sched_alloc = simulator_state["resource_allocation"].get("IDS-Scheduler", 0)
            fw_agv_alloc = simulator_state["resource_allocation"].get("Firewall-AGV", 0)
            fw_sched_alloc = simulator_state["resource_allocation"].get("Firewall-Scheduler", 0)

            # 计算CPU使用率 - 使用更合理的计算方式，确保不会超过100%
            # 基础值范围缩小，系数也减小，确保总和不会超过100%
            if simulator_state["is_attacking"]:
                # 攻击状态下，基础值较高
                base_ids = random.uniform(20, 30)
                base_fw = random.uniform(25, 35)
                # 系数较小，确保总和不会超过100%
                ids_factor = 0.3
                fw_factor = 0.3
            else:
                # 无攻击状态下，基础值较低
                base_ids = random.uniform(10, 20)
                base_fw = random.uniform(15, 25)
                # 系数较小，确保总和不会超过100%
                ids_factor = 0.2
                fw_factor = 0.2

            # 计算最终CPU使用率，并确保不超过100%
            ids_cpu_agv = min(95, base_ids + ids_agv_alloc * ids_factor)
            ids_cpu_sched = min(95, base_ids + ids_sched_alloc * ids_factor)
            fw_cpu_agv = min(95, base_fw + fw_agv_alloc * fw_factor)
            fw_cpu_sched = min(95, base_fw + fw_sched_alloc * fw_factor)

            # 更新状态
            simulator_state["ids_cpu_usage"] = ids_cpu_agv
            simulator_state["ids_cpu_usage_2"] = ids_cpu_sched
            simulator_state["fw_cpu_usage"] = fw_cpu_agv
            simulator_state["fw_cpu_usage_2"] = fw_cpu_sched

            # AI方案：QPS高，MTTR低 - 使变化更加平滑
            if simulator_state["is_attacking"]:
                # 攻击状态下，MTTR应该逐渐增加到0.7-0.9范围
                target_mttr_min = 0.7
                target_mttr_max = 0.9
                target_qps_min = 800
                target_qps_max = 1000
            else:
                # 无攻击状态下，MTTR应该逐渐降低到0.2-0.5范围
                target_mttr_min = 0.2
                target_mttr_max = 0.5
                target_qps_min = 700
                target_qps_max = 800

            # 当前MTTR值
            current_mttr = simulator_state["mttr"]
            current_qps = simulator_state["container_qps"]

            # 计算目标MTTR值 - 在目标范围内随机选择一个值
            target_mttr = random.uniform(target_mttr_min, target_mttr_max)
            target_qps = random.randint(target_qps_min, target_qps_max)

            # 平滑过渡 - 每次只移动一小步
            mttr_step = 0.02  # 每次最多变化0.02
            qps_step = 20     # 每次最多变化20

            # 计算MTTR的变化方向和大小
            if abs(target_mttr - current_mttr) < mttr_step:
                # 如果差距很小，直接设置为目标值
                simulator_state["mttr"] = target_mttr
            else:
                # 否则，向目标值移动一小步
                direction = 1 if target_mttr > current_mttr else -1
                simulator_state["mttr"] = current_mttr + direction * min(mttr_step, abs(target_mttr - current_mttr))

            # 计算QPS的变化方向和大小
            if abs(target_qps - current_qps) < qps_step:
                # 如果差距很小，直接设置为目标值
                simulator_state["container_qps"] = target_qps
            else:
                # 否则，向目标值移动一小步
                direction = 1 if target_qps > current_qps else -1
                simulator_state["container_qps"] = current_qps + direction * min(qps_step, abs(target_qps - current_qps))

        # 更新资源分配情况 - 只在必要时小幅度调整，避免大幅波动
        if simulator_state["defense_scheme"] == "flexible" and simulator_state["is_attacking"]:
            # 柔性重组方案在攻击时，资源分配较高
            # 获取当前资源分配
            current_ids_agv = simulator_state["resource_allocation"].get("IDS-AGV", 0)
            current_ids_sched = simulator_state["resource_allocation"].get("IDS-Scheduler", 0)
            current_fw_agv = simulator_state["resource_allocation"].get("Firewall-AGV", 0)
            current_fw_sched = simulator_state["resource_allocation"].get("Firewall-Scheduler", 0)

            # 计算目标资源分配 - 攻击状态下，资源分配较高但不超过80%
            target_ids_agv = random.uniform(55, 75)
            target_ids_sched = random.uniform(55, 75)
            target_fw_agv = random.uniform(60, 80)
            target_fw_sched = random.uniform(60, 80)

            # 平滑过渡 - 每次只小幅调整
            adjust_factor = 0.05  # 每次最多调整5%

            # 更新资源分配
            simulator_state["resource_allocation"] = {
                "IDS-AGV": current_ids_agv * (1 - adjust_factor) + target_ids_agv * adjust_factor,
                "IDS-Scheduler": current_ids_sched * (1 - adjust_factor) + target_ids_sched * adjust_factor,
                "Firewall-AGV": current_fw_agv * (1 - adjust_factor) + target_fw_agv * adjust_factor,
                "Firewall-Scheduler": current_fw_sched * (1 - adjust_factor) + target_fw_sched * adjust_factor,
            }
        else:
            # 其他情况下，资源分配较低
            # 获取当前资源分配
            current_ids_agv = simulator_state["resource_allocation"].get("IDS-AGV", 0)
            current_ids_sched = simulator_state["resource_allocation"].get("IDS-Scheduler", 0)
            current_fw_agv = simulator_state["resource_allocation"].get("Firewall-AGV", 0)
            current_fw_sched = simulator_state["resource_allocation"].get("Firewall-Scheduler", 0)

            # 计算目标资源分配 - 无攻击状态下，资源分配较低
            target_ids_agv = random.uniform(15, 25)
            target_ids_sched = random.uniform(15, 25)
            target_fw_agv = random.uniform(20, 30)
            target_fw_sched = random.uniform(20, 30)

            # 平滑过渡 - 每次只小幅调整
            adjust_factor = 0.05  # 每次最多调整5%

            # 更新资源分配
            simulator_state["resource_allocation"] = {
                "IDS-AGV": current_ids_agv * (1 - adjust_factor) + target_ids_agv * adjust_factor,
                "IDS-Scheduler": current_ids_sched * (1 - adjust_factor) + target_ids_sched * adjust_factor,
                "Firewall-AGV": current_fw_agv * (1 - adjust_factor) + target_fw_agv * adjust_factor,
                "Firewall-Scheduler": current_fw_sched * (1 - adjust_factor) + target_fw_sched * adjust_factor,
            }

        # 随机添加一些系统日志
        if random.random() < 0.05:  # 5%的概率添加日志
            log_types = ["info", "info", "info", "warning"]  # 大多数是info，偶尔有warning
            log_type = random.choice(log_types)

            log_contents = [
                "系统正常运行中，无异常",
                "网络流量正常，无异常",
                "安全检测正常，无异常",
                "执行例行安全扫描",
                "更新安全规则库",
                "检测到少量异常流量，在正常范围内",
                "执行系统资源优化",
                "安全组件健康检查通过"
            ]

            if log_type == "warning":
                log_contents = [
                    "检测到轻微异常流量，已自动处理",
                    "系统负载略高，已自动调整资源分配",
                    "检测到可疑IP访问尝试，已自动阻断",
                    "安全规则更新略有延迟，正在重试"
                ]

            add_log(log_type, random.choice(log_contents))

    # 确保前端能够正确显示日志
    response_data = simulator_state.copy()
    response_data["logs"] = simulator_state["attack_logs"]

    return jsonify(response_data)

def simulate_attack():
    """模拟攻击过程"""
    # 保留之前的日志，不清空
    # 添加初始日志
    add_log("warning", "网络探针检测到疑似网络扫描活动，可能是攻击准备阶段")
    simulator_state["risk_level"] = "中"
    simulator_state["attacks_detected"] += 1

    # 确保攻击类型已设置
    if not simulator_state["attack_types"]:
        # 如果没有设置攻击类型，默认设置为同时攻击
        simulator_state["attack_types"] = [1, 2]
        simulator_state["attack_traffic"] = {1: 2000, 2: 1500}

    # 更新IDS检测率和防火墙阻断率
    update_security_rates()

    # 根据防御方案添加不同的日志
    if simulator_state["defense_scheme"] == "traditional":
        add_log("info", "传统防御方案启动，静态IDS和防火墙开始工作")
    else:
        # 不在这里添加日志，因为日志会在攻击阶段中添加，避免重复
        # 设置AI方案的组件名称 - 简化版本
        simulator_state["component_names"] = {
            "ids_agv": "AGV-IDS",
            "ids_scheduler": "RCS-IDS",
            "fw_agv": "AGV-防火墙",
            "fw_scheduler": "RCS-防火墙"
        }

    # 模拟攻击阶段
    phases = generate_attack_phases()

    # 获取当前状态，用于平滑过渡
    current_ids_security = simulator_state["ids_security"]
    current_fw_security = simulator_state["fw_security"]
    current_ids_cpu = simulator_state["ids_cpu_usage"]
    current_ids_cpu2 = simulator_state["ids_cpu_usage_2"]
    current_fw_cpu = simulator_state["fw_cpu_usage"]
    current_fw_cpu2 = simulator_state["fw_cpu_usage_2"]

    for i, phase in enumerate(phases):
        # 如果用户停止了攻击，则退出循环
        if not simulator_state["is_attacking"]:
            break

        # 计算目标值
        target_ids_security = phase["idsSecurity"]
        target_fw_security = phase["fwSecurity"]
        target_ids_cpu = phase["idsCpu"]
        target_ids_cpu2 = phase["idsCpu2"]
        target_fw_cpu = phase["fwCpu"]
        target_fw_cpu2 = phase["fwCpu2"]

        # 平滑过渡到目标值 - 分3个小步骤
        steps = 3
        for step in range(steps):
            # 如果用户停止了攻击，则退出循环
            if not simulator_state["is_attacking"]:
                break

            # 计算当前步骤的值 - 线性插值
            progress = (step + 1) / steps
            simulator_state["ids_security"] = int(current_ids_security + (target_ids_security - current_ids_security) * progress)
            simulator_state["fw_security"] = int(current_fw_security + (target_fw_security - current_fw_security) * progress)
            simulator_state["ids_cpu_usage"] = current_ids_cpu + (target_ids_cpu - current_ids_cpu) * progress
            simulator_state["ids_cpu_usage_2"] = current_ids_cpu2 + (target_ids_cpu2 - current_ids_cpu2) * progress
            simulator_state["fw_cpu_usage"] = current_fw_cpu + (target_fw_cpu - current_fw_cpu) * progress
            simulator_state["fw_cpu_usage_2"] = current_fw_cpu2 + (target_fw_cpu2 - current_fw_cpu2) * progress

            # 添加一些随机波动，使曲线看起来更自然
            simulator_state["ids_cpu_usage"] += random.uniform(-1, 1)
            simulator_state["ids_cpu_usage_2"] += random.uniform(-1, 1)
            simulator_state["fw_cpu_usage"] += random.uniform(-1, 1)
            simulator_state["fw_cpu_usage_2"] += random.uniform(-1, 1)

            # 确保值在合理范围内
            simulator_state["ids_cpu_usage"] = max(0, min(100, simulator_state["ids_cpu_usage"]))
            simulator_state["ids_cpu_usage_2"] = max(0, min(100, simulator_state["ids_cpu_usage_2"]))
            simulator_state["fw_cpu_usage"] = max(0, min(100, simulator_state["fw_cpu_usage"]))
            simulator_state["fw_cpu_usage_2"] = max(0, min(100, simulator_state["fw_cpu_usage_2"]))

            # 暂停一小段时间 - 增加每个步骤的延时
            time.sleep(phase["seconds"] / steps)

        # 更新当前状态，用于下一个阶段的平滑过渡
        current_ids_security = target_ids_security
        current_fw_security = target_fw_security
        current_ids_cpu = target_ids_cpu
        current_ids_cpu2 = target_ids_cpu2
        current_fw_cpu = target_fw_cpu
        current_fw_cpu2 = target_fw_cpu2

        # 更新其他状态
        simulator_state["agv_active"] = phase["agvStatus"]
        simulator_state["ids_active"] = phase["idsStatus"]
        simulator_state["risk_level"] = phase["risk"]

        # 在每个阶段更新QPS和MTTR，使其与检测率和阻断率的更新时机保持一致
        if simulator_state["defense_scheme"] == "traditional":
            # 传统方案：QPS低，MTTR高
            simulator_state["mttr"] = max(2.23, min(3.18, simulator_state["mttr"] + random.uniform(-0.02, 0.02)))
            simulator_state["container_qps"] = random.randint(140, 200)
        else:
            # AI方案：QPS高，MTTR低
            if i <= 1:  # 前两个阶段
                simulator_state["mttr"] = random.uniform(0.7, 0.9)
                simulator_state["container_qps"] = random.randint(800, 900)
            elif i <= 3:  # 中间阶段
                simulator_state["mttr"] = random.uniform(0.5, 0.7)
                simulator_state["container_qps"] = random.randint(850, 950)
            elif i <= 6:  # 重组阶段
                simulator_state["mttr"] = random.uniform(0.3, 0.5)
                simulator_state["container_qps"] = random.randint(900, 980)
            else:  # 最终阶段
                simulator_state["mttr"] = random.uniform(0.2, 0.4)
                simulator_state["container_qps"] = random.randint(950, 1000)

        # 在AI柔性重组方案中，不再添加额外的日志，因为日志已经在攻击阶段中添加

        # 根据当前阶段更新IDS检测率和防火墙阻断率
        if simulator_state["defense_scheme"] == "traditional":
            # 传统方案随着攻击进行，检测率和阻断率逐渐降低
            progress_factor = 1.0 - (i / len(phases))  # 从1.0降到接近0
            simulator_state["ids_rate_1"] = f"{max(5, random.uniform(0.45, 0.55) * 100 * progress_factor):.2f}%"
            simulator_state["fw_rate_1"] = f"{max(5, random.uniform(0.3, 0.5) * 100 * progress_factor):.2f}%"
            simulator_state["ids_rate_2"] = f"{max(5, random.uniform(0.35, 0.65) * 100 * progress_factor):.2f}%"
            simulator_state["fw_rate_2"] = f"{max(5, random.uniform(0.2, 0.6) * 100 * progress_factor):.2f}%"
        else:
            # AI柔性重组方案：检测率和阻断率始终保持较高水平
            # 根据当前阶段设置不同的检测率和阻断率
            if i <= 1:  # 前两个阶段：初始检测
                # 初始阶段：检测率和阻断率已经较高
                simulator_state["ids_rate_1"] = f"{random.uniform(0.85, 0.90) * 100:.2f}%"
                simulator_state["fw_rate_1"] = f"{random.uniform(0.80, 0.85) * 100:.2f}%"
                simulator_state["ids_rate_2"] = f"{random.uniform(0.85, 0.90) * 100:.2f}%"
                simulator_state["fw_rate_2"] = f"{random.uniform(0.80, 0.85) * 100:.2f}%"
            elif i <= 3:  # 中间阶段：分析和准备
                # 分析阶段：检测率和阻断率略有提升
                simulator_state["ids_rate_1"] = f"{random.uniform(0.88, 0.93) * 100:.2f}%"
                simulator_state["fw_rate_1"] = f"{random.uniform(0.83, 0.88) * 100:.2f}%"
                simulator_state["ids_rate_2"] = f"{random.uniform(0.88, 0.93) * 100:.2f}%"
                simulator_state["fw_rate_2"] = f"{random.uniform(0.83, 0.88) * 100:.2f}%"
            elif i <= 6:  # 重组阶段：能力提升
                # 重组阶段：检测率和阻断率明显提升
                simulator_state["ids_rate_1"] = f"{random.uniform(0.92, 0.96) * 100:.2f}%"
                simulator_state["fw_rate_1"] = f"{random.uniform(0.88, 0.93) * 100:.2f}%"
                simulator_state["ids_rate_2"] = f"{random.uniform(0.92, 0.96) * 100:.2f}%"
                simulator_state["fw_rate_2"] = f"{random.uniform(0.88, 0.93) * 100:.2f}%"
            else:  # 最终阶段：完全防御
                # 最终阶段：检测率和阻断率达到最高
                simulator_state["ids_rate_1"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
                simulator_state["fw_rate_1"] = f"{random.uniform(0.94, 0.98) * 100:.2f}%"
                simulator_state["ids_rate_2"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
                simulator_state["fw_rate_2"] = f"{random.uniform(0.94, 0.98) * 100:.2f}%"

        # 添加日志
        add_log(phase["logType"], phase["log"])

        # 在阶段之间添加延时，使攻击过程更加可观察
        time.sleep(1.0)  # 每个阶段之间增加1秒的延时

    # 根据防御方案设置最终状态
    if simulator_state["defense_scheme"] == "traditional":
        # 传统方案：攻击结束后，系统仍处于被攻击状态，需要人工干预
        # 不改变is_attacking状态，保持为True
        # 不增加attacks_blocked计数
        # 保持attack_types不变，确保数据继续更新

        # 检测率和阻断率保持较低 - 使用visual_interface.py中的数值
        simulator_state["ids_rate_1"] = f"{random.uniform(0.45, 0.55) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(0.3, 0.5) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(0.35, 0.65) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(0.2, 0.6) * 100:.2f}%"

        # CPU使用率保持在较高水平
        cpu_base = 55
        fluctuation = 2
        simulator_state["ids_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

        # MTTR和QPS保持在攻击状态的水平
        simulator_state["mttr"] = max(2.23, min(3.18, simulator_state["mttr"] + random.uniform(-0.02, 0.02)))
        simulator_state["container_qps"] = random.randint(140, 200)

        # 添加需要人工干预的日志
        add_log("error", "传统防御系统无法自动恢复，需要人工干预重启系统")

        # 启动一个新线程，模拟传统方案下的持续攻击状态
        threading.Thread(target=simulate_traditional_attack_state).start()
    else:
        # AI柔性重组方案：攻击结束后，系统进入警戒期
        # 不再自动设置is_attacking为False，而是保持攻击状态，直到用户点击停止
        # 只有在用户点击停止按钮时，才会执行trigger_attack中的停止逻辑

        # 所有阶段执行完毕后，进入持续防御状态
        simulator_state["attacks_blocked"] += 1

        # 保持较高的安全能力指标，表示系统已经成功防御
        simulator_state["ids_security"] = 100
        simulator_state["fw_security"] = 99

        # AGV和IDS状态保持正常
        simulator_state["agv_active"] = True
        simulator_state["ids_active"] = True

        # 风险等级保持低
        simulator_state["risk_level"] = "低"

        # 设置CPU使用率到高效防御状态 - 高于无攻击状态，表示系统处于高效防御状态
        cpu_base = 60
        fluctuation = 5
        simulator_state["ids_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

        # 设置检测率和阻断率为高值，表示系统处于高效防御状态
        simulator_state["ids_rate_1"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(0.95, 0.98) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(0.95, 0.98) * 100:.2f}%"

        # 设置MTTR和QPS - 表示系统高效运行
        simulator_state["mttr"] = max(0.2, min(0.4, simulator_state["mttr"] + random.uniform(-0.05, 0.05)))
        simulator_state["container_qps"] = random.randint(900, 1000)

        # 保持重组后的组件名称，表示系统仍在使用优化后的组件
        # 不重置组件名称，保持当前的动态组件

        # 添加持续防御的日志
        add_log("success", "AI安全功能柔性重组完成，系统进入持续防御状态，实时监控网络流量")

        # 启动一个新线程，模拟持续防御状态下的资源使用变化
        threading.Thread(target=simulate_continuous_defense).start()

def simulate_traditional_attack_state():
    """模拟传统方案下的持续攻击状态"""
    # 传统方案下的CPU使用率基准值
    cpu_base = 55
    fluctuation = 2

    # 传统方案下的检测率和阻断率范围
    ids_rate_min = 0.45
    ids_rate_max = 0.55
    fw_rate_min = 0.3
    fw_rate_max = 0.5
    ids_rate2_min = 0.35
    ids_rate2_max = 0.65
    fw_rate2_min = 0.2
    fw_rate2_max = 0.6

    # 持续更新数据，直到攻击停止
    while simulator_state["is_attacking"]:
        # 更新CPU使用率 - 添加小幅波动
        simulator_state["ids_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
        simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

        # 更新检测率和阻断率 - 保持在较低水平
        simulator_state["ids_rate_1"] = f"{random.uniform(ids_rate_min, ids_rate_max) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(fw_rate_min, fw_rate_max) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(ids_rate2_min, ids_rate2_max) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(fw_rate2_min, fw_rate2_max) * 100:.2f}%"

        # 更新MTTR和QPS - 保持在攻击状态的水平
        simulator_state["mttr"] = max(2.23, min(3.18, simulator_state["mttr"] + random.uniform(-0.02, 0.02)))
        simulator_state["container_qps"] = random.randint(140, 200)

        # 偶尔添加一些攻击持续的日志
        if random.random() < 0.1:  # 10%的概率添加日志
            log_contents = [
                "攻击持续中，传统防御系统无法有效应对",
                "系统性能持续下降，需要人工干预",
                "检测到新的攻击尝试，防御能力不足",
                "防火墙规则无法有效阻断当前攻击",
                "IDS检测到异常流量，但无法自动处理"
            ]
            add_log("error", random.choice(log_contents))

        # 暂停一小段时间
        time.sleep(3)

def simulate_continuous_defense():
    """模拟持续防御状态下的资源使用变化"""
    # 初始资源使用率 - 高效防御状态
    cpu_base_high = 60
    fluctuation_high = 5

    # 最终资源使用率 - 常态监控状态
    cpu_base_low = 35
    fluctuation_low = 3

    # 警戒期持续时间（秒）
    alert_period = 30

    # 过渡期持续时间（秒）
    transition_period = 60

    # 记录开始时间
    start_time = time.time()

    # 添加警戒期日志
    add_log("info", "系统进入警戒期，保持高级别防御状态")

    # 警戒期 - 保持高资源使用率
    while simulator_state["is_attacking"] and time.time() - start_time < alert_period:
        # 高资源使用率
        simulator_state["ids_cpu_usage"] = random.uniform(cpu_base_high - fluctuation_high, cpu_base_high + fluctuation_high)
        simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base_high - fluctuation_high, cpu_base_high + fluctuation_high)
        simulator_state["fw_cpu_usage"] = random.uniform(cpu_base_high - fluctuation_high, cpu_base_high + fluctuation_high)
        simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base_high - fluctuation_high, cpu_base_high + fluctuation_high)

        # 高检测率和阻断率
        simulator_state["ids_rate_1"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(0.96, 0.99) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(0.95, 0.98) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(0.95, 0.98) * 100:.2f}%"

        # 高QPS
        simulator_state["container_qps"] = random.randint(900, 1000)

        # 暂停一小段时间
        time.sleep(3)

    # 如果用户停止了攻击，则退出
    if not simulator_state["is_attacking"]:
        return

    # 添加过渡期日志
    add_log("info", "警戒期结束，系统进入资源优化阶段，逐步降低资源使用率")

    # 过渡期 - 资源使用率逐渐降低
    transition_start = time.time()
    while simulator_state["is_attacking"] and time.time() - transition_start < transition_period:
        # 计算过渡进度 (0.0 到 1.0)
        progress = min(1.0, (time.time() - transition_start) / transition_period)

        # 线性插值计算当前资源使用率
        current_cpu_base = cpu_base_high - progress * (cpu_base_high - cpu_base_low)
        current_fluctuation = fluctuation_high - progress * (fluctuation_high - fluctuation_low)

        # 更新资源使用率
        simulator_state["ids_cpu_usage"] = random.uniform(current_cpu_base - current_fluctuation, current_cpu_base + current_fluctuation)
        simulator_state["ids_cpu_usage_2"] = random.uniform(current_cpu_base - current_fluctuation, current_cpu_base + current_fluctuation)
        simulator_state["fw_cpu_usage"] = random.uniform(current_cpu_base - current_fluctuation, current_cpu_base + current_fluctuation)
        simulator_state["fw_cpu_usage_2"] = random.uniform(current_cpu_base - current_fluctuation, current_cpu_base + current_fluctuation)

        # 检测率和阻断率保持较高，但略有下降
        detection_base = 0.96 - progress * 0.06  # 从0.96降到0.90
        blocking_base = 0.95 - progress * 0.05   # 从0.95降到0.90

        simulator_state["ids_rate_1"] = f"{random.uniform(detection_base, detection_base + 0.03) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(detection_base, detection_base + 0.03) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(blocking_base, blocking_base + 0.03) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(blocking_base, blocking_base + 0.03) * 100:.2f}%"

        # QPS逐渐降低
        qps_high = 900
        qps_low = 800
        current_qps = int(qps_high - progress * (qps_high - qps_low))
        simulator_state["container_qps"] = random.randint(current_qps - 20, current_qps + 20)

        # 暂停一小段时间
        time.sleep(3)

    # 如果用户停止了攻击，则退出
    if not simulator_state["is_attacking"]:
        return

    # 添加常态监控日志
    add_log("info", "系统进入常态监控状态，保持优化后的资源配置")

    # 常态监控状态 - 低资源使用率但保持高检测能力
    while simulator_state["is_attacking"]:
        # 低资源使用率
        simulator_state["ids_cpu_usage"] = random.uniform(cpu_base_low - fluctuation_low, cpu_base_low + fluctuation_low)
        simulator_state["ids_cpu_usage_2"] = random.uniform(cpu_base_low - fluctuation_low, cpu_base_low + fluctuation_low)
        simulator_state["fw_cpu_usage"] = random.uniform(cpu_base_low - fluctuation_low, cpu_base_low + fluctuation_low)
        simulator_state["fw_cpu_usage_2"] = random.uniform(cpu_base_low - fluctuation_low, cpu_base_low + fluctuation_low)

        # 检测率和阻断率保持较高
        simulator_state["ids_rate_1"] = f"{random.uniform(0.90, 0.93) * 100:.2f}%"
        simulator_state["ids_rate_2"] = f"{random.uniform(0.90, 0.93) * 100:.2f}%"
        simulator_state["fw_rate_1"] = f"{random.uniform(0.90, 0.93) * 100:.2f}%"
        simulator_state["fw_rate_2"] = f"{random.uniform(0.90, 0.93) * 100:.2f}%"

        # 正常QPS
        simulator_state["container_qps"] = random.randint(780, 820)

        # 偶尔添加一些监控日志
        if random.random() < 0.1:  # 10%的概率添加日志
            log_contents = [
                "系统持续监控中，未发现异常",
                "安全组件运行正常，资源使用率稳定",
                "网络流量分析正常，未检测到攻击特征",
                "安全规则库自动更新完成",
                "AI模型持续学习中，防御能力不断提升"
            ]
            add_log("info", random.choice(log_contents))

        # 暂停一小段时间
        time.sleep(5)

def update_security_rates(attack_id=None):
    """更新IDS检测率和防火墙阻断率"""
    defense_scheme = simulator_state["defense_scheme"]

    # 如果attack_id不为None，更新attack_types
    if attack_id is not None:
        if attack_id == 0:
            simulator_state["attack_types"] = []
        elif attack_id == 1:
            simulator_state["attack_types"] = [1]
        elif attack_id == 2:
            simulator_state["attack_types"] = [2]
        elif attack_id == 3:
            simulator_state["attack_types"] = [1, 2]

    attack_types = simulator_state["attack_types"]

    # 更新组件名称 - 简化版本
    if defense_scheme == "traditional":
        # 传统方案使用静态组件
        simulator_state["component_names"] = {
            "ids_agv": "静态IDS-AGV",
            "ids_scheduler": "静态IDS-RCS",
            "fw_agv": "静态防火墙-AGV",
            "fw_scheduler": "静态防火墙-RCS"
        }
    else:
        # AI柔性重组方案使用动态组件
        simulator_state["component_names"] = {
            "ids_agv": "AGV-IDS",
            "ids_scheduler": "RCS-IDS",
            "fw_agv": "AGV-防火墙",
            "fw_scheduler": "RCS-防火墙"
        }

    # 根据防御方案和攻击类型设置检测率和阻断率
    if defense_scheme == "traditional":
        # 传统方案
        if not attack_types:
            # 无攻击
            simulator_state["ids_rate_1"] = "N/A（无攻击发生）"
            simulator_state["ids_rate_2"] = "N/A（无攻击发生）"
            simulator_state["fw_rate_1"] = "N/A（无攻击需阻断）"
            simulator_state["fw_rate_2"] = "N/A（无攻击需阻断）"
        else:
            # 有攻击
            simulator_state["ids_rate_1"] = f"{random.uniform(0.45, 0.55) * 100:.2f}%"
            simulator_state["fw_rate_1"] = f"{random.uniform(0.3, 0.5) * 100:.2f}%"
            simulator_state["ids_rate_2"] = f"{random.uniform(0.35, 0.65) * 100:.2f}%"
            simulator_state["fw_rate_2"] = f"{random.uniform(0.2, 0.6) * 100:.2f}%"
    else:
        # AI柔性重组方案
        if not attack_types:
            # 无攻击
            simulator_state["ids_rate_1"] = "N/A（无攻击发生）"
            simulator_state["ids_rate_2"] = "N/A（无攻击发生）"
            simulator_state["fw_rate_1"] = "N/A（无攻击需阻断）"
            simulator_state["fw_rate_2"] = "N/A（无攻击需阻断）"
        else:
            # 有攻击
            simulator_state["ids_rate_1"] = f"{random.uniform(0.85, 0.98) * 100:.2f}%"
            simulator_state["fw_rate_1"] = f"{random.uniform(0.8, 0.95) * 100:.2f}%"
            simulator_state["ids_rate_2"] = f"{random.uniform(0.85, 0.98) * 100:.2f}%"
            simulator_state["fw_rate_2"] = f"{random.uniform(0.8, 0.95) * 100:.2f}%"

    # 更新安全能力指标 - 只在非攻击状态下更新
    if not attack_types and not simulator_state["is_attacking"]:
        simulator_state["ids_security"] = 0
        simulator_state["fw_security"] = 85
    elif not simulator_state["is_attacking"]:
        # 只在非攻击状态下，根据检测率和阻断率更新安全能力指标
        # 从百分比字符串中提取数值
        ids_rate_1 = float(re.search(r'(\d+\.\d+)', simulator_state["ids_rate_1"] or "0").group(1))
        ids_rate_2 = float(re.search(r'(\d+\.\d+)', simulator_state["ids_rate_2"] or "0").group(1))
        fw_rate_1 = float(re.search(r'(\d+\.\d+)', simulator_state["fw_rate_1"] or "0").group(1))
        fw_rate_2 = float(re.search(r'(\d+\.\d+)', simulator_state["fw_rate_2"] or "0").group(1))

        # 计算平均值作为安全能力指标
        simulator_state["ids_security"] = int((ids_rate_1 + ids_rate_2) / 2)
        simulator_state["fw_security"] = int((fw_rate_1 + fw_rate_2) / 2)
    # 在攻击状态下，安全能力指标由simulate_attack函数中的攻击阶段设置

def add_log(log_type, content):
    """添加日志"""
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    simulator_state["attack_logs"].append({
        "timestamp": timestamp,
        "type": log_type,
        "content": content
    })

def generate_attack_phases():
    """生成攻击阶段"""
    # 根据防御方案生成不同的攻击阶段
    if simulator_state["defense_scheme"] == "traditional":
        return generate_traditional_attack_phases()
    else:
        return generate_flexible_attack_phases()

def generate_traditional_attack_phases():
    """生成传统防御方案的攻击阶段"""
    # 使用visual_interface.py中的数值
    cpu_base = 55
    fluctuation = 2

    return [
        # 阶段1：攻击开始，防火墙开始应对但能力下降
        {
            "idsSecurity": 50,
            "fwSecurity": 70,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "检测到大量异常TCP连接请求，传统防火墙开始过滤",
            "logType": "warning",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段2：防火墙继续抵抗，但能力持续下降
        {
            "idsSecurity": 50,
            "fwSecurity": 55,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "防火墙检测到未授权访问尝试，可能针对AGV控制系统",
            "logType": "warning",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段3：防火墙能力急剧下降
        {
            "idsSecurity": 50,
            "fwSecurity": 40,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "防火墙资源消耗过高，检测能力下降，发现恶意软件特征",
            "logType": "warning",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "高"
        },
        # 阶段4：防火墙即将失效，AGV开始受到影响
        {
            "idsSecurity": 50,
            "fwSecurity": 25,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "防火墙即将过载，检测到针对AGV的异常指令",
            "logType": "error",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "高"
        },
        # 阶段5：防火墙能力低于20%，AGV瘫痪
        {
            "idsSecurity": 50,
            "fwSecurity": 15,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "防火墙能力严重不足，AGV接收到异常停止指令，已紧急停车",
            "logType": "error",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "高"
        },
        # 阶段6：攻击持续，系统无法恢复
        {
            "idsSecurity": 50,
            "fwSecurity": 10,
            "idsCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "idsCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "攻击持续中，传统防御系统无法自动恢复，需要人工干预",
            "logType": "error",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "高"
        }
    ]

def generate_flexible_attack_phases():
    """生成AI柔性重组方案的攻击阶段"""
    # 使用更合理的CPU使用率设置
    # 攻击初期CPU使用率较高，表示系统正在积极应对攻击
    # 攻击后期CPU使用率逐渐降低，表示系统已经有效控制了攻击
    cpu_base = 55
    fluctuation = 2

    return [
        # 阶段1：流量探针检测到异常网络活动
        {
            "idsSecurity": 50,
            "fwSecurity": 70,
            "idsCpu": 75,  # 攻击初期，IDS CPU使用率较高，表示系统正在积极分析流量
            "idsCpu2": 75,
            "fwCpu": 70,  # 攻击初期，防火墙CPU使用率较高，表示系统正在积极过滤流量
            "fwCpu2": 70,
            "log": "流量探针检测到异常网络活动，可能是攻击准备阶段",
            "logType": "warning",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段2：上报给大模型进行深度分析
        {
            "idsSecurity": 60,
            "fwSecurity": 75,
            "idsCpu": 80,  # 分析阶段，IDS CPU使用率进一步提高
            "idsCpu2": 80,
            "fwCpu": 75,  # 分析阶段，防火墙CPU使用率进一步提高
            "fwCpu2": 75,
            "log": "网络探针将异常流量数据上报给大模型进行深度分析",
            "logType": "info",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段3：大模型进行技战术分析
        {
            "idsSecurity": 70,
            "fwSecurity": 80,
            "idsCpu": 65,
            "idsCpu2": 65,
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "大模型基于RAG的网络安全知识库进行技战术分析，识别攻击特征",
            "logType": "info",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段4：生成攻击技战术与缓解措施
        {
            "idsSecurity": 80,
            "fwSecurity": 85,
            "idsCpu": 70,
            "idsCpu2": 70,
            "fwCpu": 65,
            "fwCpu2": 65,
            "log": "大模型生成当前攻击技战术分析：DDoS + 命令注入，并制定对应缓解措施",
            "logType": "info",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段5：开始安全功能重组
        {
            "idsSecurity": 85,
            "fwSecurity": 90,
            "idsCpu": 75,
            "idsCpu2": 75,
            "fwCpu": 70,
            "fwCpu2": 70,
            "log": "大模型下发安全功能柔性重组策略：部署深度检测IDS和自适应防火墙",
            "logType": "info",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段6：安全容器资源分配
        {
            "idsSecurity": 90,
            "fwSecurity": 92,
            "idsCpu": 80,
            "idsCpu2": 80,
            "fwCpu": 75,
            "fwCpu2": 75,
            "log": "根据攻击强度进行安全容器资源动态分配，优先保障关键业务",
            "logType": "info",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "中"
        },
        # 阶段7：重组完成，高效防御
        {
            "idsSecurity": 95,
            "fwSecurity": 95,
            "idsCpu": 85,
            "idsCpu2": 85,
            "fwCpu": 80,
            "fwCpu2": 80,
            "log": "安全功能重组完成，新的IDS和防火墙组件已部署并生效",
            "logType": "success",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "低"
        },
        # 阶段8：攻击被有效阻断
        {
            "idsSecurity": 98,
            "fwSecurity": 97,
            "idsCpu": 75,
            "idsCpu2": 75,
            "fwCpu": 70,
            "fwCpu2": 70,
            "log": "重组后的IDS检测率达到98%，防火墙阻断率达到97%，攻击被有效阻断",
            "logType": "success",
            "agvStatus": True,  # AGV保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "低"
        },
        # 阶段9：系统完全恢复正常
        {
            "idsSecurity": 100,
            "fwSecurity": 99,
            "idsCpu": 40,  # 最终阶段，IDS CPU使用率降低，表示系统已经有效控制了攻击
            "idsCpu2": 40,
            "fwCpu": 35,  # 最终阶段，防火墙CPU使用率降低，表示系统已经有效控制了攻击
            "fwCpu2": 35,
            "log": "AI安全功能柔性重组策略验证有效，攻击完全阻断，系统持续正常运行",
            "logType": "success",
            "agvStatus": True,  # AGV始终保持正常运行
            "idsStatus": True,
            "seconds": 1.5,
            "risk": "低"
        }
    ]

if __name__ == '__main__':
    # 启动Flask应用
    app.run(debug=True, host='0.0.0.0', port=8082)
