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
        "ids_agv": "static-IDS-1",
        "ids_scheduler": "static-IDS-2",
        "fw_agv": "static-FW-1",
        "fw_scheduler": "static-FW-2"
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
    simulator_state["defense_scheme"] = data.get("scheme")

    # 更新IDS检测率和防火墙阻断率
    update_security_rates()

    return jsonify({"status": "success", "message": f"已设置防御方案: {data.get('scheme')}"})

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
                "ids_agv": "static-IDS-1",
                "ids_scheduler": "static-IDS-2",
                "fw_agv": "static-FW-1",
                "fw_scheduler": "static-FW-2"
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

            # 重置组件名称
            simulator_state["component_names"] = {
                "ids_agv": "static-IDS-1",
                "ids_scheduler": "static-IDS-2",
                "fw_agv": "static-FW-1",
                "fw_scheduler": "static-FW-2"
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

    # 更新IDS检测率和防火墙阻断率
    update_security_rates()

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
            if not simulator_state["attack_types"]:
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
            if simulator_state["attack_types"]:
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

            # 计算CPU使用率 - 完全按照visual_interface.py的计算方式
            ids_cpu_agv = random.uniform(15, 45) + ids_agv_alloc * 0.5
            ids_cpu_sched = random.uniform(15, 45) + ids_sched_alloc * 0.5
            fw_cpu_agv = random.uniform(15, 50) + fw_agv_alloc * 0.7
            fw_cpu_sched = random.uniform(15, 50) + fw_sched_alloc * 0.7

            # 更新状态
            simulator_state["ids_cpu_usage"] = ids_cpu_agv
            simulator_state["ids_cpu_usage_2"] = ids_cpu_sched
            simulator_state["fw_cpu_usage"] = fw_cpu_agv
            simulator_state["fw_cpu_usage_2"] = fw_cpu_sched

            # AI方案：QPS高，MTTR低 - 使变化更加平滑
            if simulator_state["attack_types"]:
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

        # 更新资源分配情况
        if simulator_state["defense_scheme"] == "flexible" and simulator_state["attack_types"]:
            # 柔性重组方案在攻击时，资源分配较高
            simulator_state["resource_allocation"] = {
                "IDS-AGV": random.uniform(65, 85),
                "IDS-Scheduler": random.uniform(65, 85),
                "Firewall-AGV": random.uniform(75, 95),
                "Firewall-Scheduler": random.uniform(75, 95),
            }
        else:
            # 其他情况下，资源分配较低
            simulator_state["resource_allocation"] = {
                "IDS-AGV": random.uniform(25, 35),
                "IDS-Scheduler": random.uniform(25, 35),
                "Firewall-AGV": random.uniform(30, 40),
                "Firewall-Scheduler": random.uniform(30, 40),
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
        add_log("info", "网络探针将异常流量数据上报给大模型进行分析")

        # 根据攻击类型生成不同的分析结果，不再添加延时
        attack_types = simulator_state["attack_types"]
        if 1 in attack_types and 2 in attack_types:
            add_log("info", "大模型分析：检测到针对AGV和调度系统的复合攻击")
            add_log("info", "大模型识别攻击技战术：DDoS + 命令注入 + 权限提升")
            add_log("info", "大模型下发安全功能柔性重组策略：部署深度检测IDS和自适应防火墙")
        elif 1 in attack_types:
            add_log("info", "大模型分析：检测到针对AGV控制系统的攻击")
            add_log("info", "大模型识别攻击技战术：工控系统缓冲区溢出攻击")
            add_log("info", "大模型下发安全功能柔性重组策略：部署AGV专用深度检测IDS和自适应防火墙")
        elif 2 in attack_types:
            add_log("info", "大模型分析：检测到针对调度系统的攻击")
            add_log("info", "大模型识别攻击技战术：SQL注入 + 权限提升攻击")
            add_log("info", "大模型下发安全功能柔性重组策略：部署调度系统专用深度检测IDS和自适应防火墙")

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

        # 平滑过渡到目标值 - 分3个小步骤，加快响应速度
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

            # 暂停一小段时间
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

        # 在AI柔性重组方案中，添加额外的日志
        if simulator_state["defense_scheme"] != "traditional" and i == len(phases) // 3:
            add_log("info", "安全功能重组完成，新的IDS和防火墙组件已部署")
            if 1 in simulator_state["attack_types"]:
                add_log("info", f"重组IDS-AGV(深度检测)已启动，检测率提升至{simulator_state['ids_rate_1']}")
            if 2 in simulator_state["attack_types"]:
                add_log("info", f"重组IDS-调度系统(深度检测)已启动，检测率提升至{simulator_state['ids_rate_2']}")

        # 根据当前阶段更新IDS检测率和防火墙阻断率
        if simulator_state["defense_scheme"] == "traditional":
            # 传统方案随着攻击进行，检测率和阻断率逐渐降低
            progress_factor = 1.0 - (i / len(phases))  # 从1.0降到接近0
            simulator_state["ids_rate_1"] = f"{max(5, random.uniform(0.45, 0.55) * 100 * progress_factor):.2f}%"
            simulator_state["fw_rate_1"] = f"{max(5, random.uniform(0.3, 0.5) * 100 * progress_factor):.2f}%"
            simulator_state["ids_rate_2"] = f"{max(5, random.uniform(0.35, 0.65) * 100 * progress_factor):.2f}%"
            simulator_state["fw_rate_2"] = f"{max(5, random.uniform(0.2, 0.6) * 100 * progress_factor):.2f}%"
        else:
            # AI柔性重组方案随着攻击进行，检测率和阻断率先降低后提高
            if i < len(phases) / 2:
                # 前半段：能力下降
                progress_factor = 1.0 - (i / (len(phases) / 2))  # 从1.0降到接近0
                simulator_state["ids_rate_1"] = f"{max(10, random.uniform(0.85, 0.98) * 100 * progress_factor):.2f}%"
                simulator_state["fw_rate_1"] = f"{max(10, random.uniform(0.8, 0.95) * 100 * progress_factor):.2f}%"
                simulator_state["ids_rate_2"] = f"{max(10, random.uniform(0.85, 0.98) * 100 * progress_factor):.2f}%"
                simulator_state["fw_rate_2"] = f"{max(10, random.uniform(0.8, 0.95) * 100 * progress_factor):.2f}%"
            else:
                # 后半段：能力恢复并提高
                progress_factor = (i - len(phases) / 2) / (len(phases) / 2)  # 从接近0增加到1.0
                simulator_state["ids_rate_1"] = f"{min(100, 10 + random.uniform(0.85, 0.98) * 100 * progress_factor):.2f}%"
                simulator_state["fw_rate_1"] = f"{min(100, 10 + random.uniform(0.8, 0.95) * 100 * progress_factor):.2f}%"
                simulator_state["ids_rate_2"] = f"{min(100, 10 + random.uniform(0.85, 0.98) * 100 * progress_factor):.2f}%"
                simulator_state["fw_rate_2"] = f"{min(100, 10 + random.uniform(0.8, 0.95) * 100 * progress_factor):.2f}%"

        # 添加日志
        add_log(phase["logType"], phase["log"])

        # 不再在阶段之间添加延时，加快响应速度
        # time.sleep(phase["seconds"])

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
    else:
        # AI柔性重组方案：攻击结束后，系统成功恢复
        simulator_state["is_attacking"] = False
        simulator_state["attacks_blocked"] += 1
        simulator_state["attack_types"] = []

        # 重置安全能力指标
        simulator_state["ids_security"] = 0
        simulator_state["fw_security"] = 85

        # 重置AGV和IDS状态
        simulator_state["agv_active"] = True
        simulator_state["ids_active"] = True

        # 重置风险等级
        simulator_state["risk_level"] = "低"

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
            "ids_agv": "static-IDS-1",
            "ids_scheduler": "static-IDS-2",
            "fw_agv": "static-FW-1",
            "fw_scheduler": "static-FW-2"
        }

        # 添加成功恢复的日志
        add_log("success", "大模型安全功能柔性重组成功，系统已恢复正常")

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

    # 更新组件名称 - 与visual_interface.py保持一致
    if defense_scheme == "traditional":
        # 传统方案使用静态组件
        simulator_state["component_names"] = {
            "ids_agv": "static-IDS-1",
            "ids_scheduler": "static-IDS-2",
            "fw_agv": "static-FW-1",
            "fw_scheduler": "static-FW-2"
        }
    else:
        # AI柔性重组方案使用动态组件
        if not attack_types:
            # 无攻击时使用静态组件
            simulator_state["component_names"] = {
                "ids_agv": "static-IDS-1",
                "ids_scheduler": "static-IDS-2",
                "fw_agv": "static-FW-1",
                "fw_scheduler": "static-FW-2"
            }
        else:
            # 有攻击时使用重组后的组件
            simulator_state["component_names"] = {
                "ids_agv": "AGV-IDS",
                "ids_scheduler": "RCS-IDS",
                "fw_agv": "AGV-FW",
                "fw_scheduler": "RCS-FW"
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
            "risk": "高"
        }
    ]

def generate_flexible_attack_phases():
    """生成AI柔性重组方案的攻击阶段"""
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
            "log": "检测到大量异常TCP连接请求，初始防火墙开始过滤",
            "logType": "warning",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
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
            "seconds": 0.5,
            "risk": "高"
        },
        # 阶段6：大模型检测到问题，开始部署IDS
        {
            "idsSecurity": 50,
            "fwSecurity": 15,
            "idsCpu": 65,
            "idsCpu2": 65,
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "大模型检测到网络态势异常，开始安全功能柔性重组，部署新的IDS安全容器进行深度分析",
            "logType": "info",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "高"
        },
        # 阶段7：IDS启动，开始检测
        {
            "idsSecurity": 70,
            "fwSecurity": 18,
            "idsCpu": 75,
            "idsCpu2": 75,
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "重组后的IDS容器已启动，开始深度数据包分析，学习攻击特征",
            "logType": "info",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "高"
        },
        # 阶段8：IDS检测率提高，下发重组策略
        {
            "idsSecurity": 80,
            "fwSecurity": 25,
            "idsCpu": 85,
            "idsCpu2": 85,
            "fwCpu": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "fwCpu2": random.uniform(cpu_base - fluctuation, cpu_base + fluctuation),
            "log": "大模型下发安全功能柔性重组策略第二阶段：IDS+FW联合防御，优化检测规则",
            "logType": "info",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "高"
        },
        # 阶段9：IDS检测率继续提高，防火墙开始恢复
        {
            "idsSecurity": 90,
            "fwSecurity": 40,
            "idsCpu": 90,
            "idsCpu2": 90,
            "fwCpu": 85,
            "fwCpu2": 85,
            "log": "重组后的IDS成功识别攻击特征，开始向重组后的防火墙推送新规则",
            "logType": "info",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "高"
        },
        # 阶段10：IDS检测率接近完善，防火墙继续恢复
        {
            "idsSecurity": 95,
            "fwSecurity": 65,
            "idsCpu": 80,
            "idsCpu2": 80,
            "fwCpu": 70,
            "fwCpu2": 70,
            "log": "重组后的IDS+防火墙联合防御生效，开始隔离恶意控制流量",
            "logType": "info",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "中"
        },
        # 阶段11：IDS检测率达到100%，防火墙能力大幅提升
        {
            "idsSecurity": 100,
            "fwSecurity": 85,
            "idsCpu": 70,
            "idsCpu2": 70,
            "fwCpu": 60,
            "fwCpu2": 60,
            "log": "重组后的IDS检测率达到100%，攻击特征完全识别，重组后的防火墙规则优化完成",
            "logType": "success",
            "agvStatus": False,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "中"
        },
        # 阶段12：攻击被完全阻断，AGV恢复
        {
            "idsSecurity": 100,
            "fwSecurity": 95,
            "idsCpu": 40,
            "idsCpu2": 40,
            "fwCpu": 40,
            "fwCpu2": 40,
            "log": "AI安全功能柔性重组策略验证有效，攻击已被完全阻断，AGV恢复正常运行",
            "logType": "success",
            "agvStatus": True,
            "idsStatus": True,
            "seconds": 0.5,
            "risk": "低"
        }
    ]

if __name__ == '__main__':
    # 启动Flask应用
    app.run(debug=True, host='0.0.0.0', port=8081)
