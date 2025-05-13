#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
性能数据分析和可视化工具

此脚本用于:
1. 从API获取传统方案和AI方案的性能数据
2. 将数据保存到CSV文件
3. 生成性能对比图表
"""

import os
import json
import time
import csv
import argparse
import requests
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# 设置中文字体支持
try:
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 用来正常显示中文标签
    plt.rcParams['axes.unicode_minus'] = False    # 用来正常显示负号
except:
    print("警告: 无法设置中文字体，图表中的中文可能无法正确显示")

# 配置
API_BASE_URL = "http://127.0.0.1:8082"
DATA_DIR = "performance_data"
CHARTS_DIR = "performance_charts"

# 确保目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)

def get_performance_data():
    """从API获取性能数据"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/performance-stats")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"错误: API返回状态码 {response.status_code}")
            return None
    except Exception as e:
        print(f"获取性能数据时出错: {e}")
        return None

def save_data_to_csv(data, filename=None):
    """将性能数据保存到CSV文件"""
    if not data:
        print("没有数据可保存")
        return None
    
    # 生成文件名，包含时间戳
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_data_{timestamp}.csv"
    
    filepath = os.path.join(DATA_DIR, filename)
    
    # 准备CSV数据
    csv_data = []
    
    # 添加表头
    headers = ["指标", "传统方案", "AI方案"]
    csv_data.append(headers)
    
    # 添加数据行
    csv_data.append(["IDS检测率(%)", data["traditional"]["ids_detection_rate"], data["flexible"]["ids_detection_rate"]])
    csv_data.append(["防火墙拦截率(%)", data["traditional"]["fw_block_rate"], data["flexible"]["fw_block_rate"]])
    csv_data.append(["QPS", data["traditional"]["qps"], data["flexible"]["qps"]])
    csv_data.append(["MTTR(秒)", data["traditional"]["mttr"], data["flexible"]["mttr"]])
    
    # 写入CSV文件
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
        print(f"数据已保存到 {filepath}")
        return filepath
    except Exception as e:
        print(f"保存数据时出错: {e}")
        return None

def generate_bar_chart(data, output_filename=None):
    """生成性能对比柱状图"""
    if not data:
        print("没有数据可绘制")
        return None
    
    # 生成文件名
    if not output_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"performance_comparison_{timestamp}.png"
    
    output_path = os.path.join(CHARTS_DIR, output_filename)
    
    # 设置图表风格
    sns.set(style="whitegrid")
    
    # 创建图表
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('传统方案 vs AI安全功能柔性重组方案性能对比', fontsize=16)
    
    # 准备数据
    metrics = {
        "IDS检测率(%)": {
            "传统方案": data["traditional"]["ids_detection_rate"],
            "AI方案": data["flexible"]["ids_detection_rate"]
        },
        "防火墙拦截率(%)": {
            "传统方案": data["traditional"]["fw_block_rate"],
            "AI方案": data["flexible"]["fw_block_rate"]
        },
        "QPS": {
            "传统方案": data["traditional"]["qps"],
            "AI方案": data["flexible"]["qps"]
        },
        "MTTR(秒)": {
            "传统方案": data["traditional"]["mttr"],
            "AI方案": data["flexible"]["mttr"]
        }
    }
    
    # 颜色设置
    colors = {
        "传统方案": "#FF6B6B",  # 红色
        "AI方案": "#4ECDC4"     # 青色
    }
    
    # 绘制四个子图
    for i, (metric, values) in enumerate(metrics.items()):
        row, col = i // 2, i % 2
        ax = axes[row, col]
        
        # 创建DataFrame
        df = pd.DataFrame({
            "方案": list(values.keys()),
            "值": list(values.values())
        })
        
        # 绘制柱状图
        sns.barplot(x="方案", y="值", data=df, palette=colors, ax=ax)
        
        # 设置标题和标签
        ax.set_title(metric, fontsize=14)
        ax.set_xlabel("")
        
        # 添加数值标签
        for j, p in enumerate(ax.patches):
            height = p.get_height()
            ax.text(p.get_x() + p.get_width()/2.,
                    height + 0.1,
                    f'{height:.2f}',
                    ha="center", fontsize=12)
    
    # 调整布局
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    
    # 保存图表
    try:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"图表已保存到 {output_path}")
        return output_path
    except Exception as e:
        print(f"保存图表时出错: {e}")
        return None
    finally:
        plt.close(fig)

def generate_radar_chart(data, output_filename=None):
    """生成性能对比雷达图"""
    if not data:
        print("没有数据可绘制")
        return None
    
    # 生成文件名
    if not output_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"performance_radar_{timestamp}.png"
    
    output_path = os.path.join(CHARTS_DIR, output_filename)
    
    # 准备数据
    # 对于雷达图，我们需要将所有指标标准化到相同的范围
    categories = ['IDS检测率', '防火墙拦截率', 'QPS', 'MTTR']
    
    # 获取原始值
    traditional_values = [
        data["traditional"]["ids_detection_rate"],
        data["traditional"]["fw_block_rate"],
        data["traditional"]["qps"],
        data["traditional"]["mttr"]
    ]
    
    flexible_values = [
        data["flexible"]["ids_detection_rate"],
        data["flexible"]["fw_block_rate"],
        data["flexible"]["qps"],
        data["flexible"]["mttr"]
    ]
    
    # 标准化数据 (0-1范围)
    # 注意：对于MTTR，较低的值更好，所以我们需要反转标准化
    max_values = []
    for i in range(len(categories)):
        max_val = max(traditional_values[i], flexible_values[i])
        if max_val == 0:  # 避免除以零
            max_val = 1
        max_values.append(max_val)
    
    # 标准化
    traditional_normalized = []
    flexible_normalized = []
    
    for i in range(len(categories)):
        if categories[i] == 'MTTR':
            # 对于MTTR，较低的值更好，所以我们反转标准化
            if max_values[i] == 0:
                traditional_normalized.append(0)
                flexible_normalized.append(0)
            else:
                traditional_normalized.append(1 - (traditional_values[i] / max_values[i]))
                flexible_normalized.append(1 - (flexible_values[i] / max_values[i]))
        else:
            traditional_normalized.append(traditional_values[i] / max_values[i])
            flexible_normalized.append(flexible_values[i] / max_values[i])
    
    # 创建雷达图
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, polar=True)
    
    # 设置角度
    angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
    angles += angles[:1]  # 闭合雷达图
    
    # 添加数据
    traditional_normalized += traditional_normalized[:1]  # 闭合数据
    flexible_normalized += flexible_normalized[:1]  # 闭合数据
    
    # 绘制雷达图
    ax.plot(angles, traditional_normalized, 'o-', linewidth=2, label='传统方案', color='#FF6B6B')
    ax.fill(angles, traditional_normalized, alpha=0.25, color='#FF6B6B')
    
    ax.plot(angles, flexible_normalized, 'o-', linewidth=2, label='AI方案', color='#4ECDC4')
    ax.fill(angles, flexible_normalized, alpha=0.25, color='#4ECDC4')
    
    # 设置标签
    ax.set_thetagrids(np.degrees(angles[:-1]), categories)
    
    # 添加图例和标题
    ax.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    plt.title('传统方案 vs AI安全功能柔性重组方案性能对比 (雷达图)', fontsize=15)
    
    # 保存图表
    try:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"雷达图已保存到 {output_path}")
        return output_path
    except Exception as e:
        print(f"保存雷达图时出错: {e}")
        return None
    finally:
        plt.close(fig)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='性能数据分析和可视化工具')
    parser.add_argument('--collect', action='store_true', help='从API收集数据')
    parser.add_argument('--file', type=str, help='使用指定的CSV文件生成图表')
    parser.add_argument('--output', type=str, help='输出文件名前缀')
    args = parser.parse_args()
    
    data = None
    
    if args.collect:
        print("从API收集性能数据...")
        data = get_performance_data()
        if data:
            output_prefix = args.output if args.output else datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_file = f"{output_prefix}_data.csv"
            save_data_to_csv(data, csv_file)
    elif args.file:
        print(f"从文件 {args.file} 加载数据...")
        try:
            # 从CSV文件加载数据
            filepath = os.path.join(DATA_DIR, args.file)
            df = pd.read_csv(filepath)
            
            # 将数据转换为API格式
            data = {
                "traditional": {
                    "ids_detection_rate": float(df[df['指标'] == 'IDS检测率(%)']['传统方案'].values[0]),
                    "fw_block_rate": float(df[df['指标'] == '防火墙拦截率(%)']['传统方案'].values[0]),
                    "qps": float(df[df['指标'] == 'QPS']['传统方案'].values[0]),
                    "mttr": float(df[df['指标'] == 'MTTR(秒)']['传统方案'].values[0])
                },
                "flexible": {
                    "ids_detection_rate": float(df[df['指标'] == 'IDS检测率(%)']['AI方案'].values[0]),
                    "fw_block_rate": float(df[df['指标'] == '防火墙拦截率(%)']['AI方案'].values[0]),
                    "qps": float(df[df['指标'] == 'QPS']['AI方案'].values[0]),
                    "mttr": float(df[df['指标'] == 'MTTR(秒)']['AI方案'].values[0])
                }
            }
        except Exception as e:
            print(f"加载数据时出错: {e}")
            return
    else:
        print("从API收集性能数据...")
        data = get_performance_data()
    
    if data:
        output_prefix = args.output if args.output else datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 生成柱状图
        bar_chart_file = f"{output_prefix}_bar.png"
        generate_bar_chart(data, bar_chart_file)
        
        # 生成雷达图
        radar_chart_file = f"{output_prefix}_radar.png"
        generate_radar_chart(data, radar_chart_file)
        
        print("图表生成完成！")
    else:
        print("没有数据可用于生成图表")

if __name__ == "__main__":
    main()
