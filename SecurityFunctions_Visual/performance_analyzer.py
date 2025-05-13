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

# 使用英文字体，避免中文乱码问题
plt.rcParams['font.sans-serif'] = ['Arial']
plt.rcParams['axes.unicode_minus'] = False

# 配置
API_BASE_URL = "http://127.0.0.1:8082"
DATA_DIR = "performance_data"
CHARTS_DIR = "performance_charts"

# 确保目录存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)

def get_performance_data():
    """Get performance data from API"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/performance-stats")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: API returned status code {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting performance data: {e}")
        return None

def save_data_to_csv(data, filename=None):
    """Save performance data to CSV file"""
    if not data:
        print("No data to save")
        return None

    # Generate filename with timestamp
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_data_{timestamp}.csv"

    filepath = os.path.join(DATA_DIR, filename)

    # Prepare CSV data
    csv_data = []

    # Add headers
    headers = ["Metric", "Traditional", "AI-based"]
    csv_data.append(headers)

    # Add data rows
    csv_data.append(["IDS Detection Rate(%)", data["traditional"]["ids_detection_rate"], data["flexible"]["ids_detection_rate"]])
    csv_data.append(["Firewall Block Rate(%)", data["traditional"]["fw_block_rate"], data["flexible"]["fw_block_rate"]])
    csv_data.append(["QPS", data["traditional"]["qps"], data["flexible"]["qps"]])
    csv_data.append(["MTTR(sec)", data["traditional"]["mttr"], data["flexible"]["mttr"]])

    # Write to CSV file
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
        print(f"Data saved to {filepath}")
        return filepath
    except Exception as e:
        print(f"Error saving data: {e}")
        return None

def generate_bar_chart(data, output_filename=None):
    """Generate performance comparison bar chart"""
    if not data:
        print("No data to plot")
        return None

    # Generate filename
    if not output_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"performance_comparison_{timestamp}.png"

    output_path = os.path.join(CHARTS_DIR, output_filename)

    # Set chart style
    sns.set(style="whitegrid")

    # Create chart
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Traditional vs AI-based Security Function Reorganization Performance Comparison', fontsize=16)

    # Prepare data
    metrics = {
        "IDS Detection Rate(%)": {
            "Traditional": data["traditional"]["ids_detection_rate"],
            "AI-based": data["flexible"]["ids_detection_rate"]
        },
        "Firewall Block Rate(%)": {
            "Traditional": data["traditional"]["fw_block_rate"],
            "AI-based": data["flexible"]["fw_block_rate"]
        },
        "QPS": {
            "Traditional": data["traditional"]["qps"],
            "AI-based": data["flexible"]["qps"]
        },
        "MTTR(sec)": {
            "Traditional": data["traditional"]["mttr"],
            "AI-based": data["flexible"]["mttr"]
        }
    }

    # Color settings
    colors = {
        "Traditional": "#FF6B6B",  # Red
        "AI-based": "#4ECDC4"      # Cyan
    }

    # Draw four subplots
    for i, (metric, values) in enumerate(metrics.items()):
        row, col = i // 2, i % 2
        ax = axes[row, col]

        # Create DataFrame
        df = pd.DataFrame({
            "Strategy": list(values.keys()),
            "Value": list(values.values())
        })

        # Draw bar plot
        sns.barplot(x="Strategy", y="Value", data=df, palette=colors, ax=ax)

        # Set title and labels
        ax.set_title(metric, fontsize=14)
        ax.set_xlabel("")

        # Add value labels
        for j, p in enumerate(ax.patches):
            height = p.get_height()
            ax.text(p.get_x() + p.get_width()/2.,
                    height + 0.1,
                    f'{height:.2f}',
                    ha="center", fontsize=12)

    # Adjust layout
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    # Save chart
    try:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Chart saved to {output_path}")
        return output_path
    except Exception as e:
        print(f"Error saving chart: {e}")
        return None
    finally:
        plt.close(fig)

def generate_radar_chart(data, output_filename=None):
    """Generate performance comparison radar chart"""
    if not data:
        print("No data to plot")
        return None

    # Generate filename
    if not output_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"performance_radar_{timestamp}.png"

    output_path = os.path.join(CHARTS_DIR, output_filename)

    # Prepare data
    # For radar chart, we need to normalize all metrics to the same range
    categories = ['IDS Detection', 'Firewall Block', 'QPS', 'MTTR']

    # Get original values
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

    # Normalize data (0-1 range)
    # Note: For MTTR, lower values are better, so we need to invert the normalization
    max_values = []
    for i in range(len(categories)):
        max_val = max(traditional_values[i], flexible_values[i])
        if max_val == 0:  # Avoid division by zero
            max_val = 1
        max_values.append(max_val)

    # Normalize
    traditional_normalized = []
    flexible_normalized = []

    for i in range(len(categories)):
        if categories[i] == 'MTTR':
            # For MTTR, lower values are better, so we invert the normalization
            if max_values[i] == 0:
                traditional_normalized.append(0)
                flexible_normalized.append(0)
            else:
                traditional_normalized.append(1 - (traditional_values[i] / max_values[i]))
                flexible_normalized.append(1 - (flexible_values[i] / max_values[i]))
        else:
            traditional_normalized.append(traditional_values[i] / max_values[i])
            flexible_normalized.append(flexible_values[i] / max_values[i])

    # Create radar chart
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, polar=True)

    # Set angles
    angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
    angles += angles[:1]  # Close the radar chart

    # Add data
    traditional_normalized += traditional_normalized[:1]  # Close the data
    flexible_normalized += flexible_normalized[:1]  # Close the data

    # Draw radar chart
    ax.plot(angles, traditional_normalized, 'o-', linewidth=2, label='Traditional', color='#FF6B6B')
    ax.fill(angles, traditional_normalized, alpha=0.25, color='#FF6B6B')

    ax.plot(angles, flexible_normalized, 'o-', linewidth=2, label='AI-based', color='#4ECDC4')
    ax.fill(angles, flexible_normalized, alpha=0.25, color='#4ECDC4')

    # Set labels
    ax.set_thetagrids(np.degrees(angles[:-1]), categories)

    # Add legend and title
    ax.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    plt.title('Traditional vs AI-based Security Function Reorganization (Radar Chart)', fontsize=15)

    # Save chart
    try:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Radar chart saved to {output_path}")
        return output_path
    except Exception as e:
        print(f"Error saving radar chart: {e}")
        return None
    finally:
        plt.close(fig)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Performance Data Analysis and Visualization Tool')
    parser.add_argument('--collect', action='store_true', help='Collect data from API')
    parser.add_argument('--file', type=str, help='Use specified CSV file to generate charts')
    parser.add_argument('--output', type=str, help='Output filename prefix')
    args = parser.parse_args()

    data = None

    if args.collect:
        print("Collecting performance data from API...")
        data = get_performance_data()
        if data:
            output_prefix = args.output if args.output else datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_file = f"{output_prefix}_data.csv"
            save_data_to_csv(data, csv_file)
    elif args.file:
        print(f"Loading data from file {args.file}...")
        try:
            # Load data from CSV file
            filepath = os.path.join(DATA_DIR, args.file)
            df = pd.read_csv(filepath)

            # Convert data to API format
            data = {
                "traditional": {
                    "ids_detection_rate": float(df[df['Metric'] == 'IDS Detection Rate(%)']['Traditional'].values[0]),
                    "fw_block_rate": float(df[df['Metric'] == 'Firewall Block Rate(%)']['Traditional'].values[0]),
                    "qps": float(df[df['Metric'] == 'QPS']['Traditional'].values[0]),
                    "mttr": float(df[df['Metric'] == 'MTTR(sec)']['Traditional'].values[0])
                },
                "flexible": {
                    "ids_detection_rate": float(df[df['Metric'] == 'IDS Detection Rate(%)']['AI-based'].values[0]),
                    "fw_block_rate": float(df[df['Metric'] == 'Firewall Block Rate(%)']['AI-based'].values[0]),
                    "qps": float(df[df['Metric'] == 'QPS']['AI-based'].values[0]),
                    "mttr": float(df[df['Metric'] == 'MTTR(sec)']['AI-based'].values[0])
                }
            }
        except Exception as e:
            print(f"Error loading data: {e}")
            return
    else:
        print("Collecting performance data from API...")
        data = get_performance_data()

    if data:
        output_prefix = args.output if args.output else datetime.now().strftime("%Y%m%d_%H%M%S")

        # Generate bar chart
        bar_chart_file = f"{output_prefix}_bar.png"
        generate_bar_chart(data, bar_chart_file)

        # Generate radar chart
        radar_chart_file = f"{output_prefix}_radar.png"
        generate_radar_chart(data, radar_chart_file)

        print("Charts generation completed!")
    else:
        print("No data available for chart generation")

if __name__ == "__main__":
    main()
