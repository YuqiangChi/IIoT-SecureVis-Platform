#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智慧工厂安全防御仿真系统

功能流程：
- 启动选择防御方案（传统方案或AI安全功能柔性重组方案）
- 根据选择，决定攻击类型（无攻击，攻击AGV，攻击调度，或同时攻击）
- AI柔性方案保持原分析流程及详细交互展示
- 实时监控界面包括流量、CPU占用、检测率、阻断率等
- 程序退出时输出最终MTTR与平均QPS
- 按 Ctrl+C 退出程序
"""

import random
import time
import sys
from threading import Event
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

console = Console()


class Simulator:
    def __init__(self):
        self.time_step = 0.5  # 刷新间隔秒
        self.defense_scheme = None  # 'traditional' 或 'flexible'
        self.attack_types = []  # []无攻击，[1, 2]编码对应攻击类型
        self.running = True

        self.attack_traffic = {}  # 攻击类型对应流量字典

        self.mttr = 0.0  # 平均修复时间（秒）
        self.container_qps = 0  # 容器每秒查询数

        self.resource_allocation = {
            "IDS-AGV": 0,
            "IDS-Scheduler": 0,
            "Firewall-AGV": 0,
            "Firewall-Scheduler": 0,
        }

        self.preprocess_done = Event()

    def prompt_defense_scheme(self):
        console.print("[bold green]请选择安全防御方案：[/]")
        console.print(" [bold]1[/]. 传统防御方案")
        console.print(" [bold]2[/]. AI安全功能柔性重组方案")
        while True:
            choice = console.input("请输入方案编号 (1/2): ").strip()
            if choice == "1":
                self.defense_scheme = "traditional"
                break
            elif choice == "2":
                self.defense_scheme = "flexible"
                break
            console.print("[red]无效输入，请输入 1 或 2[/]")

    def prompt_attack_type(self):
        console.print("\n[bold green]请选择攻击方式（直接回车默认无攻击）：[/]")
        console.print(" [bold]0[/]. 无攻击")
        console.print(" [bold]1[/]. 攻击AGV控制系统")
        console.print(" [bold]2[/]. 攻击调度系统")
        console.print(" [bold]3[/]. 同时攻击AGV和调度系统")
        while True:
            choice = console.input("请输入攻击编号 (0/1/2/3): ").strip()
            if choice == "" or choice == "0":
                self.attack_types = []
                self.attack_traffic = {}
                break
            elif choice == "1":
                self.attack_types = [1]
                self.attack_traffic = {1: int(console.input("请输入AGV攻击的数据量 (默认2000): ") or 2000)}
                break
            elif choice == "2":
                self.attack_types = [2]
                self.attack_traffic = {2: int(console.input("请输入调度系统攻击的数据量 (默认1500): ") or 1500)}
                break
            elif choice == "3":
                self.attack_types = [1, 2]
                agv_volume = int(console.input("请输入AGV攻击的数据量 (默认2000): ") or 2000)
                rcs_volume = int(console.input("请输入调度系统攻击的数据量 (默认1500): ") or 1500)
                self.attack_traffic = {1: agv_volume, 2: rcs_volume}
                break
            console.print("[red]无效输入，请重试[/]")

    def simulate_normal_traffic(self):
        return random.randint(200, 600)

    def simulate_cpu_usage(self):
        if self.defense_scheme == "traditional":
            ids_cpu_1 = random.uniform(20, 60)
            ids_cpu_2 = random.uniform(20, 60)
            fw_cpu_1 = random.uniform(20, 60)
            fw_cpu_2 = random.uniform(20, 60)
            return ids_cpu_1, ids_cpu_2, fw_cpu_1, fw_cpu_2
        else:
            ids_cpu_agv = random.uniform(15, 45) + self.resource_allocation.get("IDS-AGV", 0) * 0.5
            ids_cpu_sched = random.uniform(15, 45) + self.resource_allocation.get("IDS-Scheduler", 0) * 0.5
            fw_cpu_agv = random.uniform(15, 50) + self.resource_allocation.get("Firewall-AGV", 0) * 0.7
            fw_cpu_sched = random.uniform(15, 50) + self.resource_allocation.get("Firewall-Scheduler", 0) * 0.7
            return ids_cpu_agv, ids_cpu_sched, fw_cpu_agv, fw_cpu_sched

    def flexible_defense_preprocess(self):
        console.clear()
        console.print("[bold cyan]流量探针检测到异常网络活动[/bold cyan]")
        time.sleep(1)
        console.print("[bold cyan]上报给大模型进行深度分析...[/bold cyan]")
        time.sleep(1.5)

        attack_desc = []
        for atk in self.attack_types:
            if atk == 1:
                attack_desc.append("AGV控制系统")
            elif atk == 2:
                attack_desc.append("调度系统")
        attacks_str = "与".join(attack_desc) if attack_desc else "无攻击"
        console.print(f"[bold red]检测到针对[{attacks_str}]的网络攻击！[/bold red]")
        time.sleep(1.7)

        console.print("[bold yellow]大模型分析当前技战术与缓解措施中...[/bold yellow]")
        time.sleep(2)

        total_volume = sum(self.attack_traffic.values()) if self.attack_traffic else 1
        self.resource_allocation.clear()
        for attack_id, volume in self.attack_traffic.items():
            base_alloc = 50
            proportion = volume / total_volume
            allocated = min(100, base_alloc + proportion * 50)
            if attack_id == 1:
                self.resource_allocation["IDS-AGV"] = allocated
                self.resource_allocation["Firewall-AGV"] = min(100, allocated * 1.2)
            elif attack_id == 2:
                self.resource_allocation["IDS-Scheduler"] = allocated
                self.resource_allocation["Firewall-Scheduler"] = min(100, allocated * 1.2)

        if 1 in self.attack_types and 2 in self.attack_types:
            console.print("[yellow]技战术: DDoS + 命令注入[/yellow]")
            console.print("[yellow]缓解措施:[/yellow]")
            console.print(" · IDS-AGV + 防火墙 混合防护，部署高优先级容器")
            console.print(" · IDS-Scheduler + 防火墙 混合防护，部署高优先级容器")
        elif 1 in self.attack_types:
            console.print("[yellow]技战术: 工控系统缓冲区溢出攻击[/yellow]")
            console.print("[yellow]缓解措施: IDS-AGV + 防火墙 增强版应急防护[/yellow]")
        elif 2 in self.attack_types:
            console.print("[yellow]技战术: SQL注入 + 权限提升攻击[/yellow]")
            console.print("[yellow]缓解措施: IDS-Scheduler + 防火墙 加强访问控制[/yellow]")
        else:
            console.print("[green]当前无检测到攻击，维持正常防护策略[/green]")

        console.print("\n[bold cyan]安全资源分配情况:[/bold cyan]")
        for comp, val in self.resource_allocation.items():
            console.print(f" · {comp} 资源分配: {val:.1f}%")

        # 预处理完成时暂不显示MTTR、QPS，后续运行时动态更新
        self.mttr = random.uniform(0.5, 1.5)
        self.container_qps = random.randint(800, 1500)

        self.preprocess_done.set()

    def build_panel(self):
        safety_data = self.simulate_normal_traffic()
        agv_attack_data = self.attack_traffic.get(1, 0)
        rcs_attack_data = self.attack_traffic.get(2, 0)
        total_flow = safety_data + agv_attack_data + rcs_attack_data

        if self.defense_scheme == "traditional":
            # 传统方案：无攻击时资源消耗较低，攻击时资源消耗较高且稍微波动
            if not self.attack_types:
                cpu_base = 30
                fluctuation = 2
                ids_rate_1 = ids_rate_2 = "N/A（无攻击发生）"
                fw_rate_1 = fw_rate_2 = "N/A（无攻击需阻断）"
            else:
                cpu_base = 55
                fluctuation = 2
                ids_rate_1 = f"{random.uniform(0.45, 0.55) * 100:.2f}%"
                fw_rate_1 = f"{random.uniform(0.3, 0.5) * 100:.2f}%"
                ids_rate_2 = f"{random.uniform(0.35, 0.65) * 100:.2f}%"
                fw_rate_2 = f"{random.uniform(0.2, 0.6) * 100:.2f}%"

            ids_cpu_1 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            ids_cpu_2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            fw_cpu_1 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)
            fw_cpu_2 = random.uniform(cpu_base - fluctuation, cpu_base + fluctuation)

            if not self.attack_types:
                self.mttr = max(0.65, min(0.75, getattr(self, "mttr", 0.7) + random.uniform(-0.02, 0.02)))
                self.container_qps = random.randint(400, 500)
            else:
                self.mttr = max(2.23, min(3.18, getattr(self, "mttr", 2.73) + random.uniform(-0.02, 0.02)))
                self.container_qps = random.randint(140, 200)

        else:
            ids_cpu_agv = random.uniform(15, 45) + self.resource_allocation.get("IDS-AGV", 0) * 0.5
            ids_cpu_sched = random.uniform(15, 45) + self.resource_allocation.get("IDS-Scheduler", 0) * 0.5
            fw_cpu_agv = random.uniform(15, 50) + self.resource_allocation.get("Firewall-AGV", 0) * 0.7
            fw_cpu_sched = random.uniform(15, 50) + self.resource_allocation.get("Firewall-Scheduler", 0) * 0.7

            if not self.attack_types:
                ids_rate = "N/A（无攻击发生）"
                fw_rate = "N/A（无攻击需阻断）"
                ids_rate_1 = ids_rate_2 = "N/A（无攻击发生）"
                fw_rate_1 = fw_rate_2 = "N/A（无攻击需阻断）"
            else:
                # ids_rate = f"{random.uniform(0.85, 0.98) * 100:.2f}%"
                # fw_rate = f"{random.uniform(0.8, 0.95) * 100:.2f}%"
                ids_rate_1 = f"{random.uniform(0.85, 0.98) * 100:.2f}%"
                fw_rate_1 = f"{random.uniform(0.8, 0.95) * 100:.2f}%"
                ids_rate_2 = f"{random.uniform(0.85, 0.98) * 100:.2f}%"
                fw_rate_2 = f"{random.uniform(0.8, 0.95) * 100:.2f}%"

            if self.attack_types:
                self.mttr = max(0.7, min(0.9, getattr(self, "mttr", 0.8) + random.uniform(-0.05, 0.05)))
                self.container_qps = random.randint(800, 1000)
            else:
                self.mttr = max(0.2, min(0.5, getattr(self, "mttr", 0.35) + random.uniform(-0.05, 0.05)))
                self.container_qps = random.randint(700, 800)


        flow_table = Table.grid(expand=True)
        flow_table.add_column(justify="left")
        flow_table.add_column(justify="right")
        flow_table.add_row("当前安全数据量 (条/秒):", f"[bold green]{safety_data}[/]")
        flow_table.add_row("当前AGV攻击数据量 (条/秒):", f"[bold red]{agv_attack_data}[/]")
        flow_table.add_row("当前调度系统攻击数据量 (条/秒):", f"[bold red]{rcs_attack_data}[/]")
        mode_desc = "无攻击状态" if not self.attack_types else "攻击中"
        flow_table.add_row("当前模式:", f"{self.defense_scheme} - {mode_desc}")

        resource_table = Table(title="安全功能资源占用", expand=True)
        resource_table.add_column("组件")
        resource_table.add_column("CPU占用率(%)", justify="right")
        resource_table.add_column("状态指标", justify="right")

        if self.defense_scheme == "traditional":
            resource_table.add_row("static-IDS-1", f"{ids_cpu_1:.1f}", f"检测率: {ids_rate_1}")
            resource_table.add_row("static-IDS-2", f"{ids_cpu_2:.1f}", f"检测率: {ids_rate_2}")
            resource_table.add_row("static-FW-1", f"{fw_cpu_1:.1f}", f"阻断率: {fw_rate_1}")
            resource_table.add_row("static-FW-2", f"{fw_cpu_2:.1f}", f"阻断率: {fw_rate_2}")
        else:
            resource_table.add_row("AGV-IDS", f"{ids_cpu_agv:.1f}", f"检测率: {ids_rate_1}")
            resource_table.add_row("RCS-IDS", f"{ids_cpu_sched:.1f}", f"检测率: {ids_rate_2}")
            resource_table.add_row("AGV-FW", f"{fw_cpu_agv:.1f}", f"阻断率: {fw_rate_1}")
            resource_table.add_row("RCS-FW", f"{fw_cpu_sched:.1f}", f"阻断率: {fw_rate_2}")

        perf_table = Table.grid(expand=True)
        perf_table.add_column(justify="left")
        perf_table.add_column(justify="right")

        if self.preprocess_done.is_set():
            perf_table.add_row("平均安全响应时间(MTTR):", f"[bold green]{self.mttr:.2f}秒[/]")
            perf_table.add_row("安全容器QPS:", f"[bold green]{self.container_qps}[/]")
        else:
            perf_table.add_row("平均安全响应时间(MTTR):", "[yellow]实时监控中显示[/yellow]")
            perf_table.add_row("安全容器QPS:", "[yellow]实时监控中显示[/yellow]")

        panel = Panel(Group(flow_table, resource_table, perf_table),
                      title="智慧工厂安全防御实时监控", padding=(1, 2))

        return panel

    def run(self):
        console.clear()
        self.prompt_defense_scheme()
        self.prompt_attack_type()

        # 柔性方案在进入实时界面前执行预处理，但不马上显示MTTR和QPS具体值
        if self.defense_scheme == "flexible" and self.attack_types:
            self.flexible_defense_preprocess()
        else:
            self.preprocess_done.set()

        console.print("[bold green]进入实时监控界面，按 Ctrl+C 退出[/]\n")

        try:
            with Live(console=console, refresh_per_second=4) as live:
                while True:
                    panel = self.build_panel()
                    live.update(panel)
                    time.sleep(self.time_step)
        except KeyboardInterrupt:
            # 退出时打印最终MTTR和平均QPS
            console.print("\n[bold red]程序退出.[/]")
            console.print(f"[bold green]最终平均MTTR: {self.mttr:.2f} 秒[/]")
            console.print(f"[bold green]最终平均安全容器QPS: {self.container_qps}[/]")
            console.print("[bold green]感谢使用！[/]")
            sys.exit(0)


if __name__ == "__main__":
    sim = Simulator()
    sim.run()