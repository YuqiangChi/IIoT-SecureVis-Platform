// 使用Vue 3 Composition API
const { createApp, ref, computed, onMounted, onUnmounted, nextTick } = Vue;

// 创建Vue应用
const app = createApp({
    setup() {
        // 状态数据
        const agvActive = ref(true);
        const idsActive = ref(false);  // IDS初始未启动
        const idsSecurity = ref(0);    // IDS初始检测率为0
        const fwSecurity = ref(85);    // 防火墙初始拦截能力为85%
        const isAttacking = ref(false);
        const isInitializingAttack = ref(false); // 攻击初始化状态
        const logs = ref([]);

        // 外部组件状态
        const externalComponentLoaded = ref(false);
        const externalComponent = ref(null);

        // IDS检测率和防火墙阻断率
        const idsRate1 = ref("N/A（无攻击发生）");
        const idsRate2 = ref("N/A（无攻击发生）");
        const fwRate1 = ref("N/A（无攻击需阻断）");
        const fwRate2 = ref("N/A（无攻击需阻断）");

        // 组件名称
        const componentNames = ref({
            ids_agv: "静态IDS-AGV",
            ids_scheduler: "静态IDS-调度系统",
            fw_agv: "静态防火墙-AGV",
            fw_scheduler: "静态防火墙-调度系统"
        });

        // 安全统计数据
        const attacksDetected = ref(0);
        const attacksBlocked = ref(0);
        const riskLevel = ref('低');

        // 系统性能指标
        const normalTraffic = ref(300);
        const containerQps = ref(750);
        const mttr = ref(0.35);

        // 资源使用数据
        const idsCpuUsage = ref(0);
        const idsCpuUsage2 = ref(0);  // 第二组IDS的CPU使用率
        const fwCpuUsage = ref(25);
        const fwCpuUsage2 = ref(25);  // 第二组防火墙的CPU使用率

        // 设置对话框
        const showSetupDialog = ref(false);
        const showDefenseSelector = ref(false); // 是否显示防御策略选择器
        const defenseSchemes = ref([]);
        const attackTypes = ref([]);
        const setupForm = ref({
            defenseScheme: 'flexible',
            attackType: 0,
            agvTraffic: 2000,
            schedulerTraffic: 1500
        });

        // 时间序列数据
        const timeData = ref([]);
        const idsCpuData = ref([]);
        const idsCpuData2 = ref([]);  // 第二组IDS的CPU数据
        const fwCpuData = ref([]);
        const fwCpuData2 = ref([]);  // 第二组防火墙的CPU数据

        // 图表实例
        let idsCpuChart = null;
        let idsCpu2Chart = null;  // 第二组IDS的CPU图表
        let fwCpuChart = null;
        let fwCpu2Chart = null;  // 第二组防火墙的CPU图表

        // 获取风险等级样式类
        const getRiskClass = () => {
            if (riskLevel.value === '低') return 'risk-low';
            if (riskLevel.value === '中') return 'risk-medium';
            return 'risk-high';
        };

        // 获取风险等级缩写
        const getRiskShortName = () => {
            if (riskLevel.value === '低') return 'L';
            if (riskLevel.value === '中') return 'M';
            return 'H';
        };

        // 获取安全能力的颜色
        const getSecurityColor = (value) => {
            // 待机状态（值为10）显示为蓝色
            if (value === 10) return '#3b82f6'; // 蓝色，表示待机状态

            // 红色到黄色到绿色的渐变，更加鲜明的颜色
            if (value < 20) return '#ff0000'; // 纯红色
            if (value < 30) return '#ff3300'; // 红橙色
            if (value < 40) return '#ff6600'; // 橙色
            if (value < 50) return '#ff9900'; // 橙黄色
            if (value < 60) return '#ffcc00'; // 黄色
            if (value < 70) return '#ccff00'; // 黄绿色
            if (value < 80) return '#66ff00'; // 浅绿色
            if (value < 90) return '#00ff66'; // 青绿色
            return '#00cc00'; // 纯绿色
        };

        // 进度条百分比格式化函数
        const percentFormat = (percentage) => {
            return `${percentage.toFixed(0)}%`;
        };

        // 从字符串中提取数值
        const parseRate = (rateStr) => {
            // 如果是N/A（无攻击）状态，返回一个小的默认值，使仪表盘显示为待机状态
            if (!rateStr || typeof rateStr !== 'string' || rateStr.includes('N/A')) return 10;

            // 尝试匹配百分比数字，如"45.67%"或"45%"
            const match = rateStr.match(/(\d+(?:\.\d+)?)/);
            const value = match ? parseFloat(match[1]) : 0;

            // 确保值在0-100之间
            return Math.min(100, Math.max(0, value));
        };

        // 调试函数，用于检查仪表盘数据
        const debugDashboard = () => {
            console.log("IDS检测率数据:", {
                idsRate1: idsRate1.value,
                idsRate2: idsRate2.value,
                parsedIdsRate1: parseRate(idsRate1.value),
                parsedIdsRate2: parseRate(idsRate2.value)
            });
            console.log("防火墙拦截率数据:", {
                fwRate1: fwRate1.value,
                fwRate2: fwRate2.value,
                parsedFwRate1: parseRate(fwRate1.value),
                parsedFwRate2: parseRate(fwRate2.value)
            });
        };

        // 初始化时间数据
        const initTimeData = () => {
            const now = new Date();
            timeData.value = [];
            idsCpuData.value = [];
            idsCpuData2.value = [];
            fwCpuData.value = [];
            fwCpuData2.value = [];

            // 使用固定值而不是随机值，避免初始图表波动
            const initialIdsCpuValue = 30;
            const initialFwCpuValue = 35;

            // 只生成5个初始数据点，间隔3秒，与轮询间隔一致
            for (let i = 0; i < 5; i++) {
                const time = new Date(now - (4 - i) * 3000); // 3秒间隔，与轮询间隔一致
                timeData.value.push(formatChartTime(time));
                idsCpuData.value.push(initialIdsCpuValue);  // IDS初始CPU使用率固定值
                idsCpuData2.value.push(initialIdsCpuValue);  // 第二组IDS初始CPU使用率固定值
                fwCpuData.value.push(initialFwCpuValue);  // 防火墙初始CPU使用率固定值
                fwCpuData2.value.push(initialFwCpuValue);  // 第二组防火墙初始CPU使用率固定值
            }
        };

        // 格式化时间 (小时:分钟:秒格式) - 用于图表
        const formatChartTime = (date) => {
            return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;
        };

        // 初始化资源监控图表
        const initResourceCharts = () => {
            // 通用图表配置
            const commonChartConfig = {
                grid: {
                    left: '5%',
                    right: '5%',
                    bottom: '12%',
                    top: '5%',
                    containLabel: true
                },
                xAxis: {
                    type: 'category',
                    boundaryGap: false,
                    data: timeData.value,
                    axisLine: {
                        lineStyle: {
                            color: '#ddd'
                        }
                    },
                    axisTick: {
                        show: true,
                        alignWithLabel: true
                    },
                    axisLabel: {
                        rotate: 45,
                        fontSize: 10,
                        interval: function(index, value) {
                            // 每隔10个数据点显示一个标签，避免拥挤
                            return index % 10 === 0;
                        }
                    },
                    splitLine: {
                        show: true,
                        lineStyle: {
                            color: '#eee',
                            type: 'dashed'
                        }
                    }
                },
                tooltip: {
                    trigger: 'axis',
                    backgroundColor: 'rgba(255, 255, 255, 0.9)',
                    borderColor: '#e0e0e0',
                    textStyle: {
                        color: '#333'
                    }
                }
            };

            // CPU图表配置
            const cpuChartConfig = {
                ...commonChartConfig,
                yAxis: {
                    type: 'value',
                    min: 0,
                    max: 100,
                    name: 'CPU(%)',
                    nameTextStyle: {
                        color: '#666',
                        padding: [0, 0, 0, 0]
                    },
                    axisLine: {
                        show: true,
                        lineStyle: {
                            color: '#ddd'
                        }
                    },
                    axisTick: {
                        show: false
                    },
                    splitLine: {
                        show: true,
                        lineStyle: {
                            color: '#eee',
                            type: 'dashed'
                        }
                    }
                },
                series: [{
                    name: 'CPU使用率',
                    type: 'line',
                    smooth: false, // 禁用曲线平滑
                    symbol: 'none',
                    step: 'middle', // 使用阶梯线，避免大幅度变化时的蠕动效果
                    connectNulls: true, // 连接空值点
                    lineStyle: {
                        width: 2,
                        color: '#3b82f6'
                    },
                    areaStyle: {
                        opacity: 0.2,
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#3b82f6' },
                            { offset: 1, color: 'rgba(59, 130, 246, 0.1)' }
                        ])
                    }
                }]
            };

            // 第二组CPU图表配置（原内存图表配置）
            const cpu2ChartConfig = {
                ...commonChartConfig,
                yAxis: {
                    type: 'value',
                    min: 0,
                    max: 100,
                    name: 'CPU(%)',
                    nameTextStyle: {
                        color: '#666',
                        padding: [0, 0, 0, 0]
                    },
                    axisLine: {
                        show: true,
                        lineStyle: {
                            color: '#ddd'
                        }
                    },
                    axisTick: {
                        show: false
                    },
                    splitLine: {
                        show: true,
                        lineStyle: {
                            color: '#eee',
                            type: 'dashed'
                        }
                    }
                },
                series: [{
                    name: 'CPU使用率',
                    type: 'line',
                    smooth: false, // 禁用曲线平滑
                    symbol: 'none',
                    step: 'middle', // 使用阶梯线，避免大幅度变化时的蠕动效果
                    connectNulls: true, // 连接空值点
                    lineStyle: {
                        width: 2,
                        color: '#10b981'
                    },
                    areaStyle: {
                        opacity: 0.2,
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#10b981' },
                            { offset: 1, color: 'rgba(16, 185, 129, 0.1)' }
                        ])
                    }
                }]
            };

            // 添加动画配置 - 完全禁用动画以避免蠕动效果
            const animationConfig = {
                animation: false,
                animationDuration: 0,
                animationThreshold: 0
            };

            // 初始化所有图表
            idsCpuChart = echarts.init(document.getElementById('idsCpuChart'));
            const idsCpuConfig = JSON.parse(JSON.stringify(cpuChartConfig));
            idsCpuConfig.series[0].data = idsCpuData.value;
            idsCpuConfig.series[0].smooth = false; // 禁用曲线平滑
            idsCpuConfig.tooltip.formatter = '{b}<br />CPU使用率: {c}%';
            Object.assign(idsCpuConfig, animationConfig);
            idsCpuChart.setOption(idsCpuConfig);

            idsCpu2Chart = echarts.init(document.getElementById('idsMemoryChart'));
            const idsCpu2Config = JSON.parse(JSON.stringify(cpu2ChartConfig));
            idsCpu2Config.series[0].data = idsCpuData2.value;
            idsCpu2Config.series[0].smooth = false; // 禁用曲线平滑
            idsCpu2Config.tooltip.formatter = '{b}<br />CPU使用率: {c}%';
            Object.assign(idsCpu2Config, animationConfig);
            idsCpu2Chart.setOption(idsCpu2Config);

            fwCpuChart = echarts.init(document.getElementById('fwCpuChart'));
            const fwCpuConfig = JSON.parse(JSON.stringify(cpuChartConfig));
            fwCpuConfig.series[0].data = fwCpuData.value;
            fwCpuConfig.series[0].smooth = false; // 禁用曲线平滑
            fwCpuConfig.tooltip.formatter = '{b}<br />CPU使用率: {c}%';
            Object.assign(fwCpuConfig, animationConfig);
            fwCpuChart.setOption(fwCpuConfig);

            fwCpu2Chart = echarts.init(document.getElementById('fwMemoryChart'));
            const fwCpu2Config = JSON.parse(JSON.stringify(cpu2ChartConfig));
            fwCpu2Config.series[0].data = fwCpuData2.value;
            fwCpu2Config.series[0].smooth = false; // 禁用曲线平滑
            fwCpu2Config.tooltip.formatter = '{b}<br />CPU使用率: {c}%';
            Object.assign(fwCpu2Config, animationConfig);
            fwCpu2Chart.setOption(fwCpu2Config);
        };

        // 更新所有图表
        const updateAllCharts = () => {
            // 更新图表的动画配置 - 完全禁用动画以避免蠕动效果
            const updateConfig = {
                animation: false,
                animationDuration: 0,
                animationThreshold: 0
            };

            if (idsCpuChart) {
                idsCpuChart.setOption({
                    ...updateConfig,
                    xAxis: { data: timeData.value },
                    series: [{
                        data: idsCpuData.value,
                        smooth: false, // 禁用曲线平滑
                        step: 'middle', // 使用阶梯线
                        connectNulls: true // 连接空值点
                    }]
                });
            }

            if (idsCpu2Chart) {
                idsCpu2Chart.setOption({
                    ...updateConfig,
                    xAxis: { data: timeData.value },
                    series: [{
                        data: idsCpuData2.value,
                        smooth: false, // 禁用曲线平滑
                        step: 'middle', // 使用阶梯线
                        connectNulls: true // 连接空值点
                    }]
                });
            }

            if (fwCpuChart) {
                fwCpuChart.setOption({
                    ...updateConfig,
                    xAxis: { data: timeData.value },
                    series: [{
                        data: fwCpuData.value,
                        smooth: false, // 禁用曲线平滑
                        step: 'middle', // 使用阶梯线
                        connectNulls: true // 连接空值点
                    }]
                });
            }

            if (fwCpu2Chart) {
                fwCpu2Chart.setOption({
                    ...updateConfig,
                    xAxis: { data: timeData.value },
                    series: [{
                        data: fwCpuData2.value,
                        smooth: false, // 禁用曲线平滑
                        step: 'middle', // 使用阶梯线
                        connectNulls: true // 连接空值点
                    }]
                });
            }
        };

        // 加载防御方案和攻击类型
        const loadOptions = async () => {
            try {
                const [defenseRes, attackRes] = await Promise.all([
                    axios.get('/api/defense-schemes'),
                    axios.get('/api/attack-types')
                ]);
                defenseSchemes.value = defenseRes.data.schemes;
                attackTypes.value = attackRes.data.types;
            } catch (error) {
                console.error('加载选项失败:', error);
                ElementPlus.ElMessage.error('加载选项失败，请刷新页面重试');
            }
        };

        // 处理攻击类型变更
        const handleAttackTypeChange = () => {
            if (setupForm.value.attackType === 0) {
                // 无攻击
                setupForm.value.agvTraffic = 0;
                setupForm.value.schedulerTraffic = 0;
            } else if (setupForm.value.attackType === 1) {
                // 攻击AGV
                setupForm.value.agvTraffic = 2000;
                setupForm.value.schedulerTraffic = 0;
            } else if (setupForm.value.attackType === 2) {
                // 攻击调度系统
                setupForm.value.agvTraffic = 0;
                setupForm.value.schedulerTraffic = 1500;
            } else if (setupForm.value.attackType === 3) {
                // 同时攻击
                setupForm.value.agvTraffic = 2000;
                setupForm.value.schedulerTraffic = 1500;
            }
        };

        // 确认设置
        const confirmSetup = async () => {
            try {
                // 设置防御方案
                await axios.post('/api/set-defense-scheme', {
                    scheme: setupForm.value.defenseScheme
                });

                // 设置攻击类型和流量
                await axios.post('/api/set-attack', {
                    attack_id: setupForm.value.attackType,
                    agv_traffic: setupForm.value.agvTraffic,
                    scheduler_traffic: setupForm.value.schedulerTraffic
                });

                showSetupDialog.value = false;
                ElementPlus.ElMessage.success('系统设置已完成');
            } catch (error) {
                console.error('设置失败:', error);
                ElementPlus.ElMessage.error('设置失败，请重试');
            }
        };

        // 触发或停止攻击
        const triggerAttack = async () => {
            try {
                // 如果当前正在攻击中，则停止攻击
                if (isAttacking.value) {
                    // 调用停止攻击API
                    const response = await axios.post('/api/trigger-attack');
                    if (response.data.status === 'success') {
                        isAttacking.value = false;
                        isInitializingAttack.value = false; // 重置攻击初始化状态
                        ElementPlus.ElMessage({
                            type: 'success',
                            message: '攻击已停止，系统恢复中...',
                            showClose: true,
                            duration: 3000
                        });
                    } else {
                        ElementPlus.ElMessage.error(response.data.message);
                    }
                    return;
                }

                // 如果当前没有攻击，则开始攻击
                // 设置为同时攻击AGV和调度系统
                setupForm.value.attackType = 3; // 同时攻击
                setupForm.value.agvTraffic = 2000;
                setupForm.value.schedulerTraffic = 1500;

                // 先设置攻击类型
                await axios.post('/api/set-attack', {
                    attack_id: setupForm.value.attackType,
                    agv_traffic: setupForm.value.agvTraffic,
                    scheduler_traffic: setupForm.value.schedulerTraffic
                });

                // 设置攻击初始化状态
                isInitializingAttack.value = true;

                // 然后触发攻击
                const response = await axios.post('/api/trigger-attack');
                if (response.data.status === 'success') {
                    isAttacking.value = true;
                    ElementPlus.ElMessage({
                        type: 'warning',
                        message: '检测到网络攻击！启动安全防御机制...',
                        showClose: true,
                        duration: 5000
                    });

                    // 开始轮询状态
                    startPollingStatus();
                } else {
                    ElementPlus.ElMessage.error(response.data.message);
                }
            } catch (error) {
                console.error('触发/停止攻击失败:', error);
                ElementPlus.ElMessage.error('操作失败，请重试');
            }
        };

        // 轮询间隔ID
        let pollIntervalId = null;

        // 开始轮询状态
        const startPollingStatus = () => {
            // 如果已经有轮询在运行，先清除它
            if (pollIntervalId) {
                clearInterval(pollIntervalId);
                pollIntervalId = null;
            }

            // 启动新的轮询
            pollIntervalId = setInterval(async () => {
                try {
                    const response = await axios.get('/api/status');
                    const data = response.data;

                    // 更新状态
                    agvActive.value = data.agv_active;
                    idsActive.value = data.ids_active;
                    idsSecurity.value = data.ids_security;
                    fwSecurity.value = data.fw_security;
                    idsCpuUsage.value = data.ids_cpu_usage;
                    idsCpuUsage2.value = data.ids_cpu_usage_2;
                    fwCpuUsage.value = data.fw_cpu_usage;
                    fwCpuUsage2.value = data.fw_cpu_usage_2;
                    attacksDetected.value = data.attacks_detected;
                    attacksBlocked.value = data.attacks_blocked;
                    riskLevel.value = data.risk_level;
                    logs.value = data.logs || data.attack_logs;

                    // 更新系统性能指标
                    normalTraffic.value = data.normal_traffic || 300;
                    containerQps.value = data.container_qps || 750;
                    mttr.value = data.mttr || 0.35;

                    // 更新IDS检测率和防火墙阻断率
                    idsRate1.value = data.ids_rate_1;
                    idsRate2.value = data.ids_rate_2;
                    fwRate1.value = data.fw_rate_1;
                    fwRate2.value = data.fw_rate_2;

                    // 如果收到了有效的检测率数据（不是N/A），则重置攻击初始化状态
                    if (isInitializingAttack.value &&
                        data.ids_rate_1 && !data.ids_rate_1.includes('N/A') &&
                        data.fw_rate_1 && !data.fw_rate_1.includes('N/A')) {
                        isInitializingAttack.value = false;
                    }

                    // 调试仪表盘数据
                    debugDashboard();

                    // 更新组件名称
                    componentNames.value = data.component_names;

                    // 通知外部组件状态更新
                    if (externalComponent.value) {
                        const status = {
                            agvActive: agvActive.value,
                            idsActive: idsActive.value,
                            idsSecurity: idsSecurity.value,
                            fwSecurity: fwSecurity.value,
                            isAttacking: isAttacking.value,
                            logs: logs.value,
                            idsRate1: idsRate1.value,
                            idsRate2: idsRate2.value,
                            fwRate1: fwRate1.value,
                            fwRate2: fwRate2.value,
                            componentNames: componentNames.value,
                            attacksDetected: attacksDetected.value,
                            attacksBlocked: attacksBlocked.value,
                            riskLevel: riskLevel.value,
                            idsCpuUsage: idsCpuUsage.value,
                            idsCpuUsage2: idsCpuUsage2.value,
                            fwCpuUsage: fwCpuUsage.value,
                            fwCpuUsage2: fwCpuUsage2.value,
                            defense_scheme: setupForm.value.defenseScheme,
                            attack_types: setupForm.value.attackType ? [setupForm.value.attackType] : [],
                            is_attacking: isAttacking.value
                        };
                        externalComponent.value.interface.update(status);
                    }

                    // 触发状态更新事件
                    window.dispatchEvent(new CustomEvent('system-status-update'));

                    // 更新图表数据 - 不再移除旧数据点，而是添加新数据点
                    const now = new Date();
                    timeData.value.push(formatChartTime(now));
                    idsCpuData.value.push(idsCpuUsage.value);
                    idsCpuData2.value.push(idsCpuUsage2.value);
                    fwCpuData.value.push(fwCpuUsage.value);
                    fwCpuData2.value.push(fwCpuUsage2.value);

                    // 限制数据点数量，保持最新的300个点（约15分钟的数据）
                    const maxPoints = 300;
                    if (timeData.value.length > maxPoints) {
                        timeData.value = timeData.value.slice(-maxPoints);
                        idsCpuData.value = idsCpuData.value.slice(-maxPoints);
                        idsCpuData2.value = idsCpuData2.value.slice(-maxPoints);
                        fwCpuData.value = fwCpuData.value.slice(-maxPoints);
                        fwCpuData2.value = fwCpuData2.value.slice(-maxPoints);
                    }

                    // 更新图表
                    updateAllCharts();

                    // 确保日志滚动到最新的消息
                    nextTick(() => {
                        const logContainer = document.getElementById('logContainer');
                        if (logContainer) {
                            logContainer.scrollTop = logContainer.scrollHeight;
                        }
                    });

                    // 更新攻击状态
                    if (!data.is_attacking) {
                        isAttacking.value = false;
                    }
                } catch (error) {
                    console.error('获取状态失败:', error);
                    clearInterval(pollIntervalId);
                    pollIntervalId = null;
                }
            }, 3000);
        };

        // 加载外部组件
        const loadExternalComponent = async () => {
            try {
                // 清理之前的组件
                if (externalComponent.value) {
                    externalComponent.value.interface.destroy();
                    externalComponent.value = null;
                    externalComponentLoaded.value = false;

                    // 清空挂载点
                    const mountPoint = document.getElementById('externalComponentMount');
                    if (mountPoint) {
                        mountPoint.innerHTML = '';
                    }
                }

                // 创建系统API
                const systemAPI = {
                    // 获取当前系统状态
                    getStatus: () => {
                        return {
                            agvActive: agvActive.value,
                            idsActive: idsActive.value,
                            idsSecurity: idsSecurity.value,
                            fwSecurity: fwSecurity.value,
                            isAttacking: isAttacking.value,
                            logs: logs.value,
                            idsRate1: idsRate1.value,
                            idsRate2: idsRate2.value,
                            fwRate1: fwRate1.value,
                            fwRate2: fwRate2.value,
                            componentNames: componentNames.value,
                            attacksDetected: attacksDetected.value,
                            attacksBlocked: attacksBlocked.value,
                            riskLevel: riskLevel.value,
                            idsCpuUsage: idsCpuUsage.value,
                            idsCpuUsage2: idsCpuUsage2.value,
                            fwCpuUsage: fwCpuUsage.value,
                            fwCpuUsage2: fwCpuUsage2.value,
                            defense_scheme: setupForm.value.defenseScheme,
                            attack_types: setupForm.value.attackType ? [setupForm.value.attackType] : []
                        };
                    },

                    // 订阅状态变化事件
                    subscribe: (callback) => {
                        window.addEventListener('system-status-update', () => {
                            callback(systemAPI.getStatus());
                        });
                    },

                    // 取消订阅状态变化事件
                    unsubscribe: (callback) => {
                        window.removeEventListener('system-status-update', callback);
                    },

                    // 触发攻击模拟
                    triggerAttack: () => {
                        triggerAttack();
                    },

                    // 设置防御方案
                    setDefenseScheme: (scheme) => {
                        setupForm.value.defenseScheme = scheme;
                        confirmSetup();
                    },

                    // 设置攻击类型
                    setAttack: (attackId, agvTraffic, schedulerTraffic) => {
                        setupForm.value.attackType = attackId;
                        if (agvTraffic !== undefined) setupForm.value.agvTraffic = agvTraffic;
                        if (schedulerTraffic !== undefined) setupForm.value.schedulerTraffic = schedulerTraffic;
                        confirmSetup();
                    }
                };

                // 加载外部组件脚本
                const script = document.createElement('script');
                script.src = '/static/external/example.js';
                script.onload = () => {
                    // 检查是否存在外部组件
                    if (window.ExternalComponent) {
                        // 获取挂载点
                        const mountPoint = document.getElementById('externalComponentMount');

                        // 初始化组件
                        externalComponent.value = window.ExternalComponent.interface.init(mountPoint, systemAPI);
                        externalComponentLoaded.value = true;

                        // 更新组件状态
                        externalComponent.value.interface.update(systemAPI.getStatus());

                        // 显示成功消息
                        ElementPlus.ElMessage.success('外部组件加载成功');
                    } else {
                        ElementPlus.ElMessage.warning('未找到有效的外部组件');
                    }
                };
                script.onerror = () => {
                    ElementPlus.ElMessage.error('加载外部组件失败');
                };
                document.head.appendChild(script);
            } catch (error) {
                console.error('加载外部组件失败:', error);
                ElementPlus.ElMessage.error('加载外部组件失败: ' + error.message);
            }
        };

        // 打开防御策略选择对话框
        const openDefenseDialog = () => {
            console.log("打开防御策略选择对话框");
            showSetupDialog.value = true;
            console.log("showSetupDialog.value =", showSetupDialog.value);

            // 强制更新视图
            nextTick(() => {
                console.log("nextTick: showSetupDialog.value =", showSetupDialog.value);
            });
        };

        // 自动开始轮询状态
        const startAutoPolling = () => {
            // 不再自动打开设置对话框，但仍然开始轮询状态，以显示实时数据
            startPollingStatus();

            console.log("自动开始轮询状态");
        };

        // 组件挂载时
        onMounted(async () => {
            await loadOptions();
            initTimeData();
            nextTick(() => {
                initResourceCharts();

                // 监听窗口大小变化，重新调整图表大小
                window.addEventListener('resize', () => {
                    idsCpuChart?.resize();
                    idsCpu2Chart?.resize();
                    fwCpuChart?.resize();
                    fwCpu2Chart?.resize();
                });

                // 尝试加载外部组件
                // loadExternalComponent();

                // 自动开始轮询状态
                setTimeout(() => {
                    startAutoPolling();
                }, 1000);
            });
        });

        // 组件卸载时
        onUnmounted(() => {
            window.removeEventListener('resize', () => {});
            idsCpuChart?.dispose();
            idsCpu2Chart?.dispose();
            fwCpuChart?.dispose();
            fwCpu2Chart?.dispose();
        });

        return {
            // 状态数据
            agvActive,
            idsActive,
            idsSecurity,
            fwSecurity,
            isAttacking,
            isInitializingAttack,
            logs,
            attacksDetected,
            attacksBlocked,
            riskLevel,
            idsCpuUsage,
            idsCpuUsage2,
            fwCpuUsage,
            fwCpuUsage2,

            // 系统性能指标
            normalTraffic,
            containerQps,
            mttr,

            // 设置对话框
            showSetupDialog,
            showDefenseSelector,
            defenseSchemes,
            attackTypes,
            setupForm,

            // IDS检测率和防火墙阻断率
            idsRate1,
            idsRate2,
            fwRate1,
            fwRate2,

            // 组件名称
            componentNames,

            // 外部组件
            externalComponentLoaded,
            loadExternalComponent,

            // 方法
            getRiskClass,
            getRiskShortName,
            getSecurityColor,
            parseRate,
            percentFormat,
            handleAttackTypeChange,
            confirmSetup,
            triggerAttack,
            openDefenseDialog
        };
    }
});

// 设置分隔符
app.config.compilerOptions = {
    delimiters: ['${', '}$']
};

// 使用Element Plus
if (window.ElementPlus) {
    app.use(ElementPlus);
    console.log('Element Plus 已注册');
} else {
    console.error('Element Plus 未加载');
}

// 挂载应用
app.mount('#app');
