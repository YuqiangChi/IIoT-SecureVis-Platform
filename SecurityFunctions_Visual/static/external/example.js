/**
 * 课题一组件示例文件
 *
 * 此文件演示了如何创建一个可以集成到主系统的课题一组件。
 * 课题一开发者可以参考此示例，创建自己的组件。
 */

// 课题一组件命名空间
window.ExternalComponent = {
    // 组件名称
    name: "示例课题一组件",

    // 组件版本
    version: "1.0.0",

    // 组件描述
    description: "这是一个示例外部组件，演示如何与主系统集成",

    // 组件作者
    author: "外部开发者",

    // 组件依赖
    dependencies: [],

    // 组件接口 - 主系统将调用这些方法
    interface: {
        // 初始化方法 - 当组件被加载时调用
        init: function(container, systemAPI) {
            console.log("外部组件初始化");

            // 存储系统API引用
            this.api = systemAPI;

            // 创建组件UI
            this.createUI(container);

            // 返回组件实例
            return this;
        },

        // 更新方法 - 当系统状态变化时调用
        update: function(data) {
            console.log("外部组件更新", data);

            // 更新组件UI
            if (this.statusElement) {
                this.statusElement.textContent = "系统状态: " + (data.is_attacking ? "攻击中" : "正常");
            }

            if (this.defenseElement) {
                this.defenseElement.textContent = "防御方案: " + (data.defense_scheme === "traditional" ? "传统防御" : "AI柔性重组");
            }

            if (this.riskElement) {
                this.riskElement.textContent = "风险等级: " + data.risk_level;

                // 根据风险等级更新样式
                this.riskElement.className = "component-risk-level";
                if (data.risk_level === "低") {
                    this.riskElement.classList.add("risk-low");
                } else if (data.risk_level === "中") {
                    this.riskElement.classList.add("risk-medium");
                } else {
                    this.riskElement.classList.add("risk-high");
                }
            }
        },

        // 销毁方法 - 当组件被卸载时调用
        destroy: function() {
            console.log("外部组件销毁");

            // 清理资源
            this.container = null;
            this.api = null;
        }
    },

    // 创建组件UI
    createUI: function(container) {
        // 存储容器引用
        this.container = container;

        // 创建组件容器
        const componentContainer = document.createElement("div");
        componentContainer.className = "external-component";

        // 创建组件标题
        const title = document.createElement("h2");
        title.textContent = this.name + " v" + this.version;
        title.className = "component-title";

        // 创建组件描述
        const description = document.createElement("p");
        description.textContent = this.description;
        description.className = "component-description";

        // 创建状态显示
        const status = document.createElement("div");
        status.textContent = "系统状态: 正常";
        status.className = "component-status";
        this.statusElement = status;

        // 创建防御方案显示
        const defense = document.createElement("div");
        defense.textContent = "防御方案: 未知";
        defense.className = "component-defense";
        this.defenseElement = defense;

        // 创建风险等级显示
        const risk = document.createElement("div");
        risk.textContent = "风险等级: 低";
        risk.className = "component-risk-level risk-low";
        this.riskElement = risk;

        // 创建操作按钮
        const button = document.createElement("button");
        button.textContent = "测试组件";
        button.className = "component-button";
        button.onclick = () => {
            alert("外部组件测试成功！");
        };

        // 添加样式
        const style = document.createElement("style");
        style.textContent = `
            .external-component {
                background-color: #fff;
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }

            .component-title {
                font-size: 18px;
                margin: 0 0 10px 0;
                color: #1e3a8a;
            }

            .component-description {
                font-size: 14px;
                color: #6b7280;
                margin-bottom: 20px;
            }

            .component-status, .component-defense, .component-risk-level {
                font-size: 14px;
                padding: 8px;
                margin-bottom: 10px;
                border-radius: 4px;
                background-color: #f3f4f6;
            }

            .component-risk-level.risk-low {
                background-color: #d1fae5;
                color: #065f46;
            }

            .component-risk-level.risk-medium {
                background-color: #fef3c7;
                color: #92400e;
            }

            .component-risk-level.risk-high {
                background-color: #fee2e2;
                color: #b91c1c;
            }

            .component-button {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 14px;
                cursor: pointer;
                margin-top: 10px;
            }

            .component-button:hover {
                background-color: #1d4ed8;
            }
        `;

        // 将元素添加到组件容器
        componentContainer.appendChild(style);
        componentContainer.appendChild(title);
        componentContainer.appendChild(description);
        componentContainer.appendChild(status);
        componentContainer.appendChild(defense);
        componentContainer.appendChild(risk);
        componentContainer.appendChild(button);

        // 将组件容器添加到主容器
        container.appendChild(componentContainer);
    }
};
