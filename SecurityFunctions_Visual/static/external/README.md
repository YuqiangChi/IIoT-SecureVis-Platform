# 课题一组件集成指南

本文档提供了如何将课题一组件集成到网络安全功能柔性重组智能监控系统的指南。

## 概述

系统提供了一个专门的区域用于集成课题一开发者的组件。这些组件可以访问系统的状态数据，并与主系统进行交互。

## 组件结构

课题一组件应该遵循以下结构：

```javascript
window.ExternalComponent = {
    // 组件元数据
    name: "组件名称",
    version: "1.0.0",
    description: "组件描述",
    author: "开发者名称",
    dependencies: [], // 依赖项列表

    // 组件接口
    interface: {
        // 初始化方法 - 当组件被加载时调用
        init: function(container, systemAPI) {
            // 初始化组件
            return this;
        },

        // 更新方法 - 当系统状态变化时调用
        update: function(data) {
            // 更新组件UI
        },

        // 销毁方法 - 当组件被卸载时调用
        destroy: function() {
            // 清理资源
        }
    },

    // 其他自定义方法和属性
    // ...
};
```

## 集成步骤

1. 创建一个JavaScript文件，实现上述结构
2. 将文件放置在 `/static/external/` 目录下
3. 文件名应该是唯一的，建议使用 `课题一_组件名称.js` 的格式
4. 系统将自动检测并加载组件

## 系统API

系统提供了以下API供外部组件使用：

```javascript
{
    // 获取当前系统状态
    getStatus: function() {
        // 返回系统状态对象
    },

    // 订阅状态变化事件
    subscribe: function(callback) {
        // 注册回调函数，当状态变化时调用
    },

    // 取消订阅状态变化事件
    unsubscribe: function(callback) {
        // 取消注册回调函数
    },

    // 触发攻击模拟
    triggerAttack: function() {
        // 触发攻击模拟
    },

    // 设置防御方案
    setDefenseScheme: function(scheme) {
        // 设置防御方案
    },

    // 设置攻击类型
    setAttack: function(attackId, agvTraffic, schedulerTraffic) {
        // 设置攻击类型和流量
    }
}
```

## 示例

请参考 `example.js` 文件，了解如何创建一个外部组件。

## 注意事项

1. 组件应该是自包含的，不应该依赖于主系统的内部实现
2. 组件应该通过系统API与主系统交互，而不是直接操作DOM
3. 组件应该在销毁方法中清理所有资源，避免内存泄漏
4. 组件应该处理可能的错误，不应该影响主系统的运行

## 调试

可以通过浏览器控制台查看组件的日志输出。建议在开发过程中使用 `console.log` 输出调试信息。

## 支持

如有任何问题，请联系系统管理员。
