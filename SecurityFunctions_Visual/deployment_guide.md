# 安全功能柔性重组可视化系统部署指南

本文档提供了在不联网环境下部署安全功能柔性重组可视化系统的详细步骤。

## 前提条件

在开发环境（有网络连接的环境）中需要安装：
- Docker (20.10.x或更高版本)
- Git (可选，用于获取源代码)

在工厂服务器（目标环境）中需要安装：
- Docker (20.10.x或更高版本)

## 开发环境操作步骤

### 1. 准备应用代码

确保您有完整的应用代码，包括：
- app.py
- static/目录
- templates/目录
- performance_analyzer.py
- 其他必要文件

### 2. 创建Dockerfile和requirements.txt

使用本仓库提供的Dockerfile和requirements.txt文件。

### 3. 构建Docker镜像

在项目根目录下执行：

```bash
docker build -t security-visualization:latest .
```

### 4. 导出Docker镜像

将构建好的镜像导出为tar文件：

```bash
docker save -o security-visualization.tar security-visualization:latest
```

### 5. 传输文件到工厂服务器

将生成的`security-visualization.tar`文件复制到工厂服务器。可以使用U盘、硬盘或其他物理媒介进行传输。

## 工厂服务器操作步骤

### 1. 加载Docker镜像

在工厂服务器上执行：

```bash
docker load -i security-visualization.tar
```

### 2. 运行容器

```bash
docker run -d --name security-vis -p 8082:8082 security-visualization:latest
```

这将在后台启动容器，并将容器的8082端口映射到主机的8082端口。

### 3. 验证部署

在工厂服务器的浏览器中访问：

```
http://localhost:8082
```

或者，如果从其他机器访问，使用工厂服务器的IP地址：

```
http://<工厂服务器IP>:8082
```

## 常见问题排查

### 容器无法启动

检查Docker日志：

```bash
docker logs security-vis
```

### 端口冲突

如果8082端口已被占用，可以映射到其他端口：

```bash
docker run -d --name security-vis -p 8083:8082 security-visualization:latest
```

然后使用8083端口访问应用。

### 容器内数据持久化

如果需要保存生成的性能数据和图表，可以使用卷挂载：

```bash
docker run -d --name security-vis \
  -p 8082:8082 \
  -v /path/on/host/performance_data:/app/performance_data \
  -v /path/on/host/performance_charts:/app/performance_charts \
  security-visualization:latest
```

## 更新应用

当应用需要更新时，重复开发环境的步骤1-5，然后在工厂服务器上：

```bash
# 停止并删除旧容器
docker stop security-vis
docker rm security-vis

# 加载新镜像
docker load -i security-visualization-new.tar

# 运行新容器
docker run -d --name security-vis -p 8082:8082 security-visualization:latest
```

## 备份与恢复

### 备份容器数据

```bash
docker cp security-vis:/app/performance_data /backup/performance_data
docker cp security-vis:/app/performance_charts /backup/performance_charts
```

### 恢复容器数据

```bash
docker cp /backup/performance_data security-vis:/app/performance_data
docker cp /backup/performance_charts security-vis:/app/performance_charts
```
