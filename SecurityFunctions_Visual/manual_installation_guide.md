# 安全功能柔性重组可视化系统手动安装指南

本文档提供了在不使用Docker的情况下，直接在服务器上安装和配置系统的步骤。

## 前提条件

在工厂服务器上需要安装：

1. Python 3.9或更高版本
2. pip (Python包管理器)
3. 用于编译某些Python包的C/C++编译器

## 安装步骤

### 1. 安装Python和开发工具

#### Windows系统

1. 从[Python官网](https://www.python.org/downloads/)下载Python 3.9安装包
2. 安装时勾选"Add Python to PATH"选项
3. 安装Visual C++ Build Tools (可从[Microsoft官网](https://visualstudio.microsoft.com/visual-cpp-build-tools/)下载)

#### Linux系统 (CentOS/RHEL)

```bash
# 安装Python 3.9和开发工具
sudo yum install -y python39 python39-devel gcc

# 确保pip已安装
sudo python3.9 -m ensurepip
```

#### Linux系统 (Ubuntu/Debian)

```bash
# 安装Python 3.9和开发工具
sudo apt-get update
sudo apt-get install -y python3.9 python3.9-dev python3-pip gcc

# 安装图形库依赖
sudo apt-get install -y libfreetype6-dev pkg-config
```

### 2. 创建虚拟环境 (可选但推荐)

```bash
# 创建虚拟环境
python3.9 -m venv security_vis_env

# 激活虚拟环境
# Windows
security_vis_env\Scripts\activate
# Linux/macOS
source security_vis_env/bin/activate
```

### 3. 安装Python依赖

将应用代码和requirements.txt复制到服务器，然后执行：

```bash
pip install -r requirements.txt
```

如果服务器完全不联网，需要在有网络的环境中下载所有依赖包：

```bash
# 在有网络的环境中执行
pip download -r requirements.txt -d ./python_packages
```

然后将整个`python_packages`目录复制到服务器，并在服务器上执行：

```bash
pip install --no-index --find-links=./python_packages -r requirements.txt
```

### 4. 运行应用

```bash
# 直接运行
python app.py

# 或者使用后台运行（Linux）
nohup python app.py > app.log 2>&1 &
```

应用将在8082端口启动。

### 5. 设置开机自启 (可选)

#### Windows系统

创建一个批处理文件`start_app.bat`：

```batch
@echo off
cd C:\path\to\application
python app.py
```

然后将此批处理文件添加到Windows的启动项中。

#### Linux系统 (使用systemd)

创建服务文件`/etc/systemd/system/security-vis.service`：

```ini
[Unit]
Description=Security Visualization Service
After=network.target

[Service]
User=<username>
WorkingDirectory=/path/to/application
ExecStart=/usr/bin/python3.9 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl enable security-vis
sudo systemctl start security-vis
```

## 常见问题排查

### 依赖安装失败

如果某些包安装失败，可能需要安装额外的系统依赖：

#### Windows

安装Visual C++ Build Tools并重试。

#### Linux

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev

# CentOS/RHEL
sudo yum install -y gcc openssl-devel bzip2-devel libffi-devel
```

### 应用无法启动

检查日志文件：

```bash
# 如果使用nohup启动
cat app.log

# 如果使用systemd
sudo journalctl -u security-vis
```

### 端口冲突

如果8082端口已被占用，修改`app.py`中的端口配置：

```python
# 找到这一行
app.run(host='0.0.0.0', port=8082, debug=True)

# 修改为
app.run(host='0.0.0.0', port=8083, debug=False)  # 使用8083端口，并关闭调试模式
```

## 更新应用

当应用需要更新时，只需将新的代码文件复制到服务器上，覆盖旧文件，然后重启应用：

```bash
# 如果直接运行，先终止旧进程，再启动新进程
# 如果使用systemd
sudo systemctl restart security-vis
```

## 备份数据

定期备份生成的数据和图表：

```bash
# 创建备份
cp -r performance_data /backup/performance_data_$(date +%Y%m%d)
cp -r performance_charts /backup/performance_charts_$(date +%Y%m%d)
```
