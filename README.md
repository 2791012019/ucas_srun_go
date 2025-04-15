# UCAS 校园网认证工具

这是一个用于中国科学院大学校园网的自动认证工具，可在后台运行并自动保持网络连接。

## 功能特点

- 自动检测网络状态并进行认证
- 后台静默运行，无控制台窗口
- Windows 通知提醒认证状态
- 自动重连功能
- 详细的日志记录

## 使用方法

1. 下载最新版本
2. 运行程序，系统将自动创建配置文件模板 `config.json`
3. 编辑 `config.json` 文件，输入你的用户名和密码，默认检测间隔是300秒
4. 再次运行程序

### 配置文件说明

`config.json` 文件包含以下配置项：

```json
{
  "username": "your_username@mails.ucas.ac.cn",
  "password": "your_password",
  "interval": 300
}
```
# UCAS 校园网认证程序编译指南

以下是编译 Go 语言版 UCAS 校园网认证程序的完整步骤，按顺序执行即可生成可执行文件。

## 1. 初始化 Go 模块

```bash
cd 替换为你的路径
go mod init ucas-srun-login
```

## 2. 安装依赖

```bash
go get github.com/go-toast/toast
```

## 3. 检查并更新依赖

```bash
go mod tidy
```

## 4. 编译程序

### 普通编译 (带控制台窗口)

```bash
go build -o ucas_login.exe
```

### 无窗口编译 (推荐)

```bash
go build -ldflags="-H windowsgui" -o ucas_login.exe
```

## 5. 优化编译 (可选)

如需减小文件体积，可以添加优化参数：

```bash
go build -ldflags="-s -w -H windowsgui" -o ucas_login.exe
```

参数说明：
- `-s`: 去除符号表
- `-w`: 去除DWARF调试信息
- `-H windowsgui`: 启用GUI模式，不显示控制台窗口

## 6. 完成

编译完成后，目录中会生成 `ucas_login.exe` 文件，双击运行即可。首次运行会自动创建配置文件，按照说明修改配置文件后再次运行即可正常使用。
