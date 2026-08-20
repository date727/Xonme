# C2Sherlock Windows 本地采集控制器

Collector 只监听 Windows 本机回环地址 `127.0.0.1:8766`。它调用 Wireshark
附带的 `dumpcap.exe` 抓取本机流量，将已经关闭的 PCAPNG 分片持续上传到
C2Sherlock 云端；它本身不解析数据包，也不提供抓包驱动。

## 1. Windows 环境准备

需要安装：

1. Windows 10 或 Windows 11。
2. Python 3.10 或更高版本。安装 Python 时建议勾选 `Add Python to PATH`。
3. Wireshark，安装过程中保留 Npcap 组件。
4. PowerShell 5.1 或 PowerShell 7。

打开 PowerShell，确认 Python 可用：

```powershell
python --version
```

如果系统找不到 `python`，可以尝试 Windows Python Launcher：

```powershell
py --version
```

后续命令中的 `python` 可以相应替换成 `py`。

> `source .venv/bin/activate` 是 Linux/macOS Shell 命令，不能在 Windows
> PowerShell 中使用。PowerShell 的正确激活命令是
> `.\.venv\Scripts\Activate.ps1`。

## 2. 创建并激活虚拟环境

从项目根目录进入 Collector：

```powershell
cd "D:\competition\信安作品赛\Xonme\collector"
```

第一次运行时创建虚拟环境：

```powershell
python -m venv .venv
```

在 PowerShell 中激活：

```powershell
.\.venv\Scripts\Activate.ps1
```

激活成功后，命令提示符前面通常会出现 `(.venv)`：

```text
(.venv) PS D:\competition\信安作品赛\Xonme\collector>
```

如果 PowerShell 提示“禁止运行脚本”，只对当前 PowerShell 窗口临时放开执行
策略，然后重新激活：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

这个设置只在当前终端进程中有效，不会永久修改系统执行策略。

如果使用传统 CMD，激活命令为：

```bat
.venv\Scripts\activate.bat
```

退出虚拟环境：

```powershell
deactivate
```

## 3. 配置 Collector

第一次使用时，从示例生成实际配置：

```powershell
Copy-Item .\config.json.example .\config.json
```

编辑 `config.json`：

```json
{
  "cloud_api_base": "http://你的云服务器:8765",
  "allowed_origins": "http://你的云服务器:5500",
  "collector_port": 8766,
  "chunk_duration_seconds": 60,
  "chunk_size_mb": 16
}
```

各字段含义：

- `cloud_api_base`：云端 FastAPI 后端地址，不是前端页面地址。
- `allowed_origins`：允许调用本地 Collector 的前端页面 Origin，必须包含协议、
  主机和实际端口，但不要包含页面路径。
- `collector_port`：本地 Collector 监听端口，前端当前默认使用 `8766`。
- `chunk_duration_seconds`：每个抓包分片最长持续时间，默认 60 秒。
- `chunk_size_mb`：单个分片大小上限，默认 16 MB。时间和大小任一先达到时，
  dumpcap 就会关闭当前分片并创建下一个分片。

例如，正式网页为 `https://c2.example.com`、后端为
`https://c2.example.com/api` 时，可以写成：

```json
{
  "cloud_api_base": "https://c2.example.com/api",
  "allowed_origins": "https://c2.example.com",
  "collector_port": 8766,
  "chunk_duration_seconds": 60,
  "chunk_size_mb": 16
}
```

多个允许来源使用英文逗号分隔：

```json
{
  "allowed_origins": "http://127.0.0.1:5500,http://localhost:5500,https://c2.example.com"
}
```

`config.json` 会在打包时固化进 EXE。修改正式云端地址或允许来源后，必须重新
打包并重新发布 EXE。开发调试时可以使用 `C2S_` 开头的环境变量临时覆盖配置，
例如：

```powershell
$env:C2S_CLOUD_API_BASE = "http://127.0.0.1:8765"
$env:C2S_ALLOWED_ORIGINS = "http://127.0.0.1:5500,http://localhost:5500"
```

这些环境变量只在当前 PowerShell 会话中有效。删除临时覆盖：

```powershell
Remove-Item Env:C2S_CLOUD_API_BASE -ErrorAction SilentlyContinue
Remove-Item Env:C2S_ALLOWED_ORIGINS -ErrorAction SilentlyContinue
```

## 4. 本地开发调试：运行 main.py

### 4.1 安装依赖

确认当前位置为 `collector` 目录，并且虚拟环境已经激活：

```powershell
cd "D:\competition\信安作品赛\Xonme\collector"
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

推荐始终使用 `python -m pip`，这样可以确保依赖安装到当前激活的虚拟环境，
而不是其他 Python 环境。

### 4.2 启动云端后端和前端

Collector 只负责本机抓包和分片上传。进行完整联调前，还需要确保：

- `cloud_api_base` 指向的云端后端正在运行；
- 当前浏览器打开的前端 Origin 已写入 `allowed_origins`；
- 用户已经在前端登录，因为创建在线监测会话需要登录状态。

如果只检查 Collector 是否能够启动和发现网卡，可以暂时不启动云端；但真正点击
“开始在线监测”时，云端后端必须可访问。

### 4.3 运行 Collector

```powershell
python .\main.py
```

正常情况下终端会看到 Uvicorn 启动日志，并监听：

```text
http://127.0.0.1:8766
```

Collector 启动时会依次检查：

1. `C2S_DUMPCAP_PATH` 临时环境变量；
2. 用户以前保存的 dumpcap 路径；
3. Wireshark 默认安装目录；
4. 系统 `PATH`。

如果仍未找到，Collector 会直接在启动它的 PowerShell 终端中要求输入路径，不会
弹出图形文件选择器。可以粘贴 `dumpcap.exe` 的完整路径，也可以输入 Wireshark
安装目录。通常完整路径为：

```text
C:\Program Files\Wireshark\dumpcap.exe
```

例如终端显示：

```text
未自动找到 Wireshark dumpcap.exe。
请输入 dumpcap.exe 的完整路径。
也可以输入 Wireshark 安装目录，程序会自动查找其中的 dumpcap.exe。
示例：C:\Program Files\Wireshark\dumpcap.exe
dumpcap 路径>
```

可以输入：

```text
C:\Program Files\Wireshark\dumpcap.exe
```

路径验证成功后会保存到：

```text
%LOCALAPPDATA%\C2Sherlock\Collector\settings.json
```

该文件只保存本机工具路径，不会上传到云端。调试时也可以临时指定：

```powershell
$env:C2S_DUMPCAP_PATH = "C:\Program Files\Wireshark\dumpcap.exe"
python .\main.py
```

### 4.4 验证本地接口

新开一个 PowerShell 窗口执行：

```powershell
Invoke-RestMethod http://127.0.0.1:8766/status
Invoke-RestMethod http://127.0.0.1:8766/interfaces
```

`/status` 返回值中的 `ready` 应为 `True`，并且 `/interfaces` 应返回可用网卡。
之后打开前端“在线监测”页面，点击“重新检测”，页面应显示本地采集控制器、
dumpcap、Npcap 和网卡权限均正常。

### 4.5 运行测试

```powershell
python -m unittest discover -s .\tests -v
```

### 4.6 停止开发服务

在运行 `main.py` 的 PowerShell 窗口按：

```text
Ctrl+C
```

Collector 使用单实例锁。同一时间不要同时运行 `python main.py` 和已经打包的
`C2Sherlock-Collector.exe`，否则后启动的进程会提示 Collector 已经在运行。

## 5. Windows 打包 EXE

### 5.1 打包前检查

正式打包前确认：

1. 已经进入 `collector` 目录并激活 `.venv`；
2. `config.json` 中是正式云端 API 地址和正式网页 Origin；
3. `python -m unittest discover -s .\tests -v` 全部通过；
4. 本机没有正在运行的 Collector 调试进程；
5. 当前 Python 与目标用户系统架构一致，通常使用 64 位 Python 打包 64 位 EXE。

可以确认当前 Python 架构：

```powershell
python -c "import platform; print(platform.architecture(), platform.python_version())"
```

### 5.2 执行打包脚本

```powershell
cd "D:\competition\信安作品赛\Xonme\collector"
.\.venv\Scripts\Activate.ps1
.\build.ps1
```

如果脚本仍被执行策略阻止：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build.ps1
```

`build.ps1` 会执行以下工作：

1. 优先使用 `collector\.venv\Scripts\python.exe`，未找到时才使用 PATH 中的 Python；
2. 检查 `config.json` 是否存在；
3. 安装或更新 `requirements.txt` 中的依赖；
4. 调用 PyInstaller 清理旧的临时构建结果；
5. 将 Python、Uvicorn 和 `config.json` 打包成单文件 EXE。

生成文件：

```text
collector\dist\C2Sherlock-Collector.exe
```

`build` 目录和 `.spec` 文件属于构建中间产物；实际发布的是 `dist` 中的 EXE。

### 5.3 验证打包结果

查看文件和 SHA-256：

```powershell
Get-Item .\dist\C2Sherlock-Collector.exe
Get-FileHash .\dist\C2Sherlock-Collector.exe -Algorithm SHA256
```

运行 EXE：

```powershell
.\dist\C2Sherlock-Collector.exe
```

然后在另一个 PowerShell 窗口验证：

```powershell
Invoke-RestMethod http://127.0.0.1:8766/status
```

单文件 EXE 首次启动时需要解压运行时，可能比 `python main.py` 稍慢。未经代码
签名的 PyInstaller 单文件程序也可能触发 Windows SmartScreen 或安全软件提示，
正式发布时建议使用可信代码签名证书签名。

### 5.4 发布到前端下载目录

验证完成后，将 EXE 复制到前端固定下载位置：

```powershell
Copy-Item .\dist\C2Sherlock-Collector.exe ..\frontend\downloads\C2Sherlock-Collector.exe -Force
```

前端“下载采集控制器”按钮固定指向：

```text
frontend/downloads/C2Sherlock-Collector.exe
```

如果前端部署在云服务器，还需要把更新后的
`frontend/downloads/C2Sherlock-Collector.exe` 一并上传并重新发布前端静态文件。

## 6. 本地接口和运行数据

Collector 提供以下本地接口：

```text
GET  /status
GET  /interfaces
POST /start
POST /stop
```

同时只允许一个采集任务。采集过程使用 dumpcap 环形文件参数，每 60 秒或单个
分片达到 16 MB 时关闭一个 PCAPNG 分片并同步到云端。Collector 只上传已经关闭
的分片；上传失败会自动重试，云端确认接收后才删除对应本地分片。停止监测后，
Collector 会上传最后一个分片并请求云端合并、执行最终分析。

本地运行数据默认位于：

```text
%LOCALAPPDATA%\C2Sherlock\Collector
```

其中：

- `settings.json`：用户选择并验证过的 dumpcap 路径；
- `captures`：尚未完成上传的采集分片和 dumpcap 日志；
- `collector.lock`：防止多个 Collector 同时运行的单实例锁文件。

上传失败时 PCAPNG 会保留在 `captures` 中；修复网络或云端问题后，再次点击页面
上的“停止监测并生成结论”会尝试继续上传。

## 7. 常见问题

### PowerShell 无法识别 source

不要执行：

```text
source .venv/bin/activate
```

应执行：

```powershell
.\.venv\Scripts\Activate.ps1
```

### 找不到 python

尝试 `py`，或者重新安装 Python 并勾选 `Add Python to PATH`：

```powershell
py -m venv .venv
py -m pip install -r .\requirements.txt
py .\main.py
```

### 8766 端口被占用

查看占用进程：

```powershell
Get-NetTCPConnection -LocalPort 8766 -ErrorAction SilentlyContinue
```

通常是另一个 Collector 或未停止的 `main.py`。先回到对应终端按 `Ctrl+C`，不要
直接同时启动多个实例。

### 页面显示无法连接本地控制器

依次检查：

1. Collector 终端是否仍在运行；
2. `Invoke-RestMethod http://127.0.0.1:8766/status` 是否成功；
3. `allowed_origins` 是否与浏览器地址栏中的协议、域名和端口完全一致；
4. 修改 `config.json` 后是否重新启动 `main.py`，或者重新打包并替换 EXE；
5. 浏览器页面是否通过配置中允许的正式地址打开。

### 找不到 dumpcap 或没有网卡权限

确认 Wireshark 和 Npcap 已正确安装。可以直接检查：

```powershell
& "C:\Program Files\Wireshark\dumpcap.exe" -D
```

如果命令失败，先修复 Wireshark/Npcap 安装或当前用户的抓包权限，再重新启动
Collector 并点击页面上的“重新检测”。

### 修改 config.json 后 EXE 配置没有变化

EXE 使用打包时固化的 `config.json`。修改源文件不会改变已经生成的 EXE，必须
重新运行 `build.ps1`，再替换前端下载目录和云服务器上的旧文件。
