# C2Sherlock Windows 本地采集控制器

控制器只监听 `127.0.0.1:8766`，调用 Wireshark 提供的 `dumpcap.exe` 抓取本机流量，停止后上传至 C2Sherlock 云端。它不解析数据包，也不实现抓包驱动。

## 准备环境

1. 安装 Wireshark，并保留安装 Npcap 的选项。
2. 安装 Python 3.10+（仅开发和打包需要）。
3. 复制发布配置并填写云端地址与允许访问控制器的网页来源：

```powershell
Copy-Item config.json.example config.json
```

`config.json` 会在打包时固化进 EXE，网页不能修改上传目标或来源白名单。环境变量仅供开发调试临时覆盖。

## 开发运行

```powershell
pip install -r requirements.txt
python main.py
```

## 打包

```powershell
.\build.ps1
```

生成文件位于 `dist\C2Sherlock-Collector.exe`。发布时应将云端地址和允许来源配置为正式部署值，并对 EXE 进行代码签名。

## 本地接口

```text
GET  /status
GET  /interfaces
POST /start
POST /stop
```

同时只允许一个采集任务。上传失败时 PCAPNG 会保留在 `%LOCALAPPDATA%\C2Sherlock\Collector\captures`，再次调用 `/stop` 会重试上传；云端确认接收后本地文件才会删除。
