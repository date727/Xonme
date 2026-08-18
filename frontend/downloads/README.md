# 本地采集控制器发布目录

在 Windows 上运行 `collector/build.ps1`，完成测试和代码签名后，将生成的 `collector/dist/C2Sherlock-Collector.exe` 复制到本目录。前端“下载采集控制器”按钮固定指向该文件。

不要将未经签名、未经真机抓包验证的开发构建直接发布给用户。
