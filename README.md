# YF-Tbox

研发工具箱源码与 Windows x86 手动更新包仓库。工具箱界面不提供自动检查、下载或安装更新功能。

## 目录

- `Source/`：工具箱 Python 源码和构建脚本。
- `.github/workflows/release.yml`：Windows x86 手动更新包构建与 GitHub Release 发布流程。

## 手动更新

将 `Source/local_tcp_gui.py` 中的 `APP_VERSION` 更新后提交到 `main`。GitHub Actions 会生成 `_Manual_Overlay.zip` 与 SHA-256 文件，并发布版本 Release。

该 ZIP 仅包含工具箱应用运行文件，不含 CubeProgrammer、ST-LINK 驱动或许可证。手动更新时，将 ZIP 内容解压覆盖到已有工具箱安装目录；首次安装或从没有自动更新功能的旧版本升级，请使用 `D133-控制终端/downloads/` 中的完整便携包或自定义目录安装程序。

每个发布版本使用 `v主版本.次版本.修订号` 标签。GitHub 仓库公开，下载 Release 不需要 Token。工具箱本身不会联网检查或安装这些版本。

## 0.8.38

总览页新增连接分区标题和用途说明，按 IP/端口、设备选择、Local TCP Key 的顺序组织连接卡片；四个快捷入口增加说明，保留现有品牌蓝灰配色和业务行为。

## 0.8.37

D133CBS OTA 增加设备消息显示：TCP 信息应答和 OTA 开始应答会显示开发板消息；重启健康轮询使用 `0xD105`，旧固件不识别该命令时回退到原 `INFO` 查询。D133 的 CPIO、SHA-256、签名和 16 KiB 分片协议保持兼容。

