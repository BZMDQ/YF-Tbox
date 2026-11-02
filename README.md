# YF-Tbox

研发工具箱源码与 Windows x86 手动更新包仓库。工具箱界面不提供自动检查、下载或安装更新功能。

## 目录

- `Source/`：工具箱 Python 源码和构建脚本。
- `.github/workflows/release.yml`：Windows x86 手动更新包构建与 GitHub Release 发布流程。

## 手动更新

将 `Source/local_tcp_gui.py` 中的 `APP_VERSION` 更新后提交到 `main`。GitHub Actions 会生成 `_Manual_Overlay.zip` 与 SHA-256 文件，并发布版本 Release。

该 ZIP 仅包含工具箱应用运行文件，不含 CubeProgrammer、ST-LINK 驱动或许可证。手动更新时，将 ZIP 内容解压覆盖到已有工具箱安装目录；首次安装或从没有自动更新功能的旧版本升级，请使用 `D133-控制终端/downloads/` 中的完整便携包或自定义目录安装程序。

每个发布版本使用 `v主版本.次版本.修订号` 标签。GitHub 仓库公开，下载 Release 不需要 Token。工具箱本身不会联网检查或安装这些版本。
