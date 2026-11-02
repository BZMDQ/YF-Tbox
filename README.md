# YF-Tbox

研发工具箱源码、Windows 原位更新包与 GitHub 自动更新发布仓库。

## 目录

- `Source/`：工具箱 Python 源码、构建脚本和更新器。
- `.github/workflows/release.yml`：Windows x86 构建与 GitHub Release 发布流程。

## 发布更新

将 `Source/local_tcp_gui.py` 中的 `APP_VERSION` 更新为新版本，提交到 `main`。GitHub Actions 会使用 Python 3.8 x86 构建应用运行文件，并发布原位更新 ZIP 和 SHA-256 校验文件。原位更新包覆盖应用文件但保留本机 CubeProgrammer、ST-LINK 驱动、Key 和用户配置。

版本号不可重复。Release 使用 `v主版本.次版本.修订号` 标签。工具箱设置中的“检查更新”读取最新 Release，下载完整 onedir ZIP，并在安装前核对 SHA-256。

## 首次配置更新凭据

仓库为私有仓库。首次使用自动更新时，在 GitHub 创建 fine-grained personal access token：只选择 `BZMDQ/YF-Tbox`，只授予 `Contents: Read-only`。在工具箱设置中粘贴一次；程序通过当前 Windows 用户 DPAPI 加密保存，Token 不进入仓库、日志或更新包。

当前全量便携包和自定义目录安装程序保存在项目 `downloads/`。GitHub Release 上的 `_Update.zip` 是给已安装工具箱使用的原位更新包，不用于首次安装；用户在工具箱设置中检查更新后，程序会验证 SHA-256 并覆盖应用文件。

