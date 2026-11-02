"""Load the portable toolbox and apply the current workflow patch."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import encodings.idna
import json
import os
import tempfile
from pathlib import Path

import patch_toolbox
import localization


def _bundle_dir() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def _load_pyc(module_name: str, filename: str):
    path = _bundle_dir() / filename
    loader = importlib.machinery.SourcelessFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None:
        raise ImportError(f"无法加载内置模块：{filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    loader.exec_module(module)
    return module


def main() -> None:
    # The original GUI imports local_tcp_client by module name.
    _load_pyc("local_tcp_client", "local_tcp_client.pyc")
    _load_pyc("d133_ota_client", "d133_ota_client.pyc")
    # 目录扫描与界面共享同一个客户端实例，确保异常类型一致。
    import device_directory
    import test_fixture_ui
    gui = _load_pyc("local_tcp_gui_orig", "local_tcp_gui_orig.pyc")
    device_directory.install(gui)
    test_fixture_ui.install(gui)
    patch_toolbox.apply(gui)
    d133_ota_ui = _load_pyc("d133_ota_ui", "d133_ota_ui.pyc")
    d133_ota_ui.install(gui)
    localization.install(gui)
    if len(sys.argv) == 3 and sys.argv[1] == '--startup-check':
        report = Path(sys.argv[2])
        root = None
        try:
            with tempfile.TemporaryDirectory(prefix='toolbox_startup_') as directory:
                gui.settings_file = lambda: Path(directory) / 'settings.json'
                root = gui.ctk.CTk()
                root.withdraw()
                errors = []
                root.report_callback_exception = lambda *error: errors.append(str(error))
                app = gui.LocalTcpApp(root)
                root.update_idletasks()
                # Isolated diagnostic only: never connect to a board or write its name.
                app._sync_device_name = lambda *_args: None
                def widgets(parent):
                    for child in parent.winfo_children():
                        yield child
                        yield from widgets(child)
                # 设备页按需创建，隔离检查时主动切换后再调用控件。
                app._show_page('devices')
                root.update_idletasks()
                page = app.pages['devices']
                entries = [w for w in widgets(page) if isinstance(w, gui.ctk.CTkEntry)]
                button = next(w for w in widgets(page) if isinstance(w, gui.ctk.CTkButton)
                              and w.cget('text') == '添加到列表')
                entries[0].insert(0, '192.168.21.107')
                entries[1].insert(0, '123')
                button.invoke()
                if errors:
                    raise RuntimeError('; '.join(errors))
                # D133 验证只构建页面、切换开发板和校验本地包，不建立任何网络连接。
                app._show_page('ota')
                app._select_ota_board('D133CBS · ArtInChip')
                assert app.ota_board_var.get() == 'D133CBS · ArtInChip'
                assert app.package_path is None
                package_version = None
                test_package = os.environ.get('D133_OTA_TEST_PACKAGE')
                if test_package:
                    app._set_package(Path(test_package))
                    package_version = app.package_version
                    assert package_version
                root.update_idletasks()
                report.write_text(json.dumps({'ok': True, 'version': gui.APP_VERSION,
                                              'pages': list(app.pages),
                                              'device_metrics': list(app.device_metric_vars),
                                              'device_page_created': True, 'd133_board_selector': app.ota_board_var.get(), 'd133_ota_package_version': package_version}, ensure_ascii=False), encoding='utf-8')
        except Exception as exc:
            report.write_text(json.dumps({'ok': False, 'error': str(exc)}), encoding='utf-8')
            sys.exit(1)
        finally:
            if root is not None:
                root.destroy()
        return
    gui.main()


if __name__ == "__main__":
    main()



