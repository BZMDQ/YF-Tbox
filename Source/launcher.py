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
                assert 'App' not in app.browse_button.cget('text')
                assert not hasattr(app, '_upload_app')
                # BOOT检查只创建入口和做本地/权限判定，不调用任何网络函数。
                import boot_update_client
                app._show_page('boot')
                assert 'boot' in app.nav_buttons and app.boot_start_button is not None
                app.host_var.set('127.0.0.1')
                app.key_path = None
                app.manual_key_var.set('')
                try:
                    app._boot_connection_inputs()
                except ValueError as exc:
                    assert 'Key' in str(exc)
                else:
                    raise AssertionError('BOOT入口仍允许空Key')
                boot_version = None
                test_boot = os.environ.get('BOOT_UPDATE_TEST_PACKAGE')
                if test_boot:
                    boot_version = boot_update_client.load_package(test_boot).version
                # 旧独立 App 包必须在本地拒绝，不得发起网络请求。
                for suffix in ('.fapp', '.fappb'):
                    try:
                        app._set_package(Path(directory) / ('retired' + suffix))
                    except ValueError as exc:
                        assert '系统 OTA' in str(exc)
                    else:
                        raise AssertionError('仍接受独立 App 包')
                app._select_ota_board('D133CBS · ArtInChip')
                assert app.ota_board_var.get() == 'D133CBS · ArtInChip'
                assert app.package_path is None
                assert app.boot_start_button.cget('state') == 'disabled'
                assert app.boot_browse_button.cget('state') == 'disabled'
                assert app.nav_buttons['boot'].cget('state') == 'disabled'
                try:
                    app._boot_connection_inputs()
                except ValueError as exc:
                    assert 'D133' in str(exc)
                else:
                    raise AssertionError('D133模式可以进入BOOT协议')
                package_version = None
                test_package = os.environ.get('D133_OTA_TEST_PACKAGE')
                if test_package:
                    app._set_package(Path(test_package))
                    package_version = app.package_version
                    assert package_version
                root.update_idletasks()
                app._select_ota_board('STM32F750')
                assert app.nav_buttons['boot'].cget('state') == 'normal'
                assert 'App' not in app.browse_button.cget('text')
                app._show_page('listen')
                assert app.listen_button.cget('text') == '保持信息连接'
                report.write_text(json.dumps({'ok': True, 'version': gui.APP_VERSION,
                                              'pages': list(app.pages),
                                              'device_metrics': list(app.device_metric_vars),
                                              'device_page_created': True, 'd133_selector_checked': True,
                                              'unified_system_ota_only': True,
                                              'listen_ui_checked': True,
                                              'boot_entry_checked': True,
                                              'boot_key_required': True,
                                              'boot_d133_isolation_checked': True,
                                              'boot_package_version': boot_version,
                                              'd133_ota_package_version': package_version}, ensure_ascii=False), encoding='utf-8')
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



