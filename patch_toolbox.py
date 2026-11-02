"""Compatibility and workflow patches for the portable toolbox GUI."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from PIL import Image, ImageOps


DEFAULT_PART = "PIC24FJ256DA210"
U12_CAPACITY = 4 * 1024 * 1024


def _bundle_dir() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def _pic24_parts() -> list[str]:
    path = _bundle_dir() / "PIC24_Parts.json"
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        values = []
    parts = [str(item).strip().upper() for item in values if str(item).strip()]
    if DEFAULT_PART not in parts:
        parts.insert(0, DEFAULT_PART)
    return parts


def _programmer_roots() -> list[Path]:
    roots: list[Path] = []
    for key in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        value = os.environ.get(key)
        if value:
            roots.append(Path(value))
    return roots


def _registry_install_dirs() -> list[Path]:
    try:
        import winreg
    except ImportError:
        return []

    result: list[Path] = []
    keys = (
        r"SOFTWARE\Microchip\MPLAB IDE",
        r"SOFTWARE\WOW6432Node\Microchip\MPLAB IDE",
    )
    views = (0, getattr(winreg, "KEY_WOW64_32KEY", 0), getattr(winreg, "KEY_WOW64_64KEY", 0))
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for key_name in keys:
            for view in views:
                try:
                    with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ | view) as key:
                        for value_name in ("InstallDir", "InstallPath", "Path"):
                            try:
                                value, _ = winreg.QueryValueEx(key, value_name)
                            except OSError:
                                continue
                            if isinstance(value, str) and value.strip():
                                result.append(Path(value.strip()))
                        index = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, index)
                            except OSError:
                                break
                            index += 1
                            try:
                                with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ | view) as subkey:
                                    for value_name in ("InstallDir", "InstallPath", "Path"):
                                        try:
                                            value, _ = winreg.QueryValueEx(subkey, value_name)
                                        except OSError:
                                            continue
                                        if isinstance(value, str) and value.strip():
                                            result.append(Path(value.strip()))
                            except OSError:
                                continue
                except OSError:
                    continue
    return result


def _programmer_dll_path(cli_path: str | os.PathLike[str]) -> Path | None:
    """Find the PK3CMD DLL in the CLI folder or the standard MPLAB sibling folder."""
    cli = Path(cli_path)
    candidates = [cli.parent / "MPPICkit3.dll"]
    try:
        mplab_root = cli.parent.parent.parent
        candidates.extend(
            (
                mplab_root / "PICkit 3" / "MPPICkit3.dll",
                mplab_root / "PICkit3" / "MPPICkit3.dll",
                cli.parent.parent / "PICkit 3" / "MPPICkit3.dll",
            )
        )
    except (IndexError, OSError):
        pass

    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def discover_pk3cmd(configured_path: str | os.PathLike[str] | None = None) -> Path | None:
    """Find PK3CMD and its DLL in either supported MPLAB install layout."""
    candidates: list[Path] = []

    if configured_path:
        candidates.append(Path(configured_path))

    app_dir = _bundle_dir()
    candidates.extend(
        (
            app_dir / "PK3CMD.exe",
            app_dir / "MPLAB IDE" / "Programmer Utilities" / "PICkit3" / "PK3CMD.exe",
        )
    )

    for path_entry in os.environ.get("PATH", "").split(os.pathsep):
        if path_entry.strip():
            candidates.append(Path(path_entry.strip()) / "PK3CMD.exe")

    install_dirs = _registry_install_dirs()
    for root in _programmer_roots():
        microchip = root / "Microchip"
        install_dirs.extend((microchip / "MPLAB IDE", microchip))

    for install_dir in install_dirs:
        candidates.extend(
            (
                install_dir / "Programmer Utilities" / "PICkit3" / "PK3CMD.exe",
                install_dir / "MPLAB IDE" / "Programmer Utilities" / "PICkit3" / "PK3CMD.exe",
            )
        )
        try:
            for version_dir in install_dir.glob("*"):
                candidates.append(
                    version_dir / "Programmer Utilities" / "PICkit3" / "PK3CMD.exe"
                )
        except OSError:
            continue

    seen: set[str] = set()
    for candidate in candidates:
        try:
            candidate = candidate.expanduser().resolve()
            identity = os.path.normcase(str(candidate))
            if identity in seen:
                continue
            seen.add(identity)
            if candidate.is_file() and _programmer_dll_path(candidate) is not None:
                return candidate
        except OSError:
            continue
    return None


def native_image_or_bin(path: str | os.PathLike[str]) -> tuple[bytes, Image.Image | None]:
    """Keep BIN bytes exact; encode raster images at native dimensions as RGB565 BE."""
    source = Path(path)
    if source.suffix.lower() == ".bin":
        if source.stat().st_size > U12_CAPACITY:
            raise ValueError("BIN 文件超过 U12/W25Q32 的 4 MiB 容量。")
        data = source.read_bytes()
        if not data:
            raise ValueError("BIN 文件为空。")
        return data, None

    with Image.open(source) as opened:
        width, height = opened.size
        if width <= 0 or height <= 0:
            raise ValueError("图片尺寸无效。")
        if width * height * 2 > U12_CAPACITY:
            raise ValueError("按原尺寸转换后的图片超过 U12/W25Q32 的 4 MiB 容量。")
        image = ImageOps.exif_transpose(opened).convert("RGB")

    width, height = image.size
    output_size = width * height * 2
    if output_size <= 0:
        raise ValueError("图片尺寸无效。")
    if output_size > U12_CAPACITY:
        raise ValueError("按原尺寸转换后的图片超过 U12/W25Q32 的 4 MiB 容量。")

    rgb = image.tobytes()
    output = bytearray(output_size)
    for pixel_index, offset in enumerate(range(0, len(rgb), 3)):
        red, green, blue = rgb[offset : offset + 3]
        value = ((red & 0xF8) << 8) | ((green & 0xFC) << 3) | (blue >> 3)
        target = pixel_index * 2
        output[target] = (value >> 8) & 0xFF
        output[target + 1] = value & 0xFF
    return bytes(output), image


def _hide(widget) -> None:
    try:
        widget.grid_remove()
    except Exception:
        try:
            widget.pack_forget()
        except Exception:
            pass


def _latest_saved_pic24_backup(module) -> Path | None:
    backup_dir = module.u12_recovery_state_path().parent
    try:
        backups = list(backup_dir.glob(f"{DEFAULT_PART}_*_saved.hex"))
    except OSError:
        return None
    valid = []
    for path in backups:
        try:
            if path.is_file():
                valid.append((path.stat().st_mtime_ns, path))
        except OSError:
            continue
    return max(valid, default=(0, None))[1]


def _save_pic24_backup(module, source_path: str | os.PathLike[str]) -> Path:
    source = Path(source_path)
    memory = module.read_intel_hex_memory(source)
    if not any(0x400 <= address < 0x55800 for address in memory):
        raise ValueError("PIC24 备份中没有可恢复的用户程序数据。")

    backup_dir = module.u12_recovery_state_path().parent
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    destination = backup_dir / f"{DEFAULT_PART}_{timestamp}_saved.hex"
    suffix = 2
    while destination.exists():
        destination = backup_dir / f"{DEFAULT_PART}_{timestamp}_{suffix}_saved.hex"
        suffix += 1
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        shutil.copyfile(source, temporary)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _mark_u12_written_without_pic24_restore(
    module, backup_path: str | os.PathLike[str]
) -> dict:
    """Keep the recovery record when U12 succeeds but PIC24 restore is skipped."""
    state_path = module.u12_recovery_state_path()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    expected_backup = Path(backup_path).resolve()
    recorded_backup = Path(state["backup_path"]).resolve()
    if recorded_backup != expected_backup or not recorded_backup.is_file():
        raise ValueError("PIC24 恢复备份状态与当前写入不匹配，不能跳过恢复。")

    state["u12_write_complete"] = True
    state["pic24_restored"] = False
    temporary = state_path.with_name(state_path.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary.replace(state_path)
    finally:
        temporary.unlink(missing_ok=True)
    return state


def _update_tool_status(app, module, *, save: bool = False) -> Path | None:
    configured = getattr(app, "mplab_cli_path", None)
    path = discover_pk3cmd(configured)
    app.mplab_cli_path = path
    try:
        app.mplab_cli_path_var.set(str(path) if path else "未自动检测到 PK3CMD.exe")
        app.mplab_tool_status_var.set(
            "已自动检测到 MPLAB PICkit 3 命令行工具"
            if path
            else "未检测到 MPLAB PICkit 3 命令行工具"
        )
    except Exception:
        pass
    if save and path:
        try:
            app._save_settings()
        except Exception:
            pass
    return path


def _install_pk3cmd_environment(module) -> None:
    """Expose the separated MPLAB DLL folder to PK3CMD child processes."""
    original_popen = module.subprocess.Popen
    if getattr(original_popen, "_toolbox_pk3cmd_environment", False):
        return

    def patched_popen(args, *popen_args, **kwargs):
        executable = args[0] if isinstance(args, (list, tuple)) and args else args
        try:
            cli_path = Path(os.fsdecode(executable))
            if cli_path.name.casefold() == "pk3cmd.exe":
                dll_path = _programmer_dll_path(cli_path)
                if dll_path is not None:
                    child_env = dict(os.environ if kwargs.get("env") is None else kwargs["env"])
                    path_key = next(
                        (key for key in child_env if key.casefold() == "path"), "PATH"
                    )
                    path_value = child_env.get(path_key, "")
                    dll_dir = str(dll_path.parent)
                    existing_dirs = {
                        os.path.normcase(os.path.abspath(entry.strip().strip('"')))
                        for entry in path_value.split(os.pathsep)
                        if entry.strip()
                    }
                    dll_identity = os.path.normcase(os.path.abspath(dll_dir))
                    if dll_identity not in existing_dirs:
                        child_env[path_key] = (
                            dll_dir + (os.pathsep + path_value if path_value else "")
                        )
                    kwargs["env"] = child_env
        except (OSError, TypeError, ValueError):
            pass
        return original_popen(args, *popen_args, **kwargs)

    patched_popen._toolbox_pk3cmd_environment = True
    module.subprocess.Popen = patched_popen


def _walk_widgets(widget):
    try:
        children = widget.winfo_children()
    except Exception:
        return
    for child in children:
        yield child
        yield from _walk_widgets(child)


def apply(module) -> None:
    """Patch only the requested MPLAB and U12 workflow behavior."""
    module.APP_VERSION = "0.8.34"
    module.PIC24_U12_STATUS_HEX_ADDRESS = 0x54F00
    module.PIC24_U12_MAX_STAGED_BYTES = ((0x54800 - 0x8000) // 4) * 3
    module.discover_pk3cmd = lambda *_args, **_kwargs: None
    module.rgb565_be_image = native_image_or_bin
    original_app_resource_path = module.app_resource_path

    def patched_app_resource_path(name):
        candidate = original_app_resource_path(name)
        if Path(name).name.lower() == "u12_pic24_bridge.hex" and not candidate.is_file():
            nested = original_app_resource_path(
                Path("U12_PIC24_Bridge") / Path(name).name
            )
            if nested.is_file():
                return nested
        return candidate

    module.app_resource_path = patched_app_resource_path
    app_class = module.LocalTcpApp
    original_init = app_class.__init__
    original_build_mplab = app_class._build_mplab_page
    original_build_u12 = app_class._build_u12_page
    original_refresh_u12 = app_class._refresh_u12_recovery_view
    original_read_once = app_class._read_once
    original_start_u12 = app_class._start_u12_programming
    original_start_u12_restore = app_class._start_u12_restore
    original_start_mplab = app_class._start_mplab_programming

    def patched_init(self, root, *args, **kwargs):
        original_init(self, root, *args, **kwargs)
        try:
            self.info_button.configure(command=self._read_once, state=module.tk.NORMAL)
        except Exception:
            pass

    def patched_read_once(self):
        self._append_log("连接按钮已触发：准备读取设备信息。")
        return original_read_once(self)

    def patched_build_mplab(self):
        original_build_mplab(self)
        _hide(getattr(self, "mplab_cli_button", None))

        old = getattr(self, "mplab_device_entry", None)
        if old is not None:
            combo = None
            try:
                info = old.grid_info()
                master = old.master
                combo = module.ctk.CTkComboBox(
                    master,
                    values=_pic24_parts(),
                    variable=self.mplab_device_var,
                    state="normal",
                )
                combo.grid(
                    row=int(info.get("row", 0)),
                    column=int(info.get("column", 0)),
                    columnspan=int(info.get("columnspan", 1)),
                    padx=info.get("padx", 0),
                    pady=info.get("pady", 0),
                    sticky=info.get("sticky", "ew"),
                )
            except Exception:
                if combo is not None:
                    try:
                        combo.destroy()
                    except Exception:
                        pass
                return
            try:
                old.destroy()
            except Exception:
                combo.destroy()
                return
            try:
                self.action_widgets.remove(old)
            except ValueError:
                pass
            self.mplab_device_entry = self._register_action(combo)

        action_card = self.mplab_program_button.master.master
        for widget in action_card.winfo_children():
            info = widget.grid_info()
            if info and int(info.get("row", -1)) >= 3:
                widget.grid_configure(row=int(info["row"]) + 1)
        self.mplab_fast_write_var = module.tk.BooleanVar(master=self.root, value=True)
        self.mplab_fast_write_checkbox = self._register_action(
            module.ctk.CTkCheckBox(
                action_card,
                text="快速烧录（跳过独立回读校验）",
                variable=self.mplab_fast_write_var,
                font=self._font(10),
                text_color=module.COLORS["text"],
                checkbox_width=18,
                checkbox_height=18,
            )
        )
        self.mplab_fast_write_checkbox.grid(
            row=3, column=0, sticky="w", padx=17, pady=(0, 8)
        )

        for widget in _walk_widgets(action_card):
            try:
                text = str(widget.cget("text"))
            except Exception:
                continue
            if text.startswith("写入 HEX 中包含的程序与配置数据"):
                widget.configure(
                    text="快速模式省略 PK3CMD 单独回读校验；取消勾选后会执行完整校验。"
                )
    def patched_build_u12(self):
        original_build_u12(self)
        _hide(getattr(self, "u12_cli_button", None))
        try:
            self.u12_choose_button.configure(text="选择图片或 BIN…")
        except Exception:
            pass
        for widget in _walk_widgets(self.root):
            try:
                text = str(widget.cget("text"))
            except Exception:
                continue
            if "自动裁切" in text or "800 × 480" in text or "800×480" in text:
                try:
                    widget.configure(
                        text="图片保留原尺寸并转为 RGB565 大端数据；BIN 文件按原始字节写入 U12。"
                    )
                except Exception:
                    pass

        action_card = self.u12_program_button.master.master
        for widget in action_card.winfo_children():
            info = widget.grid_info()
            if info and int(info.get("row", -1)) >= 2:
                widget.grid_configure(row=int(info["row"]) + 1)

        self.u12_direct_write_var = module.tk.BooleanVar(master=self.root, value=True)
        self.u12_backup_write_var = module.tk.BooleanVar(master=self.root, value=True)
        options_row = module.ctk.CTkFrame(action_card, fg_color="transparent")
        options_row.grid(row=2, column=0, sticky="ew", padx=17, pady=(0, 8))
        self.u12_direct_write_checkbox = self._register_action(
            module.ctk.CTkCheckBox(
                options_row,
                text="直接写入 U12",
                variable=self.u12_direct_write_var,
                font=self._font(10),
                text_color=module.COLORS["text"],
                checkbox_width=18,
                checkbox_height=18,
            )
        )
        self.u12_direct_write_checkbox.grid(row=0, column=0, sticky="w", padx=(0, 22))
        self.u12_backup_write_checkbox = self._register_action(
            module.ctk.CTkCheckBox(
                options_row,
                text="写入完成后恢复 PIC24 并保留备份",
                variable=self.u12_backup_write_var,
                font=self._font(10),
                text_color=module.COLORS["text"],
                checkbox_width=18,
                checkbox_height=18,
            )
        )
        self.u12_backup_write_checkbox.grid(row=0, column=1, sticky="w")
        self.u12_fast_write_var = module.tk.BooleanVar(master=self.root, value=True)
        self.u12_fast_write_checkbox = self._register_action(
            module.ctk.CTkCheckBox(
                options_row,
                text="快速烧录（跳过 U12 回读 CRC）",
                variable=self.u12_fast_write_var,
                font=self._font(10),
                text_color=module.COLORS["text"],
                checkbox_width=18,
                checkbox_height=18,
            )
        )
        self.u12_fast_write_checkbox.grid(row=0, column=2, sticky="w", padx=(22, 0))
        self.u12_policy_hint_label = None
        for widget in _walk_widgets(action_card):
            try:
                if str(widget.cget("text")).startswith("过程会临时改写 PIC24"):
                    self.u12_policy_hint_label = widget
                    break
            except Exception:
                continue
        self.u12_saved_backup_path = _latest_saved_pic24_backup(module)

        def sync_u12_options(*_):
            direct = self.u12_direct_write_var.get()
            backup = self.u12_backup_write_var.get()
            if direct:
                self.u12_backup_write_checkbox.configure(
                    text="写入完成后恢复 PIC24 并保留备份"
                )
                text = "写入 U12 并恢复 PIC24" if backup else "写入 U12（不恢复 PIC24）"
            elif backup:
                self.u12_backup_write_checkbox.configure(text="备份 PIC24 原程序到本机")
                text = "备份 PIC24 到本机"
            else:
                self.u12_backup_write_checkbox.configure(text="备份 PIC24 原程序到本机")
                text = "请选择写入或备份"
            self.u12_fast_write_checkbox.configure(
                state=module.tk.NORMAL if direct else module.tk.DISABLED
            )
            if self.u12_policy_hint_label is not None:
                if direct:
                    finish = "成功后恢复 PIC24 并保留备份。" if backup else "成功后保留桥接程序，不恢复 PIC24。"
                    hint = "一次点击自动完成全部分块。工具先保存 PIC24 恢复备份；" + finish + "失败时自动尝试恢复。烧录期间保持供电和 PICkit 3 连接。"
                else:
                    hint = "只将 PIC24 原程序备份到本机，不写入 U12。"
                self.u12_policy_hint_label.configure(text=hint)
            self.u12_program_button.configure(text=text)
            self._refresh_u12_recovery_view()

        self.u12_direct_write_var.trace_add("write", sync_u12_options)
        self.u12_backup_write_var.trace_add("write", sync_u12_options)
        sync_u12_options()

    def patched_refresh_u12(self):
        original_refresh_u12(self)
        if not hasattr(self, "u12_direct_write_var"):
            return

        saved_backup = _latest_saved_pic24_backup(module)
        self.u12_saved_backup_path = saved_backup
        pending = bool(self.u12_recovery_state)
        running = bool(self.is_running)
        if pending:
            if (
                self.u12_recovery_state.get("u12_write_complete")
                and not self.u12_recovery_state.get("pic24_restored", True)
            ):
                self.u12_recovery_status_var.set(
                    "U12 已写入；PIC24 原程序未恢复。备份已保留，请点击“恢复 PIC24 备份”。"
                )
        elif saved_backup:
            self.u12_recovery_status_var.set(
                f"本机 PIC24 备份已保存：{saved_backup.name}；可点击“恢复 PIC24 备份”。"
            )
        else:
            self.u12_recovery_status_var.set("当前没有待恢复或已保存的 PIC24 备份。")

        direct = self.u12_direct_write_var.get()
        can_backup = self.u12_backup_write_var.get()
        can_start = not running and not pending and (
            (direct and bool(self.u12_image_data)) or (not direct and can_backup)
        )
        self.u12_program_button.configure(
            state=module.tk.NORMAL if can_start else module.tk.DISABLED
        )
        can_restore = (pending or bool(saved_backup)) and not running
        self.u12_restore_button.configure(
            state=module.tk.NORMAL if can_restore else module.tk.DISABLED
        )

    def patched_choose_u12(self):
        filetypes = (
            ("U12 BIN 或图片", "*.bin *.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp"),
            ("BIN 文件", "*.bin"),
            ("图片文件", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff *.webp"),
            ("所有文件", "*.*"),
        )
        try:
            initial_dir = (
                self.u12_image_path.parent
                if self.u12_image_path is not None
                else self.base_dir
            )
        except Exception:
            initial_dir = self.base_dir

        chosen = module.filedialog.askopenfilename(
            parent=self.root,
            title="选择写入 U12 的 BIN 文件或图片",
            initialdir=str(initial_dir),
            filetypes=filetypes,
        )
        if not chosen:
            return

        path = Path(chosen).resolve()
        try:
            payload, preview = native_image_or_bin(path)
        except Exception as exc:
            module.messagebox.showerror("文件无法导入", str(exc), parent=self.root)
            return

        self.u12_image_path = path
        self.u12_image_data = payload
        self.u12_image_name_var.set(path.name)
        self.u12_image_path_var.set(str(path))
        if path.suffix.lower() == ".bin":
            detail = f"原始 BIN，逐字节写入；{len(payload):,} 字节"
            self.u12_preview = None
            self.u12_preview_label.configure(
                image="",
                text="BIN 原始数据\n烧录时逐字节写入，不做图像转换。",
            )
        else:
            width, height = preview.size
            detail = f"{width} × {height}，原尺寸 RGB565 大端；{len(payload):,} 字节"
            self.u12_preview = module.ctk.CTkImage(
                light_image=preview,
                dark_image=preview,
                size=(320, 192),
            )
            self.u12_preview_label.configure(image=self.u12_preview, text="")

        self.u12_image_detail_var.set(detail)
        self.u12_progress_text_var.set("文件已就绪；确认后写入 U12。")
        self._append_log(f"U12 文件已载入：{path.name}，{len(payload):,} 字节")
        self._refresh_u12_recovery_view()

    def start_pic24_backup_only(self_app, cli_path):
        if self_app.u12_recovery_state:
            module.messagebox.showerror(
                "需要先恢复 PIC24",
                "当前存在未完成的 PIC24 恢复记录。请先恢复该备份，再创建新的本机备份。",
                parent=self_app.root,
            )
            return
        if not module.messagebox.askyesno(
            "确认备份 PIC24",
            "工具将读取 PIC24 当前程序并保存到本机恢复区，不会写入 U12 或改写 PIC24。继续吗？",
            parent=self_app.root,
        ):
            return

        def action(args, key, stop_event):
            temporary_hex = Path(module.create_ascii_temp_file("U12_BKUP_", ".hex"))
            try:
                self_app._post("status", "正在读取 PIC24 并保存本机备份…")
                self_app._post("progress", (5, 100))
                code, _ = self_app._run_pk3_command(
                    cli_path,
                    [f"-P{DEFAULT_PART}", f"-GF{temporary_hex}"],
                    stop_event,
                    "正在读取 PIC24 当前程序…",
                    progress_range=(5, 85),
                )
                if code != 0 or not temporary_hex.is_file() or temporary_hex.stat().st_size == 0:
                    raise RuntimeError(f"读取 PIC24 失败（PK3CMD 退出代码 {code}）。")
                saved_path = _save_pic24_backup(module, temporary_hex)
                self_app.u12_saved_backup_path = saved_path
                self_app._post("log", f"PIC24 本机恢复备份已保存：{saved_path}")
                self_app._post("progress", (100, 100))
                self_app._post("status", "PIC24 本机备份完成")
                self_app._post("u12_progress_text", "PIC24 原程序已保存到本机恢复区。")
            finally:
                temporary_hex.unlink(missing_ok=True)

        self_app._start_task("备份 PIC24 原程序到本机", action, require_connection=False)

    def patched_start_u12_restore(self):
        if self.u12_recovery_state:
            return original_start_u12_restore(self)

        backup_path = _latest_saved_pic24_backup(module)
        if backup_path is None:
            module.messagebox.showerror("找不到备份", "没有可用的 PIC24 本机备份 HEX。", parent=self.root)
            return
        cli_path = self._u12_cli_path()
        if cli_path is None:
            return
        if not module.messagebox.askyesno(
            "确认恢复 PIC24",
            f"将使用本机备份恢复 PIC24：\n{backup_path}\n\n保持开发板供电并连接 PICkit 3。继续吗？",
            parent=self.root,
        ):
            return

        def action(args, key, stop_event):
            self._post("log", f"使用本机备份恢复 PIC24：{backup_path.name}")
            self._restore_u12_backup(
                cli_path, backup_path, stop_event, progress_range=(5, 95)
            )
            self._post("progress", (100, 100))
            self._post("status", "PIC24 已从本机备份恢复并校验")
            self._post("u12_progress_text", "PIC24 已从本机备份恢复并校验。")
            self._post("log", "PIC24 已从本机备份恢复并通过 PK3CMD 校验；备份文件仍保留。")

        self._start_task("恢复本机 PIC24 备份", action, require_connection=False)

    def patched_start_u12(self):
        if not _update_tool_status(self, module):
            module.messagebox.showerror(
                "未检测到 MPLAB 命令行工具",
                "未找到 PK3CMD.exe 和配套的 MPPICkit3.dll。请安装 MPLAB IDE v8.90，"
                "工具会自动检测，无需手动选择命令行文件。",
                parent=self.root,
            )
            return

        direct_write = bool(self.u12_direct_write_var.get())
        save_backup = bool(self.u12_backup_write_var.get())
        fast_u12 = bool(self.u12_fast_write_var.get())
        if not direct_write:
            if not save_backup:
                module.messagebox.showerror(
                    "未选择操作",
                    "请勾选“直接写入 U12”或“备份 PIC24 原程序到本机恢复区”。",
                    parent=self.root,
                )
                return
            return start_pic24_backup_only(self, self.mplab_cli_path)

        original_askyesno = module.messagebox.askyesno
        is_bin = bool(self.u12_image_path and self.u12_image_path.suffix.lower() == ".bin")
        format_label = "原始 BIN 字节" if is_bin else "原尺寸 RGB565 大端"

        def ask_with_native_format(title, message, *args, **kwargs):
            message = str(message)
            message = message.replace("图片：", "文件：")
            message = message.replace("800 × 480 RGB565", format_label)
            message = message.replace("800×480 RGB565", format_label)
            if fast_u12:
                message = message.replace(
                    "擦除并校验 U12",
                    "擦除并写入 U12（快速模式跳过外部 Flash 回读 CRC）",
                )
            if save_backup:
                message = message.replace(
                    "最后恢复 PIC24。",
                    "最后恢复 PIC24，并保留一份本机备份。",
                )
            else:
                message = message.replace(
                    "最后恢复 PIC24。",
                    "完成后不恢复 PIC24 原程序，PIC24 将保留 U12 桥接程序；"
                    "恢复备份会保留，之后可手动恢复。",
                )
            return original_askyesno(title, message, *args, **kwargs)

        original_start_task = self._start_task

        def start_task_with_u12_policy(title, action, require_connection=True):
            def action_with_u12_policy(args, key, stop_event):
                original_runner = self._run_pk3_command
                original_restore = self._restore_u12_backup
                original_clear = self._clear_u12_recovery_state
                original_post = self._post
                skipped_final_restore = False
                preserved_state = None

                def run_and_save_backup(cli, command_args, *run_args, **run_kwargs):
                    result = original_runner(cli, command_args, *run_args, **run_kwargs)
                    code = result[0] if isinstance(result, tuple) and result else None
                    if code == 0:
                        for argument in command_args:
                            if not isinstance(argument, str) or not argument.startswith("-GF"):
                                continue
                            source = Path(argument[3:])
                            if source.name.startswith("U12_BKUP_") and source.is_file():
                                saved_path = _save_pic24_backup(module, source)
                                self.u12_saved_backup_path = saved_path
                                original_post("log", f"PIC24 本机恢复备份已保存：{saved_path}")
                                break
                    return result

                def restore_with_selected_policy(
                    cli, backup_path, restore_stop_event, ignore_stop=False,
                    progress_range=None,
                ):
                    nonlocal skipped_final_restore, preserved_state
                    is_success_restore = progress_range == (88, 12) and not ignore_stop
                    if not save_backup and is_success_restore:
                        try:
                            preserved_state = _mark_u12_written_without_pic24_restore(
                                module, backup_path
                            )
                        except (OSError, ValueError, KeyError, TypeError) as exc:
                            original_post(
                                "log",
                                f"无法安全保留 PIC24 恢复记录，将按安全流程恢复原程序：{exc}",
                            )
                        else:
                            skipped_final_restore = True
                            original_post(
                                "u12_recovery", preserved_state
                            )
                            original_post(
                                "log",
                                "U12 已写入；按设置未恢复 PIC24 原程序，恢复备份已保留。",
                            )
                            return None
                    return original_restore(
                        cli, backup_path, restore_stop_event,
                        ignore_stop=ignore_stop, progress_range=progress_range,
                    )

                def clear_recovery_with_selected_policy(state):
                    if skipped_final_restore:
                        return None
                    return original_clear(state)

                def post_with_selected_policy(kind, value=None):
                    if skipped_final_restore:
                        if kind == "u12_recovery" and value is None:
                            return original_post(kind, preserved_state)
                        if kind == "log" and value == (
                            "U12 图片写入和整图 CRC 校验通过；PIC24 原程序已恢复并校验。"
                        ):
                            value = (
                                "U12 图片写入和整图 CRC 校验通过；PIC24 原程序未恢复，"
                                "恢复备份仍保留。"
                            )
                        elif kind == "status" and value == "U12 写入完成，PIC24 已恢复":
                            value = "U12 写入完成，PIC24 原程序未恢复"
                        elif kind == "log" and value == "U12 图片已写入；快速模式跳过 U12 回读 CRC，PIC24 原程序已恢复并校验。":
                            value = "U12 图片已写入；快速模式跳过 U12 回读 CRC，PIC24 原程序未恢复，恢复备份已保留。"
                        elif kind == "u12_progress_text" and value == "U12 图片已写入（快速模式跳过 U12 回读 CRC）；PIC24 原程序已恢复。":
                            value = "U12 图片已写入（快速模式跳过 U12 回读 CRC）；PIC24 原程序未恢复，备份已保留。"
                        elif kind == "u12_progress_text" and value == (
                            "U12 已写入并校验，PIC24 原程序已恢复。"
                        ):
                            value = "U12 已写入并校验；PIC24 原程序未恢复，备份已保留。"
                    return original_post(kind, value)

                self._restore_u12_backup = restore_with_selected_policy
                self._clear_u12_recovery_state = clear_recovery_with_selected_policy
                self._post = post_with_selected_policy
                if save_backup:
                    self._run_pk3_command = run_and_save_backup
                try:
                    return action(args, key, stop_event)
                finally:
                    self._run_pk3_command = original_runner
                    self._restore_u12_backup = original_restore
                    self._clear_u12_recovery_state = original_clear
                    self._post = original_post

            return original_start_task(
                title, action_with_u12_policy, require_connection=require_connection
            )

        module.messagebox.askyesno = ask_with_native_format
        self._start_task = start_task_with_u12_policy
        try:
            return original_start_u12(self)
        finally:
            self._start_task = original_start_task
            module.messagebox.askyesno = original_askyesno

    def patched_start_mplab(self):
        if not _update_tool_status(self, module):
            module.messagebox.showerror(
                "未检测到 MPLAB 命令行工具",
                "未找到 PK3CMD.exe 和配套的 MPPICkit3.dll。请安装 MPLAB IDE v8.90，"
                "工具会自动检测，无需手动选择命令行文件。",
                parent=self.root,
            )
            return

        cli_path = self.mplab_cli_path
        dll_path = _programmer_dll_path(cli_path)
        if dll_path is None:
            module.messagebox.showerror(
                "MPLAB 组件不完整",
                "未找到 PK3CMD.exe 配套的 MPPICkit3.dll。工具支持 DLL 位于 PK3CMD.exe 同目录，"
                "或位于 MPLAB IDE\\PICkit 3 目录。",
                parent=self.root,
            )
            return

        original_start_task = self._start_task
        original_askyesno = module.messagebox.askyesno
        fast_write = bool(
            getattr(self, "mplab_fast_write_var", None)
            and self.mplab_fast_write_var.get()
        )

        def run_with_fast_write(title, action, require_connection=True):
            def action_with_fast_write(args, key, stop_event):
                if not fast_write:
                    return action(args, key, stop_event)

                original_popen = module.subprocess.Popen
                original_post = self._post

                def fast_popen(command, *popen_args, **popen_kwargs):
                    if isinstance(command, (list, tuple)) and command:
                        executable = Path(str(command[0])).name.casefold()
                        if executable == "pk3cmd.exe":
                            command = [
                                item for item in command
                                if str(item).strip().casefold() != "-y"
                            ]
                    return original_popen(command, *popen_args, **popen_kwargs)

                def fast_post(kind, value=None):
                    if kind == "log" and isinstance(value, str):
                        if "写入并校验" in value:
                            value = value.replace(
                                "写入并校验", "快速写入（跳过独立回读校验）"
                            )
                        if value == "PIC24 HEX 烧录与校验完成。":
                            value = "PIC24 HEX 快速写入完成；已跳过独立回读校验。"
                    elif kind == "status" and value == "PIC24 烧录并校验完成":
                        value = "PIC24 HEX 快速写入完成"
                    elif kind == "status" and value == "正在校验 PIC24…":
                        value = "PK3CMD 快速写入已结束"
                    return original_post(kind, value)

                module.subprocess.Popen = fast_popen
                self._post = fast_post
                try:
                    return action(args, key, stop_event)
                finally:
                    module.subprocess.Popen = original_popen
                    self._post = original_post

            return original_start_task(
                title, action_with_fast_write, require_connection=require_connection
            )

        def ask_with_fast_mode(title, message, *args, **kwargs):
            if fast_write:
                message = str(message).replace(
                    "PK3CMD 将按 HEX 内容写入 PIC24 并执行校验。",
                    "快速模式会跳过 PK3CMD 单独回读校验；取消快速选项可执行完整校验。",
                )
            return original_askyesno(title, message, *args, **kwargs)

        self._start_task = run_with_fast_write
        module.messagebox.askyesno = ask_with_fast_mode
        expected_dll = cli_path.parent / "MPPICkit3.dll"
        expected_id = os.path.normcase(os.path.abspath(str(expected_dll)))
        actual_id = os.path.normcase(os.path.abspath(str(dll_path)))
        try:
            if expected_id == actual_id:
                return original_start_mplab(self)

            # The recovered GUI bytecode requires the DLL beside PK3CMD. Present
            # the real sibling DLL only for that one synchronous check.
            original_is_file = Path.is_file

            def compatible_is_file(candidate):
                try:
                    candidate_id = os.path.normcase(os.path.abspath(str(candidate)))
                    if candidate_id == expected_id:
                        return original_is_file(dll_path)
                except (OSError, TypeError, ValueError):
                    pass
                return original_is_file(candidate)

            def ask_with_path_check_restored(title, message, *args, **kwargs):
                Path.is_file = original_is_file
                try:
                    return ask_with_fast_mode(title, message, *args, **kwargs)
                finally:
                    Path.is_file = compatible_is_file

            def start_task_with_path_check_restored(*args, **kwargs):
                Path.is_file = original_is_file
                module.messagebox.askyesno = ask_with_fast_mode
                return run_with_fast_write(*args, **kwargs)

            Path.is_file = compatible_is_file
            module.messagebox.askyesno = ask_with_path_check_restored
            self._start_task = start_task_with_path_check_restored
            try:
                return original_start_mplab(self)
            finally:
                Path.is_file = original_is_file
        finally:
            module.messagebox.askyesno = original_askyesno
            self._start_task = original_start_task

    def auto_u12_cli_path(self):
        path = _update_tool_status(self, module)
        if path is None:
            module.messagebox.showerror(
                "未检测到 MPLAB 命令行工具",
                "未找到 PK3CMD.exe 和配套的 MPPICkit3.dll。请安装 MPLAB IDE v8.90，"
                "工具会自动检测，无需手动选择命令行文件。",
                parent=self.root,
            )
            return None
        return path

    def removed_programming_feature(self, *args, **kwargs):
        module.messagebox.showinfo(
            "功能已移除",
            "PIC24 HEX 烧录、U12 烧录和图片预览已从此工具箱版本中移除。",
            parent=self.root,
        )

    def removed_programming_page(self):
        return None

    app_class.__init__ = patched_init
    app_class._read_once = patched_read_once
    app_class._build_mplab_page = patched_build_mplab
    app_class._build_u12_page = patched_build_u12
    app_class._refresh_u12_recovery_view = patched_refresh_u12
    app_class._choose_u12_image = patched_choose_u12
    app_class._start_u12_restore = patched_start_u12_restore
    app_class._start_u12_programming = patched_start_u12
    app_class._start_mplab_programming = patched_start_mplab
    app_class._u12_cli_path = auto_u12_cli_path
    app_class._build_mplab_page = removed_programming_page
    app_class._build_u12_page = removed_programming_page
    app_class._start_mplab_programming = removed_programming_feature
    app_class._start_u12_programming = removed_programming_feature
    app_class._start_u12_restore = removed_programming_feature
    app_class._choose_u12_image = removed_programming_feature
    app_class._choose_mplab_hex_file = removed_programming_feature
    app_class._choose_pk3cmd = removed_programming_feature
    app_class._u12_cli_path = removed_programming_feature

