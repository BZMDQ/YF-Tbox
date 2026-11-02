"""Runtime Simplified/Traditional Chinese localization for the toolbox UI."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from opencc import OpenCC


class _Localization:
    def __init__(self):
        self.language = "zh-CN"
        self.s2tw = OpenCC("s2tw")
        self.t2s = OpenCC("t2s")
        self.widgets = []
        self.variables = []
        self.windows = []
        self.suspend = False

    def translate(self, value, language=None):
        if not isinstance(value, str):
            return value
        language = language or self.language
        if language == "zh-TW":
            return self.s2tw.convert(value)
        return value

    def convert_between(self, value, old_language, new_language):
        if not isinstance(value, str) or old_language == new_language:
            return value
        if old_language == "zh-TW":
            return self.t2s.convert(value)
        return self.s2tw.convert(value)

    def _register_variable(self, variable):
        if not hasattr(variable, "trace_add") or not hasattr(variable, "get"):
            return
        if any(item is variable for item in self.variables):
            return
        self.variables.append(variable)

        def changed(*_):
            if self.suspend:
                return
            try:
                value = variable.get()
                translated = self.translate(value)
                if translated != value:
                    self.suspend = True
                    variable.set(translated)
            except (tk.TclError, TypeError):
                pass
            finally:
                self.suspend = False

        try:
            variable.trace_add("write", changed)
            value = variable.get()
            translated = self.translate(value)
            if translated != value:
                self.suspend = True
                variable.set(translated)
        except (tk.TclError, TypeError):
            pass
        finally:
            self.suspend = False

    def _register_widget(self, widget, raw_text=None, raw_placeholder=None, raw_values=None,
                         variable=None, original_configure=None):
        self.widgets.append(widget)
        widget._toolbox_loc_text = raw_text
        widget._toolbox_loc_placeholder = raw_placeholder
        widget._toolbox_loc_values = raw_values
        widget._toolbox_loc_original_configure = original_configure
        if variable is not None:
            self._register_variable(variable)

    def _patch_ctk_widget(self, class_name, text_keys=(), values_key=None):
        cls = getattr(ctk, class_name, None)
        if cls is None or getattr(cls, "_toolbox_loc_patched", False):
            return
        original_init = cls.__init__
        original_configure = cls.configure
        manager = self

        def configure(widget, *args, **kwargs):
            if getattr(widget, "_toolbox_user_data", False):
                return original_configure(widget, *args, **kwargs)
            raw_text = kwargs.get("text") if "text" in kwargs else None
            raw_placeholder = kwargs.get("placeholder_text") if "placeholder_text" in kwargs else None
            raw_values = kwargs.get(values_key) if values_key and values_key in kwargs else None
            if raw_text is not None:
                widget._toolbox_loc_text = raw_text
                kwargs["text"] = manager.translate(raw_text)
            if raw_placeholder is not None:
                widget._toolbox_loc_placeholder = raw_placeholder
                kwargs["placeholder_text"] = manager.translate(raw_placeholder)
            if raw_values is not None:
                widget._toolbox_loc_values = list(raw_values)
                kwargs[values_key] = [manager.translate(value) for value in raw_values]
            return original_configure(widget, *args, **kwargs)

        def init(widget, *args, **kwargs):
            raw_text = kwargs.get("text")
            raw_placeholder = kwargs.get("placeholder_text")
            raw_values = list(kwargs[values_key]) if values_key and values_key in kwargs else None
            variable = (kwargs.get("textvariable") or kwargs.get("variable")) if class_name in ("CTkLabel", "CTkCheckBox", "CTkRadioButton") else None
            if raw_text is not None:
                kwargs["text"] = manager.translate(raw_text)
            if raw_placeholder is not None:
                kwargs["placeholder_text"] = manager.translate(raw_placeholder)
            if raw_values is not None:
                kwargs[values_key] = [manager.translate(value) for value in raw_values]
            original_init(widget, *args, **kwargs)
            manager._register_widget(
                widget, raw_text, raw_placeholder, raw_values, variable, original_configure)

        cls.configure = configure
        cls.config = configure
        cls.__init__ = init
        cls._toolbox_loc_patched = True

    def _patch_window_title(self, cls):
        if getattr(cls, "_toolbox_loc_title_patched", False):
            return
        original_title = cls.title
        manager = self

        def title(window, value=None):
            if value is None:
                return original_title(window)
            window._toolbox_loc_title = value
            window._toolbox_loc_title_setter = original_title
            if not any(item is window for item in manager.windows):
                manager.windows.append(window)
            return original_title(window, manager.translate(value))

        cls.title = title
        cls._toolbox_loc_title_patched = True

    def _patch_message_boxes(self):
        for name in ("showinfo", "showwarning", "showerror", "askyesno", "askokcancel"):
            original = getattr(messagebox, name)
            manager = self

            def wrapped(*args, _original=original, **kwargs):
                args = list(args)
                if len(args) > 0:
                    args[0] = manager.translate(args[0])
                if len(args) > 1:
                    args[1] = manager.translate(args[1])
                if "title" in kwargs:
                    kwargs["title"] = manager.translate(kwargs["title"])
                if "message" in kwargs:
                    kwargs["message"] = manager.translate(kwargs["message"])
                return _original(*args, **kwargs)

            setattr(messagebox, name, wrapped)

    def _patch_file_dialogs(self):
        for name in ("askopenfilename", "asksaveasfilename", "askdirectory"):
            original = getattr(filedialog, name)
            manager = self

            def wrapped(*args, _original=original, **kwargs):
                if "title" in kwargs:
                    kwargs["title"] = manager.translate(kwargs["title"])
                if "filetypes" in kwargs:
                    kwargs["filetypes"] = [
                        (manager.translate(label), pattern)
                        for label, pattern in kwargs["filetypes"]
                    ]
                return _original(*args, **kwargs)

            setattr(filedialog, name, wrapped)

    def switch(self, app, language):
        if language not in ("zh-CN", "zh-TW") or language == self.language:
            return
        old_language = self.language
        self.suspend = True
        self.language = language
        for variable in list(self.variables):
            try:
                variable.set(self.convert_between(variable.get(), old_language, language))
            except (tk.TclError, TypeError):
                pass
        self.suspend = False

        active_widgets = []
        for widget in list(self.widgets):
            try:
                if getattr(widget, "_toolbox_user_data", False):
                    active_widgets.append(widget)
                    continue
                configure = widget._toolbox_loc_original_configure
                if configure is None or not widget.winfo_exists():
                    continue
                options = {}
                if widget._toolbox_loc_text is not None:
                    options["text"] = self.translate(widget._toolbox_loc_text)
                if widget._toolbox_loc_placeholder is not None:
                    options["placeholder_text"] = self.translate(widget._toolbox_loc_placeholder)
                if widget._toolbox_loc_values is not None:
                    values_key = "values"
                    options[values_key] = [
                        self.translate(value) for value in widget._toolbox_loc_values
                    ]
                if options:
                    configure(widget, **options)
                active_widgets.append(widget)
            except (AttributeError, tk.TclError, TypeError):
                continue
        self.widgets = active_widgets

        for window in list(self.windows):
            try:
                if window.winfo_exists():
                    window._toolbox_loc_title_setter(
                        window, self.translate(window._toolbox_loc_title))
            except (AttributeError, tk.TclError):
                continue

        log = getattr(app, "log", None)
        if log is not None:
            try:
                text = log.get("1.0", "end-1c")
                converted = self.convert_between(text, old_language, language)
                log.delete("1.0", "end")
                log.insert("1.0", converted)
            except tk.TclError:
                pass
        app.ui_language = language

    def install(self, gui):
        for class_name, text_keys, values_key in (
            ("CTkLabel", ("text",), None),
            ("CTkButton", ("text",), None),
            ("CTkCheckBox", ("text",), None),
            ("CTkRadioButton", ("text",), None),
            ("CTkEntry", (), None),
            ("CTkOptionMenu", (), "values"),
            ("CTkComboBox", (), "values"),
            ("CTkSegmentedButton", (), "values"),
        ):
            self._patch_ctk_widget(class_name, text_keys, values_key)

        for cls in (ctk.CTk, ctk.CTkToplevel):
            self._patch_window_title(cls)
        self._patch_message_boxes()
        self._patch_file_dialogs()

        app_class = gui.LocalTcpApp
        original_load = app_class._load_settings
        manager = self

        def load_settings(app):
            settings = original_load(app)
            manager.language = settings.get("language", "zh-CN")
            if manager.language not in ("zh-CN", "zh-TW"):
                manager.language = "zh-CN"
            return settings

        app_class._load_settings = load_settings
        app_class._apply_ui_language = lambda app, language: manager.switch(app, language)
        original_append_log = app_class._append_log

        def append_log(app, message, *args, **kwargs):
            return original_append_log(app, manager.translate(message), *args, **kwargs)

        app_class._append_log = append_log


_manager = _Localization()


def install(gui):
    _manager.install(gui)
