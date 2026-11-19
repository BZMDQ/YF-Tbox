"""在原固件升级页选择开发板类型，复用升级列表及任务/进度框架。"""
from pathlib import Path
from tkinter import filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from d133_ota_client import upload, validate_cpio
STM32='STM32F750'
D133='D133CBS · ArtInChip'

def install(gui):
    cls=gui.LocalTcpApp
    original_build,original_choose,original_set,original_upload=(cls._build_ota_page,cls._choose_package,cls._set_package,cls._upload_ota)
    def selected(self):return getattr(self,'ota_board_var',None) is not None and self.ota_board_var.get()==D133
    def change(self,value):
        self.ota_board_var.set(value)
        # 切换开发板即清除包，防止把上一个平台的包带入新平台任务。
        self.package_path=None;self.package_version=None;self.package_var.set('请选择 '+('ota.cpio' if selected(self) else '系统 OTA 升级包'))
        if selected(self):
            if self.ota_selection_note:self.ota_selection_note.pack_forget()
            self.d133_ota_note.pack(fill='x',padx=18,pady=(0,12),before=self.progress)
        else:
            self.d133_ota_note.pack_forget()
            if self.ota_selection_note:self.ota_selection_note.pack(fill='x',padx=18,pady=(0,12),before=self.progress)
        self.package_hint_var.set('D133CBS：CPIO + 同名 .sig；端口 5000；开发板屏幕确认' if selected(self) else 'STM32F750 系统 OTA')
        self.browse_button.configure(text='选择 CPIO…' if selected(self) else '选择系统 OTA…')
        self.d133_port_entry.configure(state='normal' if selected(self) else 'disabled')
        # BOOT为F750单份内部Flash协议，D133模式必须禁用入口并在动作前再次拒绝。
        self._refresh_boot_controls()
    def build(self):
        original_build(self)
        box=self.ota_file_box;card=box.master
        row=gui.ctk.CTkFrame(card,fg_color='transparent');row.pack(fill='x',padx=18,pady=(5,10),before=box)
        self.ota_board_var=gui.tk.StringVar(master=self.root,value=STM32)
        gui.ctk.CTkLabel(row,textvariable=self.ota_board_var,font=self._font(14,'bold')).pack(side='left')
        section=self._action_section('ota')
        first=section.pack_slaves()[0]
        # 先选平台，随后选择设备与相应格式的升级包。
        self._rail_label('ota', '升级平台').pack_configure(before=first)
        self.ota_board_selector=self._register_action(gui.ctk.CTkComboBox(section,variable=self.ota_board_var,values=[STM32,D133],state='readonly',width=0,height=36,command=lambda value:change(self,value)))
        self.ota_board_selector.pack(fill='x',padx=4,pady=(0,6),before=first)
        gui.ctk.CTkLabel(row,text='D133 TCP 端口').pack(side='left',padx=(15,6))
        self.d133_port_var=gui.tk.StringVar(master=self.root,value='5000')
        self.d133_port_entry=self._register_action(gui.ctk.CTkEntry(row,textvariable=self.d133_port_var,width=80,state='disabled'));self.d133_port_entry.pack(side='left')
        labels=[w for w in card.winfo_children() if isinstance(w,gui.ctk.CTkLabel)]
        self.ota_selection_note=labels[-1] if labels else None
        self.d133_ota_note=self._flow_label(card,text='系统信息与 OTA 共用 TCP 5000；升级需要 RSA 签名及开发板触屏确认。',font=self._font(9),text_color=gui.COLORS['muted'],anchor='w')
        self.d133_ota_note.pack_forget()
        change(self,self.ota_board_var.get())
    def set_package(self,path):
        if not selected(self):return original_set(self,path)
        path=Path(path).resolve()
        if path.suffix.lower()!='.cpio':raise ValueError('D133CBS 请选择 ota.cpio')
        data=path.read_bytes();version=validate_cpio(data)
        signature=Path(str(path)+'.sig')
        if not signature.is_file() or not 1<=signature.stat().st_size<=512:raise ValueError('缺少同名 RSA 签名文件 '+signature.name)
        self.package_path=path;self.package_version=version;self.package_var.set(path.name)
        self.package_hint_var.set(f'D133CBS | 版本 {version} | {len(data):,} 字节 | CPIO 校验通过 | RSA 由开发板验证')
    def choose(self):
        if not selected(self):return original_choose(self)
        path=filedialog.askopenfilename(parent=self.root,title='选择 D133CBS ArtInChip OTA 包',filetypes=[('ArtInChip CPIO','*.cpio')])
        if path:
            try:set_package(self,path);self._append_log('已选择 D133CBS 包：'+path)
            except Exception as exc:messagebox.showerror('升级包无效',str(exc),parent=self.root)
    def upload_ota(self):
        if not selected(self):return original_upload(self)
        if self.is_running:return
        try:
            if not self.package_path:raise ValueError('请先选择 D133CBS ota.cpio')
            set_package(self,self.package_path)
            if not self.ota_hosts_input.get('1.0','end-1c').strip():raise ValueError('请在升级列表添加 D133CBS 开发板 IP')
            hosts=self._ota_target_hosts();port=int(self.d133_port_var.get())
            if not 1<=port<=65535:raise ValueError('TCP 端口无效')
        except Exception as exc:messagebox.showerror('无法升级',str(exc),parent=self.root);return
        if not messagebox.askyesno('确认 D133CBS 升级',f'向升级列表中 {len(hosts)} 台 D133CBS 推送版本 {self.package_version}？\n每台开发板都需要在屏幕确认。',parent=self.root):return
        path=self.package_path;self._reset_ota_target_rows(hosts);self.ota_batch_running=True
        def action(_args,_key,stop_event):
            def target(host):
                self._post('ota_target_status',(host,'正在连接 D133CBS'))
                try:
                    def progress(percent,text):
                        self._post('ota_target_progress',(host,percent,100));self._post('ota_target_status',(host,text))
                        if text.startswith('设备消息：'):self._post('log',f'[{host}] {text}')
                    upload(host,port,path,progress,stop_event)
                    self._post('ota_target_status',(host,'升级完成 | 新系统健康已确认'))
                    self._post('log',f'[{host}] D133CBS 新版本、启动槽位和健康确认均已核对。')
                    return True
                except Exception as exc:
                    self._post('ota_target_status',(host,'升级未完成'));self._post('log',f'[{host}] D133CBS：{exc}');return False
            with ThreadPoolExecutor(max_workers=min(len(hosts),8),thread_name_prefix='D133-OTA') as pool:
                results=list(pool.map(target,hosts))
            self._post('ota_batch_status',f'D133CBS 健康确认成功 {sum(results)}/{len(results)} 台')
        self._start_task('D133CBS TCP OTA',action,require_connection=False)
    cls._select_ota_board=change
    cls._build_ota_page=build;cls._choose_package=choose;cls._set_package=set_package;cls._upload_ota=upload_ota






