; 原生安装器只安装工具箱应用文件，不捆绑或修改厂商烧录工具和用户配置。
Unicode true
RequestExecutionLevel user
!include "MUI2.nsh"
!ifndef APP_VERSION
  !error "请定义 APP_VERSION"
!endif
!ifndef PAYLOAD_DIR
  !error "请定义 PAYLOAD_DIR"
!endif
!ifndef OUTPUT_FILE
  !error "请定义 OUTPUT_FILE"
!endif
Name "研发工具箱 ${APP_VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\研发工具箱"
InstallDirRegKey HKCU "Software\CSV0\ResearchToolbox" "InstallDir"
SetCompressor /SOLID lzma
!define MUI_ICON "research_toolbox.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\ResearchToolbox_${APP_VERSION}.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "SimpChinese"

Section "工具箱应用" SEC_APP
  SetOutPath "$INSTDIR"
  SetOverwrite on
  ; 完整 onedir 运行文件与源码一起安装；已有 CubeProgrammer/驱动保持原样。
  File /r "${PAYLOAD_DIR}\*.*"
  ; 静默安装仅用于隔离目录验证，不改用户快捷方式或注册表。
  IfSilent done
  WriteRegStr HKCU "Software\CSV0\ResearchToolbox" "InstallDir" "$INSTDIR"
  CreateShortCut "$DESKTOP\研发工具箱.lnk" "$INSTDIR\ResearchToolbox_${APP_VERSION}.exe" "" "$INSTDIR\ResearchToolbox_${APP_VERSION}.exe" 0
  CreateDirectory "$SMPROGRAMS\研发工具箱"
  CreateShortCut "$SMPROGRAMS\研发工具箱\研发工具箱.lnk" "$INSTDIR\ResearchToolbox_${APP_VERSION}.exe"
  done:
SectionEnd
