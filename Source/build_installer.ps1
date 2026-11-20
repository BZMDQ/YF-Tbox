param(
    [string]$PayloadPath,
    [string]$OutputPath,
    [string]$WorkPath,
    [switch]$OneDir=$true
)
$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$python = $env:TOOLBOX_PYTHON
if (-not $python) { $command = Get-Command python.exe -ErrorAction SilentlyContinue; if ($command) { $python = $command.Source } }
# 安装运行库使用原生 64 位，避免本机 32 位进程无法写入旧安装目录的问题。
$installerBits = & $python -c "import struct; print(struct.calcsize('P')*8)"
if ($LASTEXITCODE -ne 0 -or $installerBits -ne '64') { throw 'Build this installer with 64-bit Python (TOOLBOX_PYTHON).' }
if (-not $PayloadPath) { throw 'Specify -PayloadPath pointing to the prepared onedir payload ZIP.' }
$installerVersion = '0.8.60'
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path -Parent $source) "研发工具箱_${installerVersion}_安装程序.exe" }
$PayloadPath = [IO.Path]::GetFullPath($PayloadPath)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path -LiteralPath $PayloadPath -PathType Leaf)) { throw "Payload ZIP not found: $PayloadPath" }
if ([string]::IsNullOrWhiteSpace($WorkPath)) {
    $work = Join-Path $source 'build_installer'
} else {
    $work = [IO.Path]::GetFullPath($WorkPath)
}
$config = Join-Path $work 'pyinstaller-config'
New-Item -ItemType Directory -Path $config -Force | Out-Null
$payloadDirectory = Join-Path $work 'payload'
New-Item -ItemType Directory -Path $payloadDirectory -Force | Out-Null
$bundledPayload = Join-Path $payloadDirectory 'toolbox_payload.zip'
Copy-Item -LiteralPath $PayloadPath -Destination $bundledPayload -Force
$installerEntry = Join-Path $work 'toolbox_installer_entry.py'
$installerIcon = Join-Path $work 'research_toolbox.ico'
$installerLogo = Join-Path $work 'wslogo.png'
Copy-Item -LiteralPath (Join-Path $source '安装程序.py') -Destination $installerEntry -Force
Copy-Item -LiteralPath (Join-Path $source 'research_toolbox.ico') -Destination $installerIcon -Force
Copy-Item -LiteralPath (Join-Path $source 'wslogo.png') -Destination $installerLogo -Force
$installerName = "ResearchToolbox_${installerVersion}_Installer"
# 完整文件夹安装器不经过单文件启动器的临时目录解包，处理无法创建临时目录的问题。
$installerMode=if($OneDir){'--onedir'}else{'--onefile'}
$arguments = @('-m','PyInstaller','--noconfirm','--clean',$installerMode,'--windowed','--name',$installerName,'--distpath',(Split-Path -Parent $OutputPath),'--workpath',$work,'--specpath',$work, '--icon',$installerIcon,'--add-data',"$bundledPayload;.",'--add-data',"$installerIcon;.",'--add-data',"$installerLogo;.",'--hidden-import','tkinter.filedialog','--hidden-import','tkinter.messagebox','--hidden-import','tkinter.ttk',$installerEntry)
$previousConfig = $env:PYINSTALLER_CONFIG_DIR
$env:PYINSTALLER_CONFIG_DIR = $config
try {
    & $python @arguments
    $buildExitCode = $LASTEXITCODE
}
finally {
    if ($null -eq $previousConfig) { Remove-Item Env:PYINSTALLER_CONFIG_DIR -ErrorAction SilentlyContinue }
    else { $env:PYINSTALLER_CONFIG_DIR = $previousConfig }
}
if ($buildExitCode -ne 0) { throw "Installer build failed with code $buildExitCode" }
$built = if($OneDir){Join-Path (Join-Path (Split-Path -Parent $OutputPath) $installerName) ($installerName+'.exe')}else{Join-Path (Split-Path -Parent $OutputPath) ($installerName + '.exe')}
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { throw "Installer was not created: $built" }
Get-Item -LiteralPath $built | Select-Object FullName,Length,LastWriteTime
