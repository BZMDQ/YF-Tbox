param(
    [string]$PayloadPath,
    [string]$OutputPath,
    [string]$WorkPath
)
$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$guiSource = Get-Content -LiteralPath (Join-Path $source 'local_tcp_gui.py') -Raw -Encoding UTF8
$versionMatch = [regex]::Match($guiSource, "(?m)^APP_VERSION\s*=\s*'([^']+)'\s*$")
if (-not $versionMatch.Success) { throw 'Could not read APP_VERSION from local_tcp_gui.py' }
$version = $versionMatch.Groups[1].Value
$installerName = "研发工具箱_${version}_安装程序"
$python = $env:TOOLBOX_PYTHON
if (-not $python) { $command = Get-Command python.exe -ErrorAction SilentlyContinue; if ($command) { $python = $command.Source } }
if (-not $PayloadPath) { throw 'Specify -PayloadPath pointing to the prepared onedir payload ZIP.' }
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path -Parent $source) ($installerName + '.exe') }
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
$installerCode = Get-Content -LiteralPath $installerEntry -Raw -Encoding UTF8
$installerCode = [regex]::Replace($installerCode, "(?m)^APP_VERSION\s*=\s*'[^']+'\s*$",
    "APP_VERSION = '$version'")
Set-Content -LiteralPath $installerEntry -Value $installerCode -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $source 'research_toolbox.ico') -Destination $installerIcon -Force
Copy-Item -LiteralPath (Join-Path $source 'wslogo.png') -Destination $installerLogo -Force
$arguments = @('-m','PyInstaller','--noconfirm','--clean','--onefile','--windowed','--name',$installerName,'--distpath',(Split-Path -Parent $OutputPath),'--workpath',$work,'--specpath',$work, '--icon',$installerIcon,'--add-data',"$bundledPayload;.",'--add-data',"$installerIcon;.",'--add-data',"$installerLogo;.",'--hidden-import','tkinter.filedialog','--hidden-import','tkinter.messagebox','--hidden-import','tkinter.ttk',$installerEntry)
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
$built = Join-Path (Split-Path -Parent $OutputPath) ($installerName + '.exe')
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { throw "Installer was not created: $built" }
Get-Item -LiteralPath $built | Select-Object FullName,Length,LastWriteTime
