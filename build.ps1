param(
    [string]$OutputPath,
    [switch]$OneDir,
    [string]$WorkPath
)

$ErrorActionPreference = 'Stop'

$source = $PSScriptRoot
$root = Split-Path -Parent $source
$python = $env:TOOLBOX_PYTHON
if(!$python){$candidate=Get-Command python.exe -ErrorAction SilentlyContinue;if($candidate){$python=$candidate.Source}}
if ([string]::IsNullOrWhiteSpace($WorkPath)) {
    $work = Join-Path $source 'build'
} else {
    $work = [IO.Path]::GetFullPath($WorkPath)
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root '研发工具箱_0.8.35.exe'
}
$output = [IO.Path]::GetFullPath($OutputPath)
$dist = Split-Path -Parent $output
$appName = [IO.Path]::GetFileNameWithoutExtension($output)
$mode = if ($OneDir) { '--onedir' } else { '--onefile' }
$expectedOutput = if ($OneDir) {
    Join-Path (Join-Path $dist $appName) "$appName.exe"
} else {
    $output
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Python 3.8 x86 build environment was not found: $python"
}
if (Test-Path -LiteralPath $expectedOutput) {
    throw "Refusing to overwrite an existing build output: $expectedOutput"
}
if (-not (Test-Path -LiteralPath $dist -PathType Container)) {
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $work -PathType Container)) {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
}
$syntaxCheck = Join-Path $work 'syntax'
New-Item -ItemType Directory -Path $syntaxCheck -Force | Out-Null
$pyinstallerConfig = Join-Path $work 'pyinstaller-config'
New-Item -ItemType Directory -Path $pyinstallerConfig -Force | Out-Null

& $python -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True); py_compile.compile(sys.argv[3], cfile=sys.argv[4], doraise=True); py_compile.compile(sys.argv[5], cfile=sys.argv[6], doraise=True); py_compile.compile(sys.argv[7], cfile=sys.argv[8], doraise=True); py_compile.compile(sys.argv[9], cfile=sys.argv[10], doraise=True); py_compile.compile(sys.argv[11], cfile=sys.argv[12], doraise=True); py_compile.compile(sys.argv[13], cfile=sys.argv[14], doraise=True)" `
    (Join-Path $source 'local_tcp_gui.py') `
    (Join-Path $syntaxCheck 'local_tcp_gui_orig.pyc') `
    (Join-Path $source 'local_tcp_client.py') `
    (Join-Path $syntaxCheck 'local_tcp_client.pyc') `
    (Join-Path $source 'localization.py') `
    (Join-Path $syntaxCheck 'localization.pyc') `
    (Join-Path $source 'patch_toolbox.py') `
    (Join-Path $syntaxCheck 'patch_toolbox.pyc') `
    (Join-Path $source 'd133_ota_client.py') `
    (Join-Path $syntaxCheck 'd133_ota_client.pyc') `
    (Join-Path $source 'd133_ota_ui.py') `
    (Join-Path $syntaxCheck 'd133_ota_ui.pyc') `
    (Join-Path $source 'github_updater.py') `
    (Join-Path $syntaxCheck 'github_updater.pyc')
if ($LASTEXITCODE -ne 0) {
    throw "Could not compile the packaged GUI and OTA client modules (exit code $LASTEXITCODE)"
}

$arguments = @(
    '-m', 'PyInstaller',
    '--noconfirm',
    $mode,
    '--windowed',
    '--name', $appName,
    '--icon', (Join-Path $source 'research_toolbox.ico'),
    '--distpath', $dist,
    '--workpath', $work,
    '--specpath', $work,
    '--paths', $source,
    '--hidden-import', 'argparse',
    '--hidden-import', 'pic24_hex',
    '--hidden-import', 'd133_ota_ui',
    '--hidden-import', 'd133_ota_client',
    '--hidden-import', 'github_updater',
    '--hidden-import', 'base64',
    '--hidden-import', 'contextlib',
    '--hidden-import', 'concurrent.futures',
    '--hidden-import', 'ctypes',
    '--hidden-import', 'hashlib',
    '--hidden-import', 'http.client',
    '--hidden-import', 'ipaddress',
    '--hidden-import', 'json',
    '--hidden-import', 'os',
    '--hidden-import', 'pathlib',
    '--hidden-import', 'queue',
    '--hidden-import', 're',
    '--hidden-import', 'shutil',
    '--hidden-import', 'socket',
    '--hidden-import', 'encodings.idna',
    '--hidden-import', 'stringprep',
    '--hidden-import', 'struct',
    '--hidden-import', 'subprocess',
    '--hidden-import', 'sys',
    '--hidden-import', 'tempfile',
    '--hidden-import', 'threading',
    '--hidden-import', 'time',
    '--hidden-import', 'types',
    '--hidden-import', 'urllib.parse',
    '--hidden-import', 'urllib.request',
    '--hidden-import', 'urllib.error',
    '--hidden-import', 'uuid',
    '--hidden-import', 'ssl',
    '--hidden-import', 'zlib',
    '--collect-all', 'opencc',
    '--hidden-import', 'tkinter',
    '--hidden-import', 'tkinter.filedialog',
    '--hidden-import', 'tkinter.messagebox',
    '--hidden-import', 'tkinter.font',
    '--hidden-import', 'customtkinter',
    '--collect-all', 'customtkinter',
    '--hidden-import', 'PIL.Image',
    '--hidden-import', 'PIL.ImageOps',
    '--collect-all', 'PIL',
    '--add-data', "$source\research_toolbox.ico;.",
    '--add-data', "$source\wslogo.png;.",
    '--add-data', "$syntaxCheck\local_tcp_gui_orig.pyc;.",
    '--add-data', "$syntaxCheck\local_tcp_client.pyc;.",
    '--add-data', "$syntaxCheck\d133_ota_client.pyc;.",
    '--add-data', "$syntaxCheck\d133_ota_ui.pyc;.",
    '--add-data', "$source\toolbox_update_install.ps1;.",
    (Join-Path $source 'launcher.py')
)

$previousPyInstallerConfig = $env:PYINSTALLER_CONFIG_DIR
$env:PYINSTALLER_CONFIG_DIR = $pyinstallerConfig
try {
    & $python @arguments
    $pyinstallerExitCode = $LASTEXITCODE
}
finally {
    if ($null -eq $previousPyInstallerConfig) {
        Remove-Item Env:PYINSTALLER_CONFIG_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:PYINSTALLER_CONFIG_DIR = $previousPyInstallerConfig
    }
}
if ($pyinstallerExitCode -ne 0) {
    throw "PyInstaller exited with code $pyinstallerExitCode"
}

if (-not (Test-Path -LiteralPath $expectedOutput -PathType Leaf)) {
    throw "PyInstaller completed without creating the expected executable: $expectedOutput"
}

Get-Item -LiteralPath $expectedOutput | Select-Object FullName, Length, LastWriteTime




