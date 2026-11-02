param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][int]$ParentPid,
    [Parameter(Mandatory=$true)][string]$ExeName
)

$ErrorActionPreference = 'Stop'

try {
    # 等待工具箱退出，避免覆盖仍在使用的 EXE 与 Python 运行库。
    while (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue) {
        Start-Sleep -Milliseconds 300
    }

    $archivePath = [IO.Path]::GetFullPath($Archive)
    $targetPath = [IO.Path]::GetFullPath($Target)
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw '已下载的更新包不存在。'
    }
    if (-not (Test-Path -LiteralPath $targetPath -PathType Container)) {
        throw '找不到当前工具箱安装目录。'
    }

    $stage = Join-Path ([IO.Path]::GetTempPath()) ('YF-Tbox-Update-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # 在解压前逐项规范化路径，禁止 ZIP 条目越过暂存目录。
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $stageRoot = [IO.Path]::GetFullPath($stage).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        foreach ($entry in $zip.Entries) {
            $relative = $entry.FullName.Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains(':')) {
                throw '更新包含有无效文件路径。'
            }
            $resolved = [IO.Path]::GetFullPath((Join-Path $stageRoot $relative))
            if (-not $resolved.StartsWith($stageRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw '更新包路径超出暂存目录。'
            }
        }
    } finally {
        $zip.Dispose()
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $stage)

    # 只接受包含本版本主程序的顶层目录，避免把任意 ZIP 路径写入安装目录。
    $candidate = Get-ChildItem -LiteralPath $stage | Where-Object { $_.PSIsContainer } | Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName $ExeName) -PathType Leaf
    } | Select-Object -First 1
    if (-not $candidate) {
        throw '更新包目录结构无效，未找到新版本主程序。'
    }

    # 覆盖应用文件，保留安装目录中的 Key、设备配置和用户数据。
    Get-ChildItem -LiteralPath $candidate.FullName -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $targetPath -Recurse -Force
    }
    if (-not (Test-Path -LiteralPath (Join-Path $targetPath $ExeName) -PathType Leaf)) {
        throw '更新后的主程序未写入安装目录。'
    }

    # 删除旧版主 EXE，避免开始菜单或用户误启动到旧版本。
    Get-ChildItem -LiteralPath $targetPath -Filter 'ResearchToolbox_*.exe' |
        Where-Object { $_.Name -ne $ExeName } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Start-Process -FilePath (Join-Path $targetPath $ExeName) -WorkingDirectory $targetPath
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
} catch {
    $logPath = Join-Path ([IO.Path]::GetTempPath()) 'YF-Tbox-update-error.log'
    [IO.File]::WriteAllText($logPath, $_.Exception.ToString(), [Text.Encoding]::UTF8)
    exit 1
}
