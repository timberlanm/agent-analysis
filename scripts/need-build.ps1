# 判断前端是否需要重新构建。
#   exit 1 = 需要构建（dist 缺失，或 frontend\src 里有文件比 dist 新）
#   exit 0 = 无需构建
# 说明：抽成独立脚本，避免在 start.bat 里内联 PowerShell（含引号/管道）在不同环境被 cmd 误解析。
try {
    $distIndex = 'frontend\dist\index.html'
    if (-not (Test-Path $distIndex)) { exit 1 }
    $distTime = (Get-Item $distIndex).LastWriteTimeUtc
    $srcMax = (Get-ChildItem -Recurse -File 'frontend\src' -ErrorAction SilentlyContinue |
               Measure-Object -Property LastWriteTimeUtc -Maximum).Maximum
    if ($null -eq $srcMax -or $srcMax -gt $distTime) { exit 1 } else { exit 0 }
} catch {
    exit 1
}
