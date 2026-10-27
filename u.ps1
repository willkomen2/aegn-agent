# Atualiza o AEGN Security para o ultimo release do GitHub. Uso, num
# PowerShell de administrador:
#   irm https://raw.githubusercontent.com/willkomen2/aegn-agent/main/u.ps1 | iex
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Abra o PowerShell como administrador.' -ForegroundColor Red
    return
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$u = 'https://github.com/willkomen2/aegn-agent/releases/latest/download/'
$w = New-Object Net.WebClient
$l = [regex]::Match($w.DownloadString($u + 'SHA256SUMS.txt'), '([0-9a-fA-F]{64})\s+(AEGN-Security-[0-9.]+-x64\.msi)')
$f = Join-Path $env:TEMP $l.Groups[2].Value
Write-Host "A descarregar $($l.Groups[2].Value)..."
$w.DownloadFile($u + $l.Groups[2].Value, $f)
if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $l.Groups[1].Value) { throw 'O SHA-256 do MSI nao coincide.' }
Write-Host 'A instalar...'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$f`" /qn /norestart"
if ($p.ExitCode -in 0, 3010) {
    Write-Host ('[ok] ' + (& 'C:\Program Files\AEGN\aegn.exe' --version) + '. Reinicie o computador.') -ForegroundColor Green
} else {
    Write-Host "[erro] O msiexec terminou com o codigo $($p.ExitCode)." -ForegroundColor Red
}
