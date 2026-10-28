# Atualiza o AEGN Security para o ultimo release do GitHub. Uso, num
# PowerShell de administrador:
#   irm https://raw.githubusercontent.com/willkomen2/aegn-agent/main/u.ps1 | iex
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Abra o PowerShell como administrador.' -ForegroundColor Red
    return
}
# Resgate imediato, antes de descarregar nada: desbloqueia o computador
# mesmo que a instalacao falhe.
$ErrorActionPreference = 'Continue'
Write-Host 'A desbloquear (AppLocker, firewall, tarefa, perfis)...'
$x = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
$d = Join-Path $env:ProgramData 'AEGN'
New-Item -ItemType Directory -Force -Path $d | Out-Null
try { Get-AppLockerPolicy -Local -Xml | Set-Content (Join-Path $d ('applocker-copia-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml')) } catch { }
$v = Join-Path $env:TEMP 'aegn-vazio.xml'
Set-Content $v $x
# AppIDSvc tem de estar a correr enquanto se aplica a politica vazia; se parar
# antes, o driver continua a aplicar a cache (System32\AppLocker) e o menu
# Iniciar continua bloqueado.
& sc.exe start AppIDSvc | Out-Null
try { Set-AppLockerPolicy -XmlPolicy $v -ErrorAction Stop; Write-Host '[ok] AppLocker vazio' -ForegroundColor Green } catch { Write-Host "[erro] AppLocker: $_" -ForegroundColor Red }
Start-Sleep -Seconds 10
Get-ChildItem (Join-Path $env:SystemRoot 'System32\AppLocker') -Filter '*.AppLocker' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
& sc.exe config AppIDSvc start= demand | Out-Null
& sc.exe stop AppIDSvc | Out-Null
Get-Process -Name StartMenuExperienceHost, ShellExperienceHost, SearchHost, SearchApp, TextInputHost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-NetFirewallRule -Group 'AEGN-RemoteAccess' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'AEGN-Agent' -Confirm:$false -ErrorAction SilentlyContinue
[gc]::Collect()
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -like 'AEGN_*' } | ForEach-Object { & reg.exe unload "HKU\$($_.PSChildName)" 2>&1 | Out-Null }
$ErrorActionPreference = 'Stop'

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
