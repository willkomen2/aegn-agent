<#
.SYNOPSIS
  Atualização automática do AEGN Security a partir dos releases do GitHub.

.DESCRIPTION
  O MSI instala este script em C:\Program Files\AEGN e regista a tarefa
  AEGN-Atualizar, que o executa como SYSTEM 5 minutos depois do arranque e
  todos os dias por volta das 13:00. Como corre como SYSTEM, a atualização não
  pede UAC nem a senha do AEGN.

  Em cada execução:
    1. descarrega o SHA256SUMS.txt do último release;
    2. se houver um MSI com versão mais recente do que a instalada, descarrega-o
       para C:\Program Files\AEGN\atualizacao (só os administradores escrevem lá);
    3. confirma o SHA-256 e instala-o em silêncio com o msiexec.
  O registo fica em C:\Program Files\AEGN\logs\atualizacao.log.

  Qualquer utilizador pode pedir uma atualização imediata com
  "aegn atualizar --aplicar": isso só lança a tarefa, que instala sempre o
  release oficial do repositório.

.PARAMETER Registar
  Regista (ou atualiza) a tarefa AEGN-Atualizar. O MSI chama-o ao instalar.
#>
param([switch]$Registar)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'willkomen2/aegn-agent'
$Tarefa = 'AEGN-Atualizar'
$Pasta = Split-Path -Parent $PSCommandPath
$Exe = Join-Path $Pasta 'aegn.exe'
$Registo = Join-Path $Pasta 'logs\atualizacao.log'

# --- Registar a tarefa ---------------------------------------------------
if ($Registar) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $acao = New-ScheduledTaskAction -Execute $ps `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $arranque = New-ScheduledTaskTrigger -AtStartup
    $arranque.Delay = 'PT5M'
    # O atraso aleatório evita que uma sala inteira descarregue ao mesmo tempo.
    $diaria = New-ScheduledTaskTrigger -Daily -At '13:00' -RandomDelay (New-TimeSpan -Minutes 60)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $definicoes = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $Tarefa -Action $acao -Trigger $arranque, $diaria `
        -Principal $principal -Settings $definicoes -Force | Out-Null

    # Os utilizadores autenticados podem ler e lançar a tarefa (não alterá-la),
    # para que "aegn atualizar --aplicar" funcione sem administrador.
    try {
        $servico = New-Object -ComObject Schedule.Service
        $servico.Connect()
        $t = $servico.GetFolder('\').GetTask($Tarefa)
        $sd = $t.GetSecurityDescriptor(4)   # 4 = DACL
        if ($sd -notmatch '\(A;;GRGX;;;AU\)') { $t.SetSecurityDescriptor($sd + '(A;;GRGX;;;AU)', 0) }
    } catch {
        Write-Output "[aviso] Não foi possível abrir a tarefa aos utilizadores: $_"
    }
    Write-Output "Tarefa $Tarefa registada."
    exit 0
}

# --- Atualizar -----------------------------------------------------------
function Anotar([string]$Texto) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Registo) | Out-Null
    '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Texto | Add-Content -Path $Registo -Encoding UTF8
    Write-Output $Texto
}

try {
    # O PowerShell 5.1 pode não ter o TLS 1.2 ativo, e o GitHub exige-o.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $web = New-Object Net.WebClient
    $web.Headers.Add('User-Agent', 'aegn-atualizar')
    $base = "https://github.com/$Repo/releases"

    # Os links /latest/download/ não contam para o limite de pedidos da API.
    $somas = $web.DownloadString("$base/latest/download/SHA256SUMS.txt")
    $linha = [regex]::Match($somas, '(?m)^([0-9a-fA-F]{64})\s+(AEGN-Security-(\d+\.\d+\.\d+)-x64\.msi)\s*$')
    if (-not $linha.Success) { throw 'o SHA256SUMS.txt do último release não indica nenhum MSI.' }
    $hash = $linha.Groups[1].Value.ToLower()
    $nomeMsi = $linha.Groups[2].Value
    $nova = [version]$linha.Groups[3].Value

    $atual = $null
    if (Test-Path $Exe) {
        $saida = (& $Exe --version) -join ' '
        if ($saida -match '(\d+\.\d+\.\d+)') { $atual = [version]$Matches[1] }
    }
    if ($atual -and $nova -le $atual) {
        Anotar "Sem atualizações: instalada a $atual, último release $nova."
        exit 0
    }

    Anotar "A atualizar de $atual para $nova..."
    $dir = Join-Path $Pasta 'atualizacao'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $msi = Join-Path $dir $nomeMsi
    $web.DownloadFile("$base/download/v$nova/$nomeMsi", $msi)

    $obtido = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
    if ($obtido -ne $hash) {
        Remove-Item $msi -Force
        throw "o SHA-256 do $nomeMsi não coincide (esperado $hash, obtido $obtido)."
    }

    $logMsi = Join-Path (Split-Path $Registo) 'atualizacao-msi.log'
    $p = Start-Process msiexec.exe -Wait -PassThru `
        -ArgumentList "/i `"$msi`" /qn /norestart /l*v `"$logMsi`""
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
    switch ($p.ExitCode) {
        0 { Anotar "[ok] Atualizado para a versão $nova." }
        3010 { Anotar "[ok] Atualizado para a versão $nova (falta reiniciar)." }
        1618 { throw 'já está outra instalação em curso; tenta-se na próxima execução.' }
        default { throw "o msiexec terminou com o código $($p.ExitCode). Registo: $logMsi" }
    }
    exit 0
} catch {
    Anotar "[erro] Atualização falhou: $($_.Exception.Message)"
    exit 1
}
