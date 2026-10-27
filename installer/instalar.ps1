<#
.SYNOPSIS
  Instala, atualiza ou desinstala o AEGN Security neste computador.

.DESCRIPTION
  Sistema de segurança dos computadores da Escola AEGN.

  - Pede permissões de administrador (UAC) se for preciso.
  - Instalação nova: define a senha de administração do AEGN (Enter = "admin").
  - Atualização ou desinstalação: pede a senha atual.
  - Instala o MSI que está na mesma pasta: o aegn.exe fica em
    C:\Program Files\AEGN e o comando "aegn" fica no PATH do sistema.

.PARAMETER Desinstalar
  Desinstala o AEGN Security (pergunta se deve reverter as proteções antes).

.PARAMETER Msi
  Caminho do MSI. Por defeito, o AEGN-Security-*.msi mais recente desta pasta.

.PARAMETER SemPausa
  Não espera por Enter no fim (para uso em scripts).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\instalar.ps1
#>
param(
    [switch]$Desinstalar,
    [string]$Msi,
    [switch]$SemPausa
)

$ErrorActionPreference = 'Stop'
$Pasta = Join-Path $env:ProgramFiles 'AEGN'
$Exe = Join-Path $Pasta 'aegn.exe'

function Escrever([string]$Texto, [string]$Cor = 'Gray') { Write-Host $Texto -ForegroundColor $Cor }

function Terminar([int]$Codigo) {
    Remove-Item Env:AEGN_SENHA, Env:AEGN_SENHA_NOVA -ErrorAction SilentlyContinue
    if (-not $SemPausa) { [void](Read-Host 'Prima Enter para fechar') }
    exit $Codigo
}

function Ler-Senha([string]$Pergunta) {
    $seguro = Read-Host $Pergunta -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($seguro)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# Pede a senha atual (3 tentativas) e valida-a com o aegn.exe instalado.
function Confirmar-Senha {
    for ($i = 1; $i -le 3; $i++) {
        $env:AEGN_SENHA = Ler-Senha 'Senha atual do AEGN'
        # Com 'Stop', o PowerShell 5.1 converte o stderr redirigido em exceção.
        $ErrorActionPreference = 'Continue'
        & $Exe senha verificar 2>$null | Out-Null
        $correta = $LASTEXITCODE -eq 0
        $ErrorActionPreference = 'Stop'
        if ($correta) { return }
        Escrever 'Senha incorreta.' Red
    }
    Escrever 'Operação cancelada: senha incorreta.' Red
    Terminar 1
}

function Executar-Msi([string]$Argumentos, [string]$Registo) {
    $p = Start-Process msiexec.exe -ArgumentList "$Argumentos /qn /norestart /l*v `"$Registo`"" -Wait -PassThru
    # 3010 = concluído, falta reiniciar.
    if ($p.ExitCode -notin 0, 3010) {
        Escrever "O msiexec terminou com o código $($p.ExitCode). Registo: $Registo" Red
        Terminar 1
    }
    if ($p.ExitCode -eq 3010) { Escrever '[aviso] Reinicie o computador para concluir.' Yellow }
}

# --- Administrador -------------------------------------------------------
$identidade = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identidade.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Escrever 'A pedir permissões de administrador...' Yellow
    $argumentos = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Desinstalar) { $argumentos += '-Desinstalar' }
    if ($Msi) { $argumentos += @('-Msi', "`"$Msi`"") }
    if ($SemPausa) { $argumentos += '-SemPausa' }
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $argumentos }
    catch { Escrever 'É necessário aceitar o pedido de administrador para continuar.' Red; exit 1 }
    exit 0
}

Escrever ''
Escrever '  AEGN Security - Escola AEGN' Cyan
Escrever '  Sistema de segurança dos computadores' DarkGray
Escrever ''

# --- Desinstalar ---------------------------------------------------------
if ($Desinstalar) {
    if (-not (Test-Path $Exe)) { Escrever 'O AEGN Security não está instalado.' Yellow; Terminar 0 }
    Confirmar-Senha
    $r = Read-Host 'Reverter também as proteções aplicadas (AppLocker, firewall, tarefa)? [S/n]'
    if ($r -notmatch '^[nN]') {
        & $Exe reverter --aplicar
        if ($LASTEXITCODE -ne 0) { Escrever '[aviso] A reversão falhou; continua-se com a desinstalação.' Yellow }
    }
    $chaves = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $produto = Get-ItemProperty $chaves -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'AEGN Security' } | Select-Object -First 1
    if (-not $produto) { Escrever 'Não foi encontrado o produto AEGN Security no Windows Installer.' Red; Terminar 1 }
    Escrever 'A desinstalar...'
    Executar-Msi "/x $($produto.PSChildName)" (Join-Path $env:TEMP 'aegn-desinstalar.log')
    Escrever '[ok] AEGN Security desinstalado.' Green
    Terminar 0
}

# --- Instalar ou atualizar -----------------------------------------------
if (-not $Msi) {
    $Msi = Get-ChildItem -Path $PSScriptRoot -Filter 'AEGN-Security-*.msi' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Msi -or -not (Test-Path $Msi)) {
    Escrever "Não foi encontrado o instalador AEGN-Security-*.msi em $PSScriptRoot." Red
    Terminar 1
}

$atualizacao = Test-Path $Exe
if ($atualizacao) {
    Escrever "O AEGN Security já está instalado: vai ser atualizado com $(Split-Path $Msi -Leaf)."
    Confirmar-Senha
    $novaSenha = $null
} else {
    Escrever 'Defina a senha de administração do AEGN.'
    Escrever 'Vai ser pedida para tudo o que altere o computador. Enter = "admin".' DarkGray
    while ($true) {
        $novaSenha = Ler-Senha 'Nova senha'
        if (-not $novaSenha) { $novaSenha = 'admin'; break }
        if ($novaSenha.Length -lt 4) { Escrever 'A senha tem de ter pelo menos 4 caracteres.' Red; continue }
        if ((Ler-Senha 'Repita a senha') -eq $novaSenha) { break }
        Escrever 'As senhas não coincidem.' Red
    }
}

Escrever 'A instalar...'
Executar-Msi "/i `"$Msi`"" (Join-Path $env:TEMP 'aegn-instalar.log')

# O PATH novo só chega às consolas que se abram a partir de agora; atualiza-se nesta.
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path', 'User')

if ($novaSenha -and $novaSenha -ne 'admin') {
    $env:AEGN_SENHA = 'admin'
    $env:AEGN_SENHA_NOVA = $novaSenha
    & $Exe senha alterar
    if ($LASTEXITCODE -ne 0) { Escrever '[aviso] Não foi possível definir a senha; use: aegn senha alterar' Yellow }
}

Escrever ''
Escrever "[ok] $(& $Exe --version) instalado em $Pasta" Green
& $Exe senha estado
Escrever ''
Escrever 'Próximos passos (numa consola de administrador nova):' Cyan
Escrever '  aegn                                   menu interativo'
Escrever '  aegn executar --so-auditoria --aplicar AppLocker só regista, não bloqueia'
Escrever '  aegn politica eventos                  rever o que seria bloqueado'
Escrever '  aegn executar --aplicar                ativar o bloqueio'
Escrever '  aegn tarefa instalar --aplicar         reaplicar todos os dias'
Terminar 0
