//! Energia: repone los botones Encerrar y Reiniciar que alguien quito.
//!
//! Se pueden ocultar de varias formas y se deshacen todas (todo REG_DWORD):
//! - `NoClose` / `HidePowerOptions` en `...\CurrentVersion\Policies\Explorer`,
//!   en HKLM y en cada perfil con sesion abierta (y `.DEFAULT`, la pantalla de
//!   inicio de sesion). Nunca se carga el NTUSER.DAT de los demas (congelaba el
//!   inicio de sesion, ver audit.rs); se arreglan al abrir sesion porque la
//!   tarea AEGN-Atualizar lo vuelve a ejecutar.
//! - `ShowSleepOption`, `ShowHibernateOption` = 0 (directiva y Panel de control).
//! - `shutdownwithoutlogon` = 0: sin boton de energia en el inicio de sesion.
//! - Directivas MDM `HidePowerButton`, `HideShutDown`... de PolicyManager.
//! - Las mismas entradas en los `Registry.pol` de la directiva de grupo local
//!   (gpedit): si no se quitan de ahi, el Windows las vuelve a escribir en cada
//!   actualizacion de directivas. Se guarda copia del fichero antes de tocarlo.
//! - El derecho "Encerrar o sistema" (SeShutdownPrivilege): se vuelven a anadir
//!   Administradores, Utilizadores y Operadores de copia de seguranca.
//!
//! Una GPO de dominio o Intune ganan a todo esto: se avisa, no se toca.

use anyhow::Result;

/// Script de PowerShell. Es `$apply` = false en simulacion: solo informa.
const SCRIPT: &str = r#"$ErrorActionPreference = 'Continue'
$script:n = 0
$pasta = Join-Path $env:ProgramData 'AEGN'
New-Item -ItemType Directory -Force -Path $pasta | Out-Null

function Apagar($chave, $nomes) {
  if (-not (Test-Path -LiteralPath $chave)) { return }
  $p = Get-ItemProperty -LiteralPath $chave -ErrorAction SilentlyContinue
  foreach ($v in $nomes) {
    if ($p -and $null -ne $p.$v) {
      $script:n++
      Write-Output "  [corrigir] $v em $chave"
      if ($apply) { Remove-ItemProperty -LiteralPath $chave -Name $v -Force }
    }
  }
}

# 1. Valores de Explorer en HKLM y en cada perfil abierto (.DEFAULT incluido).
$explorer = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$ocultar = 'NoClose', 'HidePowerOptions'
$menu = 'ShowSleepOption', 'ShowHibernateOption'
Apagar "HKLM:\$explorer" $ocultar
Apagar 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' $menu
Apagar 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' $menu
foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' })) {
  Apagar ('Registry::HKEY_USERS\' + $h.PSChildName + '\' + $explorer) $ocultar
}

# 2. Boton de energia en el inicio de sesion (en los clientes viene a 1).
$sistema = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ((Get-ItemProperty -LiteralPath $sistema -ErrorAction SilentlyContinue).shutdownwithoutlogon -eq 0) {
  $script:n++
  Write-Output '  [corrigir] shutdownwithoutlogon = 0'
  if ($apply) { Set-ItemProperty -LiteralPath $sistema -Name shutdownwithoutlogon -Value 1 -Type DWord }
}

# 3. Directivas MDM de Start (efectiva y la copia de cada proveedor).
$mdm = 'HidePowerButton', 'HideShutDown', 'HideRestart', 'HideSleep', 'HideHibernate'
$mdm = $mdm + ($mdm | ForEach-Object { $_ + '_ProviderSet' })
Apagar 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start' $mdm
foreach ($pr in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers' -ErrorAction SilentlyContinue)) {
  Apagar (Join-Path $pr.PSPath 'default\Device\Start') $mdm
}

# 4. Registry.pol de la directiva local. Formato: 'PReg', version y entradas
# [clave;valor;tipo;tamano;datos] en UTF-16. Se copian todas menos las que
# ocultan la energia; las "**del.X" se dejan.
function Limpar-Pol($ficheiro) {
  try {
    $b = [IO.File]::ReadAllBytes($ficheiro)
    if ($b.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'PReg') { return }
    $saida = New-Object IO.MemoryStream
    $saida.Write($b, 0, 8)
    $tirados = 0
    $i = 8
    while ($i -lt $b.Length) {
      $ini = $i
      $i += 2
      $k = $i; while ([BitConverter]::ToUInt16($b, $i) -ne 0) { $i += 2 }
      $chave = [Text.Encoding]::Unicode.GetString($b, $k, $i - $k); $i += 4
      $k = $i; while ([BitConverter]::ToUInt16($b, $i) -ne 0) { $i += 2 }
      $valor = [Text.Encoding]::Unicode.GetString($b, $k, $i - $k); $i += 4
      $i += 6
      $tam = [BitConverter]::ToUInt32($b, $i); $i += 6
      $i += $tam + 2
      if ($i -gt $b.Length) { throw 'entrada cortada' }
      if ($chave -match 'Explorer$' -and ($ocultar + $menu) -contains $valor) { $tirados++ }
      else { $saida.Write($b, $ini, $i - $ini) }
    }
    if ($tirados -eq 0) { return }
    $script:n += $tirados
    Write-Output "  [corrigir] $tirados entradas em $ficheiro"
    if ($apply) {
      Copy-Item -LiteralPath $ficheiro -Destination ($ficheiro + '.aegn-copia-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
      [IO.File]::WriteAllBytes($ficheiro, $saida.ToArray())
    }
  } catch { Write-Output "  [erro] $($ficheiro): $_" }
}
$gp = Join-Path $env:SystemRoot 'System32\GroupPolicy'
$pols = @("$gp\Machine\Registry.pol", "$gp\User\Registry.pol")
$pols += @(Get-ChildItem (Join-Path $env:SystemRoot 'System32\GroupPolicyUsers') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'User\Registry.pol' })
foreach ($f in $pols) { if (Test-Path -LiteralPath $f) { Limpar-Pol $f } }

# 5. Derecho "Encerrar o sistema": se mantienen los que hay y se anaden los
# tres de serie. Vale para el proximo inicio de sesion.
$inf = Join-Path $env:TEMP 'aegn-direitos.inf'
Remove-Item $inf -Force -ErrorAction SilentlyContinue
& secedit.exe /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
# Sin la exportacion no se sabe quien tiene el derecho: no se toca.
$faltam = @()
if (-not (Test-Path -LiteralPath $inf)) { Write-Output '  [erro] secedit /export falhou: não se verificou o direito Encerrar o sistema.' }
else {
  $linha = Select-String -Path $inf -Pattern '^SeShutdownPrivilege' | Select-Object -First 1
  $atuais = @()
  if ($linha) { $atuais = @(($linha.Line -split '=', 2)[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
  $serie = '*S-1-5-32-544', '*S-1-5-32-545', '*S-1-5-32-551'
  $faltam = @($serie | Where-Object { $atuais -notcontains $_ })
}
if ($faltam.Count -gt 0) {
  $script:n++
  Write-Output ('  [corrigir] Encerrar o sistema: faltam ' + ($faltam -join ', '))
  if ($apply) {
    $todos = ($atuais + $faltam) -join ','
    $conteudo = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n[Privilege Rights]`r`nSeShutdownPrivilege = $todos`r`n"
    Set-Content -Path $inf -Value $conteudo -Encoding Unicode
    & secedit.exe /configure /db (Join-Path $env:TEMP 'aegn-direitos.sdb') /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Output "  [erro] secedit terminou com $LASTEXITCODE" }
  }
}
Remove-Item $inf, (Join-Path $env:TEMP 'aegn-direitos.sdb') -Force -ErrorAction SilentlyContinue

if (Test-Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start') {
  Write-Output '  [aviso] Há diretivas MDM de Start: se o Intune as voltar a pôr, corrija-as no Intune.'
}
if ($script:n -eq 0) { Write-Output '  [ok] Os botões Encerrar e Reiniciar não estão ocultos.' }
elseif ($apply) {
  # El menu Inicio relee las directivas al volver a abrirse.
  Get-Process -Name StartMenuExperienceHost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Write-Output ('  [ok] Botões de energia repostos (' + $script:n + ' correções). Alguns só voltam após reiniciar.')
}
$global:LASTEXITCODE = 0"#;

fn script(apply: bool) -> String {
    format!(
        "$apply = {}\n{SCRIPT}",
        if apply { "$true" } else { "$false" }
    )
}

/// Repone los botones de energia y devuelve la salida (lo usa el rescate).
#[cfg(windows)]
pub fn restore() -> Result<String> {
    crate::ps::run(&script(true))
}

/// Repone los botones de energia. Dry-run salvo `apply`.
pub fn run(apply: bool) -> Result<()> {
    #[cfg(windows)]
    {
        print!("{}", crate::ps::run(&script(apply))?);
        if !apply {
            println!("[simulação] Execute com --aplicar para corrigir (consola de administrador).");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = script;
        if apply {
            println!("[info] A reposição dos botões de energia só está disponível no Windows.");
        } else {
            println!("[simulação] Seriam repostos os botões Encerrar e Reiniciar (NoClose, HidePowerOptions,");
            println!("[simulação] MDM, Registry.pol e o direito Encerrar o sistema).");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_script_no_lleva_comillas_sin_cerrar() {
        for line in script(true).lines() {
            assert_eq!(line.matches('\'').count() % 2, 0, "{line}");
        }
    }

    #[test]
    fn simulacion_no_cambia_nada() {
        assert!(script(false).starts_with("$apply = $false\n"));
        // Cada cambio va detras de `if ($apply)`.
        for cambio in ["Remove-ItemProperty", "Set-ItemProperty", "WriteAllBytes", "/configure"] {
            for line in SCRIPT.lines().filter(|l| l.contains(cambio)) {
                let hasta = &SCRIPT[..SCRIPT.find(line).unwrap() + line.len()];
                let ultimo_if = hasta.rfind("if ($apply)").expect(cambio);
                assert!(hasta.len() - ultimo_if < 700, "{cambio} sin if ($apply)");
            }
        }
    }

    #[test]
    fn cubre_las_formas_conocidas_de_ocultar_la_energia() {
        for v in [
            "NoClose",
            "HidePowerOptions",
            "shutdownwithoutlogon",
            "HideShutDown",
            "HideRestart",
            "HidePowerButton",
            "Registry.pol",
            "SeShutdownPrivilege",
            "*S-1-5-32-545",
        ] {
            assert!(SCRIPT.contains(v), "falta {v}");
        }
    }
}
